from flask import Flask, jsonify, request, g, Response, make_response
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
import time
import jwt
import requests
import uuid
from functools import wraps
import os
import re
import random
from urllib.parse import urlparse

app = Flask(__name__)

# Asegurar que Flask respete encabezados X-Forwarded-* (evita redirects http en entorno detrás de proxy/CDN)
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
except Exception:
    pass

# Configuración de CORS unificada
origins_env = os.environ.get('CORS_ORIGINS')
if origins_env:
    raw_origins = [o.strip() for o in origins_env.split(',') if o.strip()]
else:
    raw_origins = [
        'http://localhost:4200',
        'https://seg-front.vercel.app',
        'regex:https://seg-front.*vercel.app',
        # Permitir despliegues previos / previews con hash: seg-front-<buildId>.vercel.app
        'regex:https://seg-front-[a-zA-Z0-9-]+\.vercel\.app'
    ]

_origins = []
for o in raw_origins:
    if o.lower().startswith('regex:'):
        try:
            _origins.append(re.compile(o[6:]))
        except re.error:
            pass
    else:
        _origins.append(o)

CORS(
    app,
    origins=_origins,
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type"],
    max_age=600
)

@app.after_request
def ensure_cors_headers(resp):
    origin = request.headers.get('Origin')
    if not origin:
        return resp
    allowed = False
    for o in _origins:
        if hasattr(o, 'match') and o.match(origin):
            allowed = True
            break
        if o == origin:
            allowed = True
            break
    # Heurística adicional: permitir despliegues dinámicos de Vercel del mismo proyecto
    # Ejemplo: https://seg-front-xxxxx-jair-herreras-projects-*.vercel.app
    if not allowed:
        try:
            if re.match(r'^https://seg-front-[a-zA-Z0-9-]+\.vercel\.app$', origin):
                allowed = True
        except Exception:
            pass
    if allowed:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Vary'] = 'Origin'
        resp.headers.setdefault('Access-Control-Allow-Credentials', 'true')
        resp.headers.setdefault('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        resp.headers.setdefault('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    return resp

# Manejo global de preflight OPTIONS (responder directamente sin proxy)
@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        # Respuesta vacía con 200; flask-cors + ensure_cors_headers añadirán cabeceras
        resp = make_response('', 200)
        # Añadimos explícitamente por robustez
        resp.headers.setdefault('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        resp.headers.setdefault('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return resp

SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-in-prod')

# Conexión a MongoDB (API Gateway podría guardar logs u otra metadata)
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/api_gateway_db')
mongo_client = MongoClient(MONGO_URI)

def _extract_db_name(uri: str, default_name: str) -> str:
    parsed = urlparse(uri)
    path = parsed.path.lstrip('/')
    if path:
        return path.split('/')[0]
    return default_name

DB_NAME = os.environ.get('MONGO_DB_NAME', _extract_db_name(MONGO_URI, 'api_gateway_db'))
mongo_db = mongo_client[DB_NAME]
# (Deprecado) Colección local de tasks: mantenida sólo para compatibilidad si se necesitara.
tasks_collection = mongo_db['tasks']
logs_collection = mongo_db['request_logs']

def validate_date(date_str: str) -> bool:
    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def ensure_indexes():
    """Crear índices para logs (timestamp, (api_name,timestamp) y TTL opcional)."""
    try:
        ttl_days = os.environ.get('LOGS_TTL_DAYS')
        if ttl_days:
            try:
                seconds = int(float(ttl_days) * 86400)
                # TTL index (si ya existe con otras opciones, Mongo ignorará si coincide)
                logs_collection.create_index('timestamp', expireAfterSeconds=seconds)
            except ValueError:
                # Fallback a índice normal si valor inválido
                logs_collection.create_index([('timestamp', -1)])
        else:
            logs_collection.create_index([('timestamp', -1)])
        logs_collection.create_index([('api_name', 1), ('timestamp', -1)])
    except Exception as e:
        print(f"Error creando índices de logs: {e}")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token requerido', 'status': 'error'}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado', 'status': 'error'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido', 'status': 'error'}), 401
        return f(*args, **kwargs)
    return decorated

VALID_STATUSES = ['InProgress', 'Revision', 'Completed', 'Paused', 'Incomplete']

# --- Request logging (simple) ---
@app.before_request
def _start_timer():
    g._start_time = time.time()

@app.after_request
def _log_request(resp):
    try:
        # Evitar logging interno de favicon o estáticos si los hubiera
        if request.method == 'OPTIONS' or request.path.startswith('/health') or request.path.startswith('/logs'):
            return resp
        duration_ms = int((time.time() - getattr(g, '_start_time', time.time())) * 1000)
        api_name = request.path.strip('/').split('/')[0] or 'root'
        doc = {
            'timestamp': datetime.datetime.utcnow(),
            'request_id': str(uuid.uuid4()),
            'method': request.method,
            'path': request.path,
            'api_name': api_name,
            'status_code': resp.status_code,
            'duration_ms': duration_ms,
            'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
            'error': resp.status_code >= 400
        }
        # Añadir upstream resolviendo según api_name principal
        upstream_map = {
            'auth': AUTH_SERVICE_URL,
            'user': USER_SERVICE_URL,
            'tasks': TASK_SERVICE_URL,
            'task': TASK_SERVICE_URL
        }
        if api_name in upstream_map:
            doc['upstream'] = upstream_map[api_name]
        # Intentar extraer usuario del JWT (best-effort)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                # Campos estándar definidos en auth_service
                if 'user_id' in payload:
                    doc['user_id'] = payload['user_id']
                if 'username' in payload:
                    doc['username'] = payload['username']
                if 'permission' in payload:
                    doc['permission'] = payload['permission']
                if 'role' in payload:
                    doc['role'] = payload['role']
            except Exception:
                pass
        logs_collection.insert_one(doc)
    except Exception:
        pass
    return resp

# ===================== PROXY A MICROSERVICIOS =====================
# URLs de microservicios configurables por variables de entorno.
AUTH_SERVICE_URL = os.environ.get('AUTH_SERVICE_URL', 'http://localhost:5001')
USER_SERVICE_URL = os.environ.get('USER_SERVICE_URL', 'http://localhost:5002')
TASK_SERVICE_URL = os.environ.get('TASK_SERVICE_URL', 'http://localhost:5003')

FORWARD_TIMEOUT = (
    int(os.environ.get('UPSTREAM_CONNECT_TIMEOUT', '10')),
    int(os.environ.get('UPSTREAM_READ_TIMEOUT', '30'))
)  # (connect, read)

def _build_target(base: str, prefix: str, path_suffix: str) -> str:
    # path_suffix ya viene sin el prefijo principal
    # Preservar query string
    qs = request.query_string.decode()
    target_path = '/' + path_suffix if path_suffix else ''
    # Evitar doble slash
    url = base.rstrip('/') + target_path
    if qs:
        url += '?' + qs
    return url

def _filtered_headers():
    hop_by_hop = { 'host', 'content-length' }
    return {k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop}

def _forward(base_url: str, prefix: str, path: str):
    target = _build_target(base_url, prefix, path)
    json_payload = None
    data = None
    files = None
    if request.method in ['POST', 'PUT', 'PATCH']:
        ct = request.headers.get('Content-Type', '').lower()
        if request.files:
            files = {f: (fobj.filename, fobj.stream, fobj.mimetype) for f, fobj in request.files.items()}
            data = request.form.to_dict(flat=True)
        elif 'application/json' in ct:
            json_payload = request.get_json(silent=True)
        else:
            data = request.get_data()
    try:
        # Debug: loggear upstream configurado (solo si DEBUG_UPSTREAMS=1 para no inundar logs)
        if os.environ.get('DEBUG_UPSTREAMS', '0') == '1':
            app.logger.info(f"[PROXY] Forward -> base={base_url} target={target} method={request.method}")
        # Forzar a upstream a enviar respuesta sin compresión compleja si es posible (identity)
        fwd_headers = _filtered_headers()
        # Sobrescribir Accept-Encoding para simplificar (el navegador se encargará luego si dejamos content-encoding pasar)
        fwd_headers['Accept-Encoding'] = 'gzip, deflate, br'
        resp = requests.request(
            method=request.method,
            url=target,
            headers=fwd_headers,
            data=None if (files or json_payload is not None) else data,
            json=json_payload,
            files=files,
            timeout=FORWARD_TIMEOUT
        )
        # Ya no excluimos 'content-encoding' para que el navegador pueda descomprimir.
        excluded = {'transfer-encoding', 'connection', 'keep-alive'}
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
        return Response(resp.content, status=resp.status_code, headers=headers)
    except requests.exceptions.ConnectTimeout:
        app.logger.warning(f"[PROXY] Connect timeout upstream={base_url} target={target}")
        return jsonify({'error': 'Upstream timeout (connect)', 'upstream': base_url, 'target': target}), 504
    except requests.exceptions.ReadTimeout:
        app.logger.warning(f"[PROXY] Read timeout upstream={base_url} target={target}")
        return jsonify({'error': 'Upstream timeout (read)', 'upstream': base_url, 'target': target}), 504
    except requests.exceptions.ConnectionError as e:
        app.logger.error(f"[PROXY] Connection error upstream={base_url} target={target} detail={e}")
        return jsonify({'error': 'Upstream connection error', 'detail': str(e), 'upstream': base_url, 'target': target}), 502
    except requests.exceptions.RequestException as e:
        app.logger.error(f"[PROXY] Generic upstream error upstream={base_url} target={target} detail={e}")
        return jsonify({'error': 'Upstream error', 'detail': str(e), 'upstream': base_url, 'target': target}), 502

# Debug endpoint (solo si DEBUG_UPSTREAMS=1) para inspeccionar URLs configuradas
@app.route('/debug/upstreams', methods=['GET'])
def debug_upstreams():
    if os.environ.get('DEBUG_UPSTREAMS', '0') != '1':
        return jsonify({'error': 'disabled'}), 403
    return jsonify({
        'auth': AUTH_SERVICE_URL,
        'user': USER_SERVICE_URL,
        'tasks': TASK_SERVICE_URL,
        'timeouts': {'connect': FORWARD_TIMEOUT[0], 'read': FORWARD_TIMEOUT[1]}
    })

# Auth Service proxy
@app.route('/auth', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE','OPTIONS'])
@app.route('/auth/<path:path>', methods=['GET','POST','PUT','DELETE','OPTIONS'])
def proxy_auth(path):
    return _forward(AUTH_SERVICE_URL, '/auth', path)

# User Service proxy
@app.route('/user', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE','OPTIONS'])
@app.route('/user/<path:path>', methods=['GET','POST','PUT','DELETE','OPTIONS'])
def proxy_user(path):
    return _forward(USER_SERVICE_URL, '/user', path)

# Task Service proxy (incluye variantes /task y /tasks)
@app.route('/tasks', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE','OPTIONS'])
@app.route('/tasks/<path:path>', methods=['GET','POST','PUT','DELETE','OPTIONS'])
def proxy_tasks(path):
    """Proxy seguro para Task Service sin redirecciones involuntarias.
    Mapea operaciones especiales (register_task, update_task/...) al root upstream.
    """
    suffix = path or ''
    method = request.method
    import re as _re
    root_ops = ('register_task', 'update_task', 'delete_task', 'disable_task', 'enable_task')
    is_object_id = bool(suffix and _re.fullmatch(r'[0-9a-fA-F]{24}', suffix))
    if method == 'GET' and suffix == '':
        upstream_path = '/tasks'
    elif method == 'GET' and is_object_id:
        upstream_path = f'/tasks/{suffix}'
    elif any(suffix.startswith(op) for op in root_ops):
        upstream_path = '/' + suffix
    else:
        upstream_path = '/tasks' + ('/' + suffix if suffix else '')
    qs = request.query_string.decode()
    target = TASK_SERVICE_URL.rstrip('/') + upstream_path + (('?' + qs) if qs else '')
    try:
        fwd_headers = _filtered_headers()
        fwd_headers['Accept-Encoding'] = 'gzip, deflate, br'
        resp = requests.request(
            method=method,
            url=target,
            headers=fwd_headers,
            timeout=FORWARD_TIMEOUT
        )
        excluded = {'transfer-encoding', 'connection', 'keep-alive'}
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
        return Response(resp.content, status=resp.status_code, headers=headers)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Upstream tasks error', 'detail': str(e), 'target': target}), 502

# ================== FIN PROXY ==================

# --- Logs Endpoints ---
@app.route('/logs/summary', methods=['GET'])
def logs_summary():
    try:
        total = logs_collection.count_documents({})

        if total == 0:
            return jsonify({
                'total_logs': 0,
                'status_counts': {},
                'apis': {},
                'avg_duration_ms': 0,
                'per_api': {},
                'fastest_api': None,
                'slowest_api': None,
                'most_used_api': None,
                'least_used_api': None
            })

        # Aggregate status counts
        status_counts = {str(item['_id']): item['count'] for item in logs_collection.aggregate([
            {'$group': {'_id': '$status_code', 'count': {'$sum': 1}}}
        ])}

        # Per API aggregation (count & avg duration)
        per_api_raw = list(logs_collection.aggregate([
            {'$group': {
                '_id': '$api_name',
                'count': {'$sum': 1},
                'avg_duration_ms': {'$avg': '$duration_ms'}
            }}
        ]))
        per_api = {}
        for item in per_api_raw:
            per_api[item['_id']] = {
                'count': item['count'],
                'avg_duration_ms': round(item['avg_duration_ms'], 2)
            }

        # Overall average duration
        avg_duration_doc = next(logs_collection.aggregate([
            {'$group': {'_id': None, 'avg': {'$avg': '$duration_ms'}}}
        ]), {'avg': 0})
        avg_duration_ms = round(avg_duration_doc.get('avg', 0), 2)

        # Derive fastest/slowest & most/least used
        fastest_api = None
        slowest_api = None
        most_used_api = None
        least_used_api = None
        if per_api:
            fastest_api = min(per_api.items(), key=lambda x: x[1]['avg_duration_ms'])[0]
            slowest_api = max(per_api.items(), key=lambda x: x[1]['avg_duration_ms'])[0]
            most_used_api = max(per_api.items(), key=lambda x: x[1]['count'])[0]
            least_used_api = min(per_api.items(), key=lambda x: x[1]['count'])[0]

        api_counts = {k: v['count'] for k, v in per_api.items()}

        return jsonify({
            'total_logs': total,
            'status_counts': status_counts,
            'apis': api_counts,
            'avg_duration_ms': avg_duration_ms,
            'per_api': per_api,
            'fastest_api': fastest_api,
            'slowest_api': slowest_api,
            'most_used_api': most_used_api,
            'least_used_api': least_used_api
        })
    except Exception as e:
        return jsonify({'error': 'Error obteniendo summary', 'detail': str(e)}), 500

@app.route('/logs/all', methods=['GET'])
def logs_all():
    try:
        cursor = logs_collection.find().sort('timestamp', -1).limit(200)
        out = []
        for doc in cursor:
            out.append({
                'id': str(doc.get('_id')),
                'timestamp': doc.get('timestamp'),
                'api_name': doc.get('api_name'),
                'status_code': doc.get('status_code'),
                'method': doc.get('method'),
                'path': doc.get('path'),
                'duration_ms': doc.get('duration_ms')
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({'error': 'Error obteniendo logs', 'detail': str(e)}), 500

@app.route('/logs/seed', methods=['POST','GET'])
def logs_seed():
    """Genera logs sintéticos para poblar el dashboard rápidamente.
    Query params:
      count: cantidad de logs (default 50, max 500)
    """
    try:
        count = request.args.get('count', '50')
        try:
            count = min(500, max(1, int(count)))
        except ValueError:
            count = 50
        statuses = [200,201,401,404,500]
        apis = ['auth','user','tasks','root','stats']
        methods = ['GET','POST','PUT','DELETE']
        bulk = []
        now = datetime.datetime.utcnow()
        for _ in range(count):
            api_name = random.choice(apis)
            status = random.choice(statuses)
            dur = random.randint(5, 1200)  # ms
            bulk.append({
                'timestamp': now - datetime.timedelta(seconds=random.randint(0, 3600)),
                'method': random.choice(methods),
                'path': f'/{api_name}' + ('' if api_name in ['root','stats'] else '/' + str(random.randint(1,9))) ,
                'api_name': api_name,
                'status_code': status,
                'duration_ms': dur,
                'ip': '127.0.0.1'
            })
        if bulk:
            logs_collection.insert_many(bulk)
        return jsonify({'inserted': len(bulk), 'status_codes': statuses, 'apis_sampled': apis}), 201
    except Exception as e:
        return jsonify({'error': 'Error generando logs', 'detail': str(e)}), 500

# ...otros endpoints de tasks...

@app.route('/', methods=['GET'])
def root():
    return jsonify({'service': 'API Gateway', 'health': '/health'}), 200

@app.route('/health', methods=['GET'])
@app.route('/healthz', methods=['GET'])
def health():
    return jsonify({'status': 'API Gateway running', 'db': DB_NAME}), 200

if __name__ == '__main__':
    ensure_indexes()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host="0.0.0.0", port=port, debug=debug)