## ...existing code...

# ...después de la definición de app y la configuración de MongoDB...


# ...existing code...


# ...existing code...

# Debe ir después de la definición de app y la configuración de MongoDB

import requests
from flask import Flask, jsonify, request, g
from flask_cors import CORS

import time
import datetime
from pymongo import MongoClient


app = Flask(__name__)
CORS(app, origins=['http://localhost:4200'])

# --- Rate Limiting ---
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["100 per minute"]  # Límite global, ajusta según necesidad
    )
except ImportError:
    print("[ADVERTENCIA] flask-limiter no está instalado. El rate limit no está activo.")

# Configuración de MongoDB
MONGO_URI = 'mongodb://localhost:27017/'  # Cambia si usas MongoDB Atlas o diferente host
mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client['api_gateway_db']
logs_collection = mongo_db['logs']

# Endpoint para resumen de logs
@app.route('/logs/summary', methods=['GET', 'OPTIONS'])
def logs_summary():
    # APIs válidas del backend (ajusta según tus rutas reales)
    # Definir rutas irrelevantes a excluir
    rutas_excluidas = {'/favicon.ico', '/', '/static', '/static/', '/robots.txt'}
    def es_api_valida(path):
        if not path or path in rutas_excluidas:
            return False
        # Excluir también si la ruta empieza por /static
        if path.startswith('/static'):
            return False
        return True
    logs = [log for log in logs_collection.find() if es_api_valida(log.get('path'))]
    def get_api_name(path):
        if not path or path == '/':
            return None
        parts = path.strip('/').split('/')
        return parts[0] if parts else None
    for log in logs:
        log['api_name'] = get_api_name(log.get('path', ''))
    # Excluir logs sin api_name válido y logs internos de logs/summary, logs/all
    logs = [log for log in logs if log.get('api_name') not in [None, '', 'favicon.ico', 'logs']]
    total_logs = len(logs)
    if total_logs == 0:
        return jsonify({
            'total_logs': 0,
            'avg_response_time': 0,
            'api_mas_rapida': None,
            'api_mas_lenta': None,
            'api_mas_consumida': None,
            'api_menos_consumida': None,
            'status_counts': {},
            'api_stats': {}
        })
    avg_response_time = round(sum(log.get('duration', 0) for log in logs) / total_logs, 3)
    from collections import Counter
    # Solo contar APIs válidas (excluyendo favicon, static, etc)
    api_counter = Counter(log.get('api_name', '') for log in logs if log.get('api_name'))
    # Eliminar de los contadores cualquier api_name irrelevante
    for excluida in ['favicon.ico', '', None]:
        if excluida in api_counter:
            del api_counter[excluida]
    api_mas_consumida = api_counter.most_common(1)[0][0] if api_counter else None
    api_menos_consumida = api_counter.most_common()[-1][0] if api_counter else None
    # Promedio de duración y cantidad por API
    api_stats = {}
    for log in logs:
        api = log.get('api_name', '')
        if api in [None, '', 'favicon.ico']:
            continue
        api_stats.setdefault(api, {'count': 0, 'total': 0})
        api_stats[api]['count'] += 1
        api_stats[api]['total'] += log.get('duration', 0)
    for api in api_stats:
        api_stats[api]['avg'] = round(api_stats[api]['total'] / api_stats[api]['count'], 3) if api_stats[api]['count'] else 0
    avg_times = {k: v['avg'] for k, v in api_stats.items()}
    api_mas_rapida = min(avg_times, key=avg_times.get) if avg_times else None
    api_mas_lenta = max(avg_times, key=avg_times.get) if avg_times else None
    # Contar status
    status_counter = Counter(str(log.get('status_code', '')) for log in logs)
    return jsonify({
        'total_logs': total_logs,
        'avg_response_time': avg_response_time,
        'api_mas_rapida': f"{api_mas_rapida} ({avg_times[api_mas_rapida]:.3f}s)" if api_mas_rapida else None,
        'api_mas_lenta': f"{api_mas_lenta} ({avg_times[api_mas_lenta]:.3f}s)" if api_mas_lenta else None,
        'api_mas_consumida': api_mas_consumida,
        'api_menos_consumida': api_menos_consumida,
        'status_counts': dict(status_counter),
        'api_stats': api_stats
    })

# ...existing code...




import requests
from flask import Flask, jsonify, request, g
from flask_cors import CORS

import time
import datetime
from pymongo import MongoClient



app = Flask(__name__)
CORS(app, origins=['http://localhost:4200'])

# Configuración de MongoDB
MONGO_URI = 'mongodb://localhost:27017/'  # Cambia si usas MongoDB Atlas o diferente host
mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client['api_gateway_db']
logs_collection = mongo_db['logs']


# ...existing code...

# Endpoint para resumen de logs (después de app y MongoDB)
@app.route('/logs/summary', methods=['GET', 'OPTIONS'])
def logs_summary():
    logs = list(logs_collection.find())
    total_logs = len(logs)
    if total_logs == 0:
        return jsonify({
            'total_logs': 0,
            'avg_response_time': 0,
            'api_mas_rapida': None,
            'api_mas_lenta': None,
            'api_mas_consumida': None,
            'api_menos_consumida': None,
            'status_counts': {}
        })

    avg_response_time = round(sum(log.get('duration', 0) for log in logs) / total_logs, 3)
    from collections import Counter
    path_counter = Counter(log.get('path', '') for log in logs)
    api_mas_consumida = path_counter.most_common(1)[0][0] if path_counter else None
    api_menos_consumida = path_counter.most_common()[-1][0] if path_counter else None
    endpoint_times = {}
    for log in logs:
        path = log.get('path', '')
        endpoint_times.setdefault(path, []).append(log.get('duration', 0))
    avg_times = {k: (sum(v)/len(v) if v else 0) for k, v in endpoint_times.items()}
    api_mas_rapida = min(avg_times, key=avg_times.get) if avg_times else None
    api_mas_lenta = max(avg_times, key=avg_times.get) if avg_times else None
    status_counter = Counter(str(log.get('status_code', '')) for log in logs)
    return jsonify({
        'total_logs': total_logs,
        'avg_response_time': avg_response_time,
        'api_mas_rapida': api_mas_rapida,
        'api_mas_lenta': api_mas_lenta,
        'api_mas_consumida': api_mas_consumida,
        'api_menos_consumida': api_menos_consumida,
        'status_counts': dict(status_counter)
    })

AUTH_SERVICE_URL = 'http://localhost:5001'
USER_SERVICE_URL = 'http://localhost:5002'
TASK_SERVICE_URL = 'http://localhost:5003'

# Middleware para logs
@app.before_request
def start_timer():
    g.start = time.time()


@app.after_request
def log_request(response):
    if request.path.startswith('/static'):
        return response
    now = time.time()
    duration = round(now - g.get('start', now), 4)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    user = request.headers.get('user') or '-'
    log_doc = {
        'timestamp': timestamp,
        'method': request.method,
        'path': request.path,
        'status_code': response.status_code,
        'duration': duration,
        'user': user
    }
    try:
        logs_collection.insert_one(log_doc)
    except Exception as e:
        print(f"Error guardando log en MongoDB: {e}")
    return response

# Esta ruta redirige a la ruta de autenticación (auth service)
@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def proxy_auth(path):
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        headers = response.headers
        headers['Access-Control-Allow-Origin'] = 'http://localhost:4200'
        headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
    method = request.method
    url = f'{AUTH_SERVICE_URL}/{path}'
    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    try:
        data = resp.json()
    except ValueError:
        data = resp.text or None
    # Siempre responde bajo la clave 'proxied_response' para el frontend
    response = jsonify({"proxied_response": data})
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:4200'
    return response

# Nuevo endpoint para obtener todos los logs (para la sesión actual)
@app.route('/logs/all', methods=['GET', 'OPTIONS'])
def logs_all():
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        headers = response.headers
        headers['Access-Control-Allow-Origin'] = 'http://localhost:4200'
        headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

    # Devolver todos los logs históricos, solo excluyendo favicon.ico y rutas vacías
    logs = [log for log in logs_collection.find() if log.get('path') not in ['/favicon.ico', '/']]
    def get_api_name(path):
        if not path or path == '/':
            return None
        parts = path.strip('/').split('/')
        return parts[0] if parts else None
    for log in logs:
        log['api_name'] = get_api_name(log.get('path', ''))
    # Convertir ObjectId y datetime a string para el frontend
    for log in logs:
        if '_id' in log:
            log['_id'] = str(log['_id'])
        if 'timestamp' in log and not isinstance(log['timestamp'], str):
            log['timestamp'] = str(log['timestamp'])
    response = jsonify(logs)
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:4200'
    return response
    # Si la respuesta es un string base64 de imagen, devuélvela tal cual
    if isinstance(data, str) and data.startswith("data:image/png;base64,"):
        return data, resp.status_code, {'Content-Type': 'text/plain'}
    return jsonify({"proxied_response": data}), resp.status_code

# Esta ruta redirige a la ruta del usuario (user service)
@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_user(path):
    method = request.method
    url = f'{USER_SERVICE_URL}/{path}'

    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    try:
        data = resp.json()
    except ValueError:
        data = resp.text or None
    if isinstance(data, str) and data.startswith("data:image/png;base64,"):
        return data, resp.status_code, {'Content-Type': 'text/plain'}
    return jsonify({"proxied_response": data}), resp.status_code

# Esta ruta redirige a la ruta de tareas (task service)
@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_task(path):
    method = request.method
    url = f'{TASK_SERVICE_URL}/{path}'

    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    try:
        data = resp.json()
    except ValueError:
        data = resp.text or None
    if isinstance(data, str) and data.startswith("data:image/png;base64,"):
        return data, resp.status_code, {'Content-Type': 'text/plain'}
    return jsonify({"proxied_response": data}), resp.status_code

if __name__ == '__main__': app.run(port=5000, debug=True)