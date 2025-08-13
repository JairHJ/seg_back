from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
import jwt
from functools import wraps
import os
from urllib.parse import urlparse

app = Flask(__name__)

# Configuración de CORS unificada
origins_env = os.environ.get('CORS_ORIGINS')
if origins_env:
    _origins = [o.strip() for o in origins_env.split(',') if o.strip()]
else:
    _origins = ['http://localhost:4200', 'https://seg-front.vercel.app']

CORS(
    app,
    origins=_origins,
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type"],
    max_age=600
)

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
tasks_collection = mongo_db['tasks']  # Placeholder; ideal: gateway no duplique lógica de task service

def validate_date(date_str: str) -> bool:
    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def init_db():
    if tasks_collection.count_documents({}) == 0:
        tasks = [
            {
                'name': 'Tarea de ejemplo 1',
                'description': 'Primera tarea de prueba',
                'created_at': '2024-01-01',
                'dead_line': '2024-01-15',
                'status': 'InProgress',
                'is_alive': True,
                'created_by': 'admin'
            },
            {
                'name': 'Tarea de ejemplo 2',
                'description': 'Segunda tarea de prueba',
                'created_at': '2024-01-02',
                'dead_line': '2024-01-20',
                'status': 'Completed',
                'is_alive': True,
                'created_by': 'admin'
            }
        ]
        tasks_collection.insert_many(tasks)

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

@app.route('/tasks', methods=['GET'])
def get_tasks():
    try:
        tasks = list(tasks_collection.find())
        tasks_list = []
        for task in tasks:
            task['id'] = str(task['_id'])
            task.pop('_id', None)
            tasks_list.append(task)
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tareas obtenidas exitosamente",
                "data": tasks_list
            }
        })
    except Exception as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": f"Database error: {str(e)}",
                "data": None
            }
        })

# ...otros endpoints de tasks...

@app.route('/', methods=['GET'])
def root():
    return jsonify({'service': 'API Gateway', 'health': '/health'}), 200

@app.route('/health', methods=['GET'])
@app.route('/healthz', methods=['GET'])
def health():
    return jsonify({'status': 'API Gateway running', 'db': DB_NAME}), 200

if __name__ == '__main__':
    # init_db()  # El gateway no debería poblar tasks; comentar para evitar duplicación
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host="0.0.0.0", port=port, debug=debug)