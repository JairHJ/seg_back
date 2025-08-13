import jwt
import os
import re
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-in-prod')

def token_required(f):
    from functools import wraps
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token requerido', 'status': 'error'}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if decoded.get('permission') != 'admin':
                return jsonify({'message': 'Permiso de admin requerido', 'status': 'error'}), 403
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado', 'status': 'error'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido', 'status': 'error'}), 401
        return f(*args, **kwargs)
    return wraps(f)(decorated)

app = Flask(__name__)

# CORS unificado
origins_env = os.environ.get('CORS_ORIGINS')
if origins_env:
    raw_origins = [o.strip() for o in origins_env.split(',') if o.strip()]
else:
    raw_origins = ['http://localhost:4200', 'https://seg-front.vercel.app', 'regex:https://seg-front.*vercel.app']

_origins = []
for o in raw_origins:
    if o.lower().startswith('regex:'):
        try:
            _origins.append(re.compile(o[6:]))
        except re.error:
            pass
    else:
        _origins.append(o)

from flask_cors import CORS as _CORS
_CORS(
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
    if allowed:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Vary'] = 'Origin'
        resp.headers.setdefault('Access-Control-Allow-Credentials', 'true')
        resp.headers.setdefault('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        resp.headers.setdefault('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    return resp

# Rate limiting básico
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per day", "100 per hour"])

# Conexión a MongoDB
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/user_service_db')
from urllib.parse import urlparse
def _extract_db_name(uri: str, default_name: str) -> str:
    parsed = urlparse(uri)
    path = parsed.path.lstrip('/')
    return path.split('/')[0] if path else default_name
mongo_client = MongoClient(MONGO_URI)
DB_NAME = os.environ.get('MONGO_DB_NAME', _extract_db_name(MONGO_URI, 'user_service_db'))
mongo_db = mongo_client[DB_NAME]
users_collection = mongo_db['users']

@app.route('/users', methods=['GET'])
@token_required
def get_users():
    users = list(users_collection.find())
    for user in users:
        user['id'] = str(user['_id'])
        user.pop('_id', None)
    return jsonify({"users": users})

@app.route('/users/<user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
        user['id'] = str(user['_id'])
        user.pop('_id', None)
        return jsonify({"user": user})
    except Exception:
        return jsonify({"error": "ID inválido"}), 400

@app.route('/users', methods=['POST'])
@token_required
def create_user():
    if not request.is_json or 'username' not in request.json or 'email' not in request.json:
        return jsonify({"error": "Username y email requeridos"}), 400

    username = request.json['username']
    email = request.json['email']
    # Verificar unicidad
    if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({"error": "Username o email ya existe"}), 409

    new_user = {
        "username": username,
        "email": email
    }
    result = users_collection.insert_one(new_user)
    new_user['id'] = str(result.inserted_id)
    return jsonify({"message": "Usuario creado con éxito!", "user": new_user}), 201

@app.route('/users/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        update_data = {}
        if request.is_json:
            if 'username' in request.json:
                update_data['username'] = request.json['username']
            if 'email' in request.json:
                update_data['email'] = request.json['email']
        if update_data:
            users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
            user.update(update_data)
        user['id'] = str(user['_id'])
        user.pop('_id', None)
        return jsonify({"message": "Usuario actualizado con éxito!", "user": user})
    except Exception:
        return jsonify({"error": "ID inválido"}), 400

@app.route('/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
        users_collection.delete_one({'_id': ObjectId(user_id)})
        return jsonify({"message": "Usuario eliminado con éxito!", "user": user['username']})
    except Exception:
        return jsonify({"error": "ID inválido"}), 400

@app.route('/', methods=['GET'])
def root():
    return jsonify({'service': 'User Service', 'health': '/health'}), 200

@app.route('/health', methods=['GET'])
@app.route('/healthz', methods=['GET'])
def health():
    return jsonify({'status': 'User Service is running', 'db': DB_NAME}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host="0.0.0.0", port=port, debug=debug)