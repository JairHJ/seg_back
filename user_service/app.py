import jwt
SECRET_KEY = 'miclavesecreta123'

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

from flask import Flask, jsonify, request
from pymongo import MongoClient
from bson.objectid import ObjectId


app = Flask(__name__)

# Conexión a MongoDB
MONGO_URI = 'mongodb://localhost:27017/'
mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client['user_service_db']
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

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5002, debug=True)
