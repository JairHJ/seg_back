from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
import jwt
from functools import wraps
import os

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get('SECRET_KEY', 'miclavesecreta123')

# Conexión a MongoDB
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client.get_database('task_service_db')
tasks_collection = mongo_db['tasks']

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

@app.route('/health', methods=['GET'])
@app.route('/healthz', methods=['GET'])
def health():
    return jsonify({'status': 'Task Service is running'}), 200

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=5003, debug=True)