from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
import jwt
from functools import wraps

app = Flask(__name__)
CORS(app)

SECRET_KEY = "miclavesecreta123"


# Conexión a MongoDB
import os
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


# Inicializar tareas de ejemplo si no existen
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
            # Solo verificamos que el token sea válido
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


@app.route('/tasks/<task_id>', methods=['GET'])
@token_required
def get_task_by_id(task_id):
    try:
        task = tasks_collection.find_one({'_id': ObjectId(task_id)})
        if task:
            task['id'] = str(task['_id'])
            task.pop('_id', None)
            return jsonify({
                "statusCode": 200,
                "intData": {
                    "message": "Tarea encontrada",
                    "data": task
                }
            })
        else:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada",
                    "data": None
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


@app.route('/register_task', methods=['POST'])
@token_required
def create_task():
    data = request.get_json()
    required_fields = ['name', 'description', 'created_at', 'dead_line', 'status', 'is_alive', 'created_by']

    if not all(field in data for field in required_fields):
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": "Todos los campos son requeridos",
                "data": None
            }
        })

    if data['status'] not in VALID_STATUSES:
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": f"El status debe ser uno de: {', '.join(VALID_STATUSES)}",
                "data": None
            }
        })

    if not validate_date(data['created_at']) or not validate_date(data['dead_line']):
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": "Formato de fecha inválido (YYYY-MM-DD)",
                "data": None
            }
        })

    try:
        tasks_collection.insert_one({
            'name': data['name'],
            'description': data['description'],
            'created_at': data['created_at'],
            'dead_line': data['dead_line'],
            'status': data['status'],
            'is_alive': data['is_alive'],
            'created_by': data['created_by']
        })
        return jsonify({
            "statusCode": 201,
            "intData": {
                "message": "Tarea creada exitosamente",
                "data": None
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


@app.route('/update_task/<task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    data = request.get_json()
    required_fields = ['name', 'description', 'created_at', 'dead_line', 'status', 'is_alive', 'created_by']

    if not all(field in data for field in required_fields):
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": "Todos los campos son obligatorios",
                "data": None
            }
        })

    if data['status'] not in VALID_STATUSES:
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": f"El status debe ser uno de: {', '.join(VALID_STATUSES)}",
                "data": None
            }
        })

    if not validate_date(data['created_at']) or not validate_date(data['dead_line']):
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": "Formato de fecha inválido (YYYY-MM-DD)",
                "data": None
            }
        })

    try:
        result = tasks_collection.update_one(
            {'_id': ObjectId(task_id)},
            {'$set': {
                'name': data['name'],
                'description': data['description'],
                'created_at': data['created_at'],
                'dead_line': data['dead_line'],
                'status': data['status'],
                'is_alive': data['is_alive'],
                'created_by': data['created_by']
            }}
        )
        if result.matched_count == 0:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para actualizar",
                    "data": None
                }
            })
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea actualizada exitosamente",
                "data": None
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


@app.route('/delete_task/<task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    try:
        result = tasks_collection.delete_one({'_id': ObjectId(task_id)})
        if result.deleted_count == 0:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para eliminar",
                    "data": None
                }
            })
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea eliminada exitosamente",
                "data": None
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


@app.route('/disable_task/<task_id>', methods=['PUT'])
@token_required
def disable_task(task_id):
    try:
        result = tasks_collection.update_one({'_id': ObjectId(task_id)}, {'$set': {'is_alive': False}})
        if result.matched_count == 0:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para desactivar",
                    "data": None
                }
            })
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea desactivada exitosamente",
                "data": None
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


@app.route('/enable_task/<task_id>', methods=['PUT'])
@token_required
def enable_task(task_id):
    try:
        result = tasks_collection.update_one({'_id': ObjectId(task_id)}, {'$set': {'is_alive': True}})
        if result.matched_count == 0:
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para activar",
                    "data": None
                }
            })
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea activada exitosamente",
                "data": None
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


@app.route('/health', methods=['GET'])
@app.route('/healthz', methods=['GET'])
def health():
    return jsonify({'status': 'Task Service is running'}), 200

if __name__ == '__main__':
    init_db()
    app.run(host="127.0.0.1", port=5003, debug=True)
