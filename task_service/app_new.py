from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import datetime
import jwt
from functools import wraps

app = Flask(__name__)
CORS(app)

SECRET_KEY = "miclavesecreta123"
DB_NAME = "database.db"

def validate_date(date_str: str) -> bool:
    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at DATE NOT NULL,
            dead_line DATE NOT NULL,
            status TEXT NOT NULL,
            is_alive BOOLEAN NOT NULL,
            created_by TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def insert_tasks_if_not_exists():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    tasks = [
        ('Tarea de ejemplo 1', 'Primera tarea de prueba', '2024-01-01', '2024-01-15', 'InProgress', 1, 'admin'),
        ('Tarea de ejemplo 2', 'Segunda tarea de prueba', '2024-01-02', '2024-01-20', 'Completed', 1, 'admin')
    ]
    for task in tasks:
        name, description, created_at, dead_line, status, is_alive, created_by = task
        cursor.execute("""
            INSERT INTO tasks (name, description, created_at, dead_line, status, is_alive, created_by)
            SELECT ?, ?, ?, ?, ?, ?, ?
            WHERE NOT EXISTS (SELECT 1 FROM tasks WHERE name = ?)
        """, (name, description, created_at, dead_line, status, is_alive, created_by, name))
    conn.commit()
    conn.close()

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
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, description, created_at, dead_line, status, is_alive, created_by FROM tasks")
        tasks = cursor.fetchall()
        conn.close()
        
        tasks_list = []
        for task in tasks:
            tasks_list.append({
                'id': task['id'],
                'name': task['name'],
                'description': task['description'],
                'created_at': task['created_at'],
                'dead_line': task['dead_line'],
                'status': task['status'],
                'is_alive': bool(task['is_alive']),
                'created_by': task['created_by']
            })
        
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tareas obtenidas exitosamente",
                "data": tasks_list
            }
        })
    except sqlite3.Error as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": f"Database error: {str(e)}",
                "data": None
            }
        })

@app.route('/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task_by_id(task_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, description, created_at, dead_line, status, is_alive, created_by FROM tasks WHERE id = ?", (task_id,))
        task = cursor.fetchone()
        conn.close()
        
        if task:
            task_data = {
                'id': task['id'],
                'name': task['name'],
                'description': task['description'],
                'created_at': task['created_at'],
                'dead_line': task['dead_line'],
                'status': task['status'],
                'is_alive': bool(task['is_alive']),
                'created_by': task['created_by']
            }
            return jsonify({
                "statusCode": 200,
                "intData": {
                    "message": "Tarea encontrada",
                    "data": task_data
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
    except sqlite3.Error as e:
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
    
    name = data['name']
    description = data['description']
    created_at = data['created_at']
    dead_line = data['dead_line']
    status = data['status']
    is_alive = data['is_alive']
    created_by = data['created_by']
    
    if status not in VALID_STATUSES:
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": f"El status debe ser uno de: {', '.join(VALID_STATUSES)}",
                "data": None
            }
        })
    
    if not validate_date(created_at) or not validate_date(dead_line):
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": "Formato de fecha inválido (YYYY-MM-DD)",
                "data": None
            }
        })
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO tasks (name, description, created_at, dead_line, status, is_alive, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, description, created_at, dead_line, status, is_alive, created_by)
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            "statusCode": 201,
            "intData": {
                "message": "Tarea creada exitosamente",
                "data": None
            }
        })
    except sqlite3.Error as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": f"Database error: {str(e)}",
                "data": None
            }
        })

@app.route('/update_task/<int:task_id>', methods=['PUT'])
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
    
    name = data['name']
    description = data['description']
    created_at = data['created_at']
    dead_line = data['dead_line']
    status = data['status']
    is_alive = data['is_alive']
    created_by = data['created_by']

    if status not in VALID_STATUSES:
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": f"El status debe ser uno de: {', '.join(VALID_STATUSES)}",
                "data": None
            }
        })
    
    if not validate_date(created_at) or not validate_date(dead_line):
        return jsonify({
            "statusCode": 400,
            "intData": {
                "message": "Formato de fecha inválido (YYYY-MM-DD)",
                "data": None
            }
        })
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE tasks SET
                name = ?, description = ?, created_at = ?, dead_line = ?, status = ?, is_alive = ?, created_by = ?
            WHERE id = ?
        """, (name, description, created_at, dead_line, status, is_alive, created_by, task_id))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para actualizar",
                    "data": None
                }
            })
        
        conn.close()
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea actualizada exitosamente",
                "data": None
            }
        })
    except sqlite3.Error as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": f"Database error: {str(e)}",
                "data": None
            }
        })

@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para eliminar",
                    "data": None
                }
            })
        
        conn.close()
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea eliminada exitosamente",
                "data": None
            }
        })
    except sqlite3.Error as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": f"Database error: {str(e)}",
                "data": None
            }
        })

@app.route('/disable_task/<int:task_id>', methods=['PUT'])
@token_required
def disable_task(task_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET is_alive = 0 WHERE id = ?", (task_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para desactivar",
                    "data": None
                }
            })
        
        conn.close()
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea desactivada exitosamente",
                "data": None
            }
        })
    except sqlite3.Error as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": f"Database error: {str(e)}",
                "data": None
            }
        })

@app.route('/enable_task/<int:task_id>', methods=['PUT'])
@token_required
def enable_task(task_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET is_alive = 1 WHERE id = ?", (task_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({
                "statusCode": 404,
                "intData": {
                    "message": "Tarea no encontrada para activar",
                    "data": None
                }
            })
        
        conn.close()
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Tarea activada exitosamente",
                "data": None
            }
        })
    except sqlite3.Error as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": f"Database error: {str(e)}",
                "data": None
            }
        })

if __name__ == '__main__':
    init_db()
    insert_tasks_if_not_exists()
    app.run(host="127.0.0.1", port=5003, debug=True)
