from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import bcrypt
from datetime import datetime, timedelta
import sqlite3
import os
import logging
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
CORS(app)

# Configuración
SECRET_KEY = "miclavesecreta123"
DATABASE = 'auth.db'

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    """Inicializar la base de datos"""
    conn = sqlite3.connect(DATABASE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mfa_secret TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Crear usuario admin por defecto si no existe
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
        admin_secret = pyotp.random_base32()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, mfa_secret) VALUES (?, ?, ?, ?)',
            ('admin', 'admin@example.com', admin_password.decode('utf-8'), admin_secret)
        )
        conn.commit()
        logger.info("Usuario admin creado: admin/admin123")
    
    conn.close()

def generate_token(user_id, username):
    """Generar JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """Verificar JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_qr_code(secret, username):
    """Generar código QR para Google Authenticator"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="TaskApp"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convertir a base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{qr_base64}"

@app.route('/register', methods=['POST'])
def register():
    """Registrar nuevo usuario con MFA"""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username y password son requeridos'}), 400
        
        username = data['username']
        password = data['password']
        email = data.get('email', f"{username}@example.com")
        
        # Generar secret MFA
        mfa_secret = pyotp.random_base32()
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, mfa_secret) VALUES (?, ?, ?, ?)',
                (username, email, password_hash.decode('utf-8'), mfa_secret)
            )
            conn.commit()
            
            # Obtener ID del usuario creado
            user_id = cursor.lastrowid
            
            # Generar QR
            qr_code = generate_qr_code(mfa_secret, username)
            
            # Generar token
            token = generate_token(user_id, username)
            
            return jsonify({
                'message': 'Usuario registrado exitosamente',
                'access_token': token,
                'token_type': 'bearer',
                'qr_code': qr_code,
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': email
                }
            }), 201
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Usuario o email ya existe'}), 400
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Error en registro: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/login', methods=['POST'])
def login():
    """Login con verificación MFA"""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username y password son requeridos'}), 400
        
        username = data['username']
        password = data['password']
        otp_code = data.get('otp_code')
        
        if not otp_code:
            return jsonify({'error': 'Código OTP es requerido'}), 400
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, username, email, password_hash, mfa_secret FROM users WHERE username = ? AND is_active = 1',
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        user_id, username, email, password_hash, mfa_secret = user
        
        # Verificar password
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        # Verificar OTP
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(otp_code):
            return jsonify({'error': 'Código OTP inválido'}), 401
        
        # Generar token
        token = generate_token(user_id, username)
        
        return jsonify({
            'message': 'Login exitoso',
            'access_token': token,
            'token_type': 'bearer',
            'user': {
                'id': user_id,
                'username': username,
                'email': email
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/verify-token', methods=['POST'])
def verify_token_endpoint():
    """Verificar si un token es válido"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token requerido'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Token inválido'}), 401
        
        return jsonify({
            'valid': True,
            'user_id': payload['user_id'],
            'username': payload['username']
        }), 200
        
    except Exception as e:
        logger.error(f"Error verificando token: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5001, debug=True)
