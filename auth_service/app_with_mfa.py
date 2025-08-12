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
            is_active BOOLEAN DEFAULT 1,
            mfa_secret TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def generate_qr_code(username, secret):
    """Generar código QR para MFA"""
    # Crear URI para Google Authenticator
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="FullStack App"
    )
    
    # Generar código QR
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    # Crear imagen
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convertir a base64
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"

def generate_token(user_id, username):
    """Generar token JWT"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """Verificar token JWT"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({'error': 'Todos los campos son obligatorios'}), 400

        # Hash de la contraseña
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Generar secreto MFA
        mfa_secret = pyotp.random_base32()

        conn = sqlite3.connect(DATABASE)
        try:
            conn.execute(
                'INSERT INTO users (username, email, password_hash, mfa_secret) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, mfa_secret)
            )
            conn.commit()
            
            # Obtener el ID del usuario creado
            user_id = conn.lastrowid
            
            # Generar código QR
            qr_code = generate_qr_code(username, mfa_secret)
            
            # Generar token
            token = generate_token(user_id, username)

            logger.info(f"Usuario registrado: {username}")
            
            return jsonify({
                'message': 'Usuario registrado exitosamente',
                'access_token': token,
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': email
                },
                'qr_code': qr_code
            }), 201

        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                return jsonify({'error': 'El nombre de usuario ya existe'}), 400
            elif 'email' in str(e):
                return jsonify({'error': 'El email ya está registrado'}), 400
            else:
                return jsonify({'error': 'Error de integridad en los datos'}), 400
        finally:
            conn.close()

    except Exception as e:
        logger.error(f"Error en registro: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        otp_code = data.get('otp_code')

        if not username or not password or not otp_code:
            return jsonify({'error': 'Usuario, contraseña y código OTP son obligatorios'}), 400

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Buscar usuario por username o email
        cursor.execute(
            'SELECT id, username, email, password_hash, mfa_secret FROM users WHERE username = ? OR email = ? AND is_active = 1',
            (username, username)
        )
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({'error': 'Credenciales inválidas'}), 401

        user_id, user_username, user_email, password_hash, mfa_secret = user

        # Verificar contraseña
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            return jsonify({'error': 'Credenciales inválidas'}), 401

        # Verificar código OTP
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(otp_code):
            return jsonify({'error': 'Código OTP inválido'}), 401

        # Generar token
        token = generate_token(user_id, user_username)

        logger.info(f"Login exitoso: {user_username}")
        
        return jsonify({
            'message': 'Login exitoso',
            'access_token': token,
            'user': {
                'id': user_id,
                'username': user_username,
                'email': user_email
            }
        }), 200

    except Exception as e:
        logger.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/verify-token', methods=['POST'])
def verify_token_endpoint():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token no proporcionado'}), 401

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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'Auth Service is running', 'mfa_enabled': True}), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
