from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
import os
import re
import logging
import pyotp
import qrcode
import io
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configuración de CORS: permite definir múltiples orígenes en la variable de entorno CORS_ORIGINS
# Si no está definida, habilitamos localhost y el dominio de producción por defecto.
origins_env = os.environ.get('CORS_ORIGINS')
if origins_env:
    raw_origins = [o.strip() for o in origins_env.split(',') if o.strip()]
else:
    # Incluimos un regex por defecto para subdominios de vercel de este proyecto
    raw_origins = ['http://localhost:4200', 'https://seg-front.vercel.app', 'regex:https://seg-front.*vercel.app']

# Soporte de patrones: si un origen empieza con 'regex:' lo convertimos a regex compilado
_origins = []
for o in raw_origins:
    if o.lower().startswith('regex:'):
        try:
            pattern = o[6:]
            _origins.append(re.compile(pattern))
        except re.error:
            # Si regex inválido lo ignoramos (o podríamos loggear)
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

# Fallback manual para asegurarnos que siempre se incluyan cabeceras CORS cuando el origen matchea
@app.after_request
def ensure_cors_headers(resp):
    try:
        origin = request.headers.get('Origin')
        if not origin:
            return resp
        # Verificar contra lista de orígenes (_origins) que puede contener strings o patrones regex
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
    except Exception as e:
        logger.debug(f"Error en ensure_cors_headers: {e}")
    return resp

# Rate Limiting (previene abuso de endpoints críticos)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Configuración
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-in-prod')

# Configuración MongoDB
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/auth_service_db')
mongo_client = MongoClient(MONGO_URI)
from urllib.parse import urlparse
def _extract_db_name(uri: str, default_name: str) -> str:
    parsed = urlparse(uri)
    path = parsed.path.lstrip('/')
    return path.split('/')[0] if path else default_name
DB_NAME = os.environ.get('MONGO_DB_NAME', _extract_db_name(MONGO_URI, 'auth_service_db'))
mongo_db = mongo_client[DB_NAME]
users_collection = mongo_db['users']

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Inicializar admin en MongoDB si no existe
def init_db():
    # Crear índices únicos (idempotente: si ya existen MongoDB ignora)
    try:
        users_collection.create_index('username', unique=True)
    except Exception as e:
        logger.warning(f"No se pudo crear índice único en username: {e}")
    try:
        users_collection.create_index('email', unique=True)
    except Exception as e:
        logger.warning(f"No se pudo crear índice único en email: {e}")
    admin = users_collection.find_one({'username': 'admin'})
    if not admin:
        admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
        mfa_secret = pyotp.random_base32()
        users_collection.insert_one({
            'username': 'admin',
            'email': 'admin@example.com',
            'password_hash': admin_password.decode('utf-8'),
            'mfa_secret': mfa_secret,
            'is_active': True,
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc)
        })
    logger.info("Usuario admin creado: admin/admin123")

def generate_token(user_id, username):
    """Generar JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24),
        'iat': datetime.now(timezone.utc)
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

def generate_qr_code(username, secret):
    """Generar código QR para MFA"""
    try:
        # Crear URI para Google Authenticator
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Fullstack App"
        )
        
        # Generar código QR
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Crear imagen del QR
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convertir a base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        logger.error(f"Error generando QR: {str(e)}")
        return None

def verify_otp(secret, otp_code):
    """Verificar código OTP"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(otp_code, valid_window=1)
    except Exception as e:
        logger.error(f"Error verificando OTP: {str(e)}")
        return False

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():

    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        otp_code = data.get('otp_code')

        if not username or not password:
            return jsonify({'error': 'Username y password son requeridos'}), 400

        if not otp_code:
            return jsonify({'error': 'Código OTP requerido'}), 400

        user = users_collection.find_one({
            '$or': [
                {'username': username},
                {'email': username}
            ]
        })

        if not user:
            return jsonify({'error': 'Credenciales inválidas'}), 401

        if not user.get('is_active', True):
            return jsonify({'error': 'Usuario desactivado'}), 401

        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Credenciales inválidas'}), 401

        # Verificar código OTP
        if not user.get('mfa_secret') or not verify_otp(user['mfa_secret'], otp_code):
            return jsonify({'error': 'Código OTP inválido'}), 401

        token = generate_token(str(user['_id']), user['username'])

        return jsonify({
            'access_token': token,
            'token_type': 'Bearer',
            'user': {
                'id': str(user['_id']),
                'username': user['username']
            }
        })

    except Exception as e:
        logger.error(f"Error en login: {str(e)}")
        # Si es error de credenciales, devolver mensaje claro
        return jsonify({'error': 'Credenciales inválidas'}), 401

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        # Normalización básica (trim). Email a minúsculas para evitar duplicados case-insensitive.
        if isinstance(username, str):
            username = username.strip()
        if isinstance(email, str):
            email = email.strip().lower()

        logger.info(f"Intento de registro username='{username}' email='{email}'")

        if not all([username, email, password]):
            return jsonify({'error': 'Todos los campos son requeridos'}), 400

        if len(password) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        mfa_secret = pyotp.random_base32()

        # Verificar unicidad diferenciando campo para mejor feedback
        existing_username = users_collection.find_one({'username': username})
        if existing_username:
            logger.info(f"Registro duplicado username existente username='{username}' id={existing_username.get('_id')}")
            return jsonify({
                'error': 'El nombre de usuario ya está en uso',
                'code': 'USERNAME_EXISTS'
            }), 409
        existing_email = users_collection.find_one({'email': email})
        if existing_email:
            logger.info(f"Registro duplicado email existente email='{email}' id={existing_email.get('_id')}")
            return jsonify({
                'error': 'El email ya está registrado',
                'code': 'EMAIL_EXISTS'
            }), 409

        user_doc = {
            'username': username,
            'email': email,
            'password_hash': password_hash.decode('utf-8'),
            'mfa_secret': mfa_secret,
            'is_active': True,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        try:
            result = users_collection.insert_one(user_doc)
        except DuplicateKeyError:
            # Carrera entre dos solicitudes simultáneas: identificar cuál campo chocó intentando otra vez consultas
            logger.info(f"DuplicateKeyError race condition username='{username}' email='{email}'")
            if users_collection.find_one({'username': username}):
                return jsonify({'error': 'El nombre de usuario ya está en uso', 'code': 'USERNAME_EXISTS'}), 409
            if users_collection.find_one({'email': email}):
                return jsonify({'error': 'El email ya está registrado', 'code': 'EMAIL_EXISTS'}), 409
            return jsonify({'error': 'Username o email ya existe', 'code': 'USER_EXISTS'}), 409
        user_id = str(result.inserted_id)

        # Generar código QR para MFA
        qr_code = generate_qr_code(username, mfa_secret)

        # Generar token inmediato tras registro (flujo aceptado por el frontend)
        access_token = generate_token(user_id, username)

        response_payload = {
            'message': 'Usuario registrado exitosamente',
            'access_token': access_token,
            'token_type': 'Bearer',
            'user': {
                'id': user_id,
                'username': username,
                'email': email
            },
            'qr_code': qr_code
        }
        # Exponer mfa_secret sólo en desarrollo si MFA_DEBUG=1
        if os.environ.get('MFA_DEBUG', '0') == '1':
            response_payload['mfa_secret'] = mfa_secret

        return jsonify(response_payload), 201

    except Exception as e:
        logger.error(f"Error en registro: {str(e)}", exc_info=True)
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/verify', methods=['POST'])
def verify():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token requerido'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Token inválido o expirado'}), 401
        
        return jsonify({
            'valid': True,
            'user': {
                'id': payload['user_id'],
                'username': payload['username']
            }
        })
        
    except Exception as e:
        logger.error(f"Error en verificación: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({'service': 'Auth Service', 'health': '/health'}), 200

@app.route('/health', methods=['GET'])
@app.route('/healthz', methods=['GET'])
def health():
    return jsonify({'status': 'Auth Service is running', 'mfa_enabled': True, 'db': DB_NAME})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)
