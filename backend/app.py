"""
ZeinaGuard Pro - Wireless Intrusion Prevention System
Flask Backend - Detection Engine and API Server
"""

import os
from datetime import timedelta
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from auth import AuthService
from routes import register_blueprints
from websocket_server import init_socketio
from models import db

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration — use env var if set, otherwise generate a per-process secret (dev only)
import secrets as _secrets
jwt_secret = os.getenv('JWT_SECRET_KEY') or _secrets.token_hex(48)
if not os.getenv('JWT_SECRET_KEY'):
    print("[WARN] JWT_SECRET_KEY not set. Using a temporary per-process secret — sessions will reset on restart. Set JWT_SECRET_KEY in Secrets for production.")

app.config['JWT_SECRET_KEY'] = jwt_secret
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JSON_SORT_KEYS'] = False

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://zeinaguard_user:secure_password_change_me@localhost:5432/zeinaguard_db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}

# CORS - restrict to Replit proxy domains and localhost for dev
_replit_dev_domain = os.getenv('REPLIT_DEV_DOMAIN', '')
_allowed_origins = [
    'http://localhost:5000',
    'http://localhost:3000',
]
if _replit_dev_domain:
    _allowed_origins.append(f'https://{_replit_dev_domain}')

CORS(app, resources={
    r"/api/*": {
        "origins": _allowed_origins,
        "methods": ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        "allow_headers": ['Content-Type', 'Authorization'],
        "supports_credentials": True,
    },
    r"/socket.io/*": {
        "origins": _allowed_origins,
        "supports_credentials": True,
    }
})

# Initialize Database
db.init_app(app)

# Initialize JWT
auth_service = AuthService(app)

# Initialize WebSocket (Socket.io)
socketio = init_socketio(app)
app.socketio = socketio  # Store reference for broadcasting

# Register API blueprints
register_blueprints(app)

# Create tables on startup
with app.app_context():
    try:
        db.create_all()
        print("[DB] Database tables created/verified")
    except Exception as e:
        print(f"[DB] Warning: Could not create tables: {e}")

# Health check endpoint
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'zeinaguard-backend'}), 200

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    """Root endpoint - API information"""
    return jsonify({
        'service': 'ZeinaGuard Pro Backend',
        'version': '1.0.0',
        'status': 'running',
        'environment': os.getenv('FLASK_ENV', 'development'),
        'endpoints': {
            'auth': '/api/auth/login',
            'threats': '/api/threats',
            'sensors': '/api/sensors',
            'alerts': '/api/alerts',
            'analytics': '/api/analytics',
            'users': '/api/users',
            'topology': '/api/topology'
        }
    }), 200

# API status endpoint
@app.route('/api/status', methods=['GET'])
def api_status():
    """API status endpoint"""
    return jsonify({
        'api': 'operational',
        'database': 'pending',
        'detection_engine': 'initializing',
        'version': '1.0.0'
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'code': 404}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'code': 500}), 500

if __name__ == '__main__':
    # Development server with WebSocket support
    port = int(os.getenv('FLASK_PORT', 8000))
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
        allow_unsafe_werkzeug=True
    )
