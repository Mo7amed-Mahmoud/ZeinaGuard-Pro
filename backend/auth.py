"""
JWT Authentication Module for ZeinaGuard Pro
Handles user authentication, token generation, and validation
"""

from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, get_jwt
)
import os

# Password hashing configuration
HASH_METHOD = 'pbkdf2:sha256'


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-SHA256"""
    return generate_password_hash(password, method=HASH_METHOD)


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verify a password against its hash"""
    return check_password_hash(stored_hash, provided_password)


class AuthService:
    """Service for handling authentication operations"""
    
    def __init__(self, app=None):
        self.app = app
        self.jwt = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize JWT with Flask app"""
        self.jwt = JWTManager(app)
        
        # JWT error handlers
        @self.jwt.expired_token_loader
        def expired_token_callback(jwt_header, jwt_data):
            return jsonify({
                'error': 'Token has expired',
                'code': 'token_expired'
            }), 401
        
        @self.jwt.invalid_token_loader
        def invalid_token_callback(error):
            return jsonify({
                'error': 'Invalid token',
                'code': 'invalid_token'
            }), 401
        
        @self.jwt.unauthorized_loader
        def missing_token_callback(error):
            return jsonify({
                'error': 'Request does not contain an access token',
                'code': 'authorization_required'
            }), 401
    
    @staticmethod
    def create_tokens(user_id: int, username: str, email: str, is_admin: bool = False):
        """
        Create JWT access token
        
        Args:
            user_id: User's database ID
            username: User's username
            email: User's email
            is_admin: Whether user is admin
        
        Returns:
            Dictionary with access token and expiration
        """
        # Flask-JWT-Extended 4.7+ requires identity to be a simple type (string/int).
        # Extra user info goes in additional_claims.
        additional_claims = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'is_admin': is_admin,
        }

        access_token = create_access_token(
            identity=str(user_id),
            additional_claims=additional_claims,
            expires_delta=timedelta(hours=24),
        )
        
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 86400,  # 24 hours in seconds
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'is_admin': is_admin
            }
        }
    
    @staticmethod
    def get_current_user():
        """Get current authenticated user from JWT (returns dict with user info)."""
        try:
            claims = get_jwt()
            return {
                'user_id': claims.get('user_id'),
                'username': claims.get('username'),
                'email': claims.get('email'),
                'is_admin': claims.get('is_admin', False),
            }
        except Exception:
            return None

    @staticmethod
    def get_current_user_id():
        """Get current user ID from JWT"""
        try:
            return int(get_jwt_identity())
        except Exception:
            return None


def token_required(f):
    """Decorator to require JWT token"""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user = AuthService.get_current_user()
        return f(current_user, *args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user = AuthService.get_current_user()
        if not (current_user and current_user.get('is_admin')):
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated_function


# In-memory user store (FOR DEVELOPMENT ONLY - use database in production)
# Matches init_db.py credentials: admin/admin123, analyst/analyst123
MOCK_USERS = {
    'admin': {
        'user_id': 1,
        'username': 'admin',
        'email': 'admin@zeinaguard.local',
        'password_hash': generate_password_hash('admin123', method=HASH_METHOD),
        'is_admin': True,
        'is_active': True,
        'created_at': datetime.now()
    },
    'analyst': {
        'user_id': 2,
        'username': 'analyst',
        'email': 'analyst@zeinaguard.local',
        'password_hash': generate_password_hash('analyst123', method=HASH_METHOD),
        'is_admin': False,
        'is_active': True,
        'created_at': datetime.now()
    },
    'monitor': {
        'user_id': 3,
        'username': 'monitor',
        'email': 'monitor@zeinaguard.local',
        'password_hash': generate_password_hash('monitor123', method=HASH_METHOD),
        'is_admin': False,
        'is_active': True,
        'created_at': datetime.now()
    },
}


def authenticate_user(username: str, password: str):
    """
    Authenticate user by username and password
    Returns user data if valid, None otherwise
    """
    user = MOCK_USERS.get(username)
    
    if not user:
        return None
    
    if not user.get('is_active'):
        return None
    
    if not verify_password(user['password_hash'], password):
        return None
    
    return user


def get_user_by_id(user_id: int):
    """Get user by ID"""
    for user in MOCK_USERS.values():
        if user['user_id'] == user_id:
            return user
    return None
