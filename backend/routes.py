"""
API Routes for ZeinaGuard Pro Backend
Handles authentication, threats, sensors, and other endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from datetime import datetime
from auth import (
    AuthService, authenticate_user, token_required, 
    admin_required, get_user_by_id
)
from websocket_server import broadcast_threat_event, broadcast_sensor_status

# Create blueprints
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
threats_bp = Blueprint('threats', __name__, url_prefix='/api/threats')
sensors_bp = Blueprint('sensors', __name__, url_prefix='/api/sensors')
alerts_bp = Blueprint('alerts', __name__, url_prefix='/api/alerts')
analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/analytics')
users_bp = Blueprint('users', __name__, url_prefix='/api/users')

# Initialize auth service
auth_service = AuthService()


# ==================== Authentication Routes ====================

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login endpoint
    Expected JSON: { "username": "...", "password": "..." }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Missing request body'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400
        
        # Authenticate user
        user = authenticate_user(username, password)
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create tokens
        tokens = auth_service.create_tokens(
            user_id=user['user_id'],
            username=user['username'],
            email=user['email'],
            is_admin=user.get('is_admin', False)
        )
        
        return jsonify(tokens), 200
    
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    User logout endpoint
    Token revocation would be implemented with database in production
    """
    return jsonify({'message': 'Logged out successfully'}), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required()
def refresh():
    """
    Refresh access token
    Requires valid JWT token
    """
    try:
        current_user = AuthService.get_current_user()
        user = get_user_by_id(current_user['user_id'] if current_user else None)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        tokens = auth_service.create_tokens(
            user_id=user['user_id'],
            username=user['username'],
            email=user['email'],
            is_admin=user.get('is_admin', False)
        )
        
        return jsonify(tokens), 200
    
    except Exception as e:
        return jsonify({'error': f'Token refresh failed: {str(e)}'}), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current authenticated user information"""
    try:
        current_user = AuthService.get_current_user()
        return jsonify(current_user), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get user: {str(e)}'}), 500


# ==================== Threat Routes ====================

@threats_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def get_threats():
    """Get list of threats — real data from DB"""
    try:
        from models import Threat
        limit = request.args.get('limit', default=50, type=int)
        offset = request.args.get('offset', default=0, type=int)
        severity = request.args.get('severity', default=None, type=str)
        is_resolved = request.args.get('resolved', default=None)

        query = Threat.query
        if severity:
            query = query.filter(Threat.severity == severity)
        if is_resolved is not None:
            resolved_bool = str(is_resolved).lower() in ('true', '1')
            query = query.filter(Threat.is_resolved == resolved_bool)
        query = query.order_by(Threat.created_at.desc())
        total = query.count()
        threats = query.offset(offset).limit(limit).all()

        return jsonify({
            'data': [{
                'id': t.id,
                'threat_type': t.threat_type,
                'severity': t.severity,
                'source_mac': t.source_mac,
                'target_mac': t.target_mac,
                'ssid': t.ssid,
                'detected_by': t.detected_by,
                'description': t.description,
                'is_resolved': t.is_resolved,
                'created_at': t.created_at.isoformat() if t.created_at else None,
            } for t in threats],
            'pagination': {'total': total, 'limit': limit, 'offset': offset},
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch threats: {str(e)}'}), 500


@threats_bp.route('/<int:threat_id>', methods=['GET'])
@jwt_required(optional=True)
def get_threat(threat_id):
    """Get threat details"""
    try:
        threat = {
            'id': threat_id,
            'threat_type': 'rogue_ap',
            'severity': 'critical',
            'source_mac': '00:11:22:33:44:55',
            'ssid': 'FreeWiFi',
            'detected_by': 1,
            'description': 'Rogue access point detected in office area',
            'is_resolved': False,
            'created_at': datetime.now().isoformat(),
            'events': [
                {
                    'id': 1,
                    'timestamp': datetime.now().isoformat(),
                    'signal_strength': -45,
                    'packet_count': 150
                }
            ]
        }
        return jsonify(threat), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to fetch threat: {str(e)}'}), 500


@threats_bp.route('/<int:threat_id>/resolve', methods=['POST'])
@jwt_required(optional=True)
def resolve_threat(threat_id):
    """Mark threat as resolved in DB"""
    try:
        from models import Threat, db
        current_user = AuthService.get_current_user() or {}
        threat = Threat.query.get(threat_id)
        if threat:
            threat.is_resolved = True
            threat.updated_at = datetime.utcnow()
            db.session.commit()
        return jsonify({
            'message': 'Threat resolved successfully',
            'threat_id': threat_id,
            'resolved_by': current_user.get('username', 'anonymous'),
            'resolved_at': datetime.utcnow().isoformat(),
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to resolve threat: {str(e)}'}), 500


@threats_bp.route('/<int:threat_id>/block', methods=['POST'])
@jwt_required(optional=True)
def block_threat(threat_id):
    """Block/whitelist a threat"""
    try:
        data = request.get_json()
        action = data.get('action', 'block') if data else 'block'
        
        return jsonify({
            'message': 'Threat blocked/whitelisted',
            'threat_id': threat_id,
            'action': action,
            'blocked_at': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to block threat: {str(e)}'}), 500


@threats_bp.route('/demo/simulate-threat', methods=['POST'])
@jwt_required(optional=True)
def simulate_threat():
    """
    Demo endpoint to simulate a real-time threat detection
    Broadcasts threat event via WebSocket to all connected clients
    This simulates what would happen when the detection engine finds a threat
    """
    try:
        from models import Threat, Alert, db
        import random, string
        current_user = AuthService.get_current_user() or {}
        data = request.get_json(silent=True) or {}

        threat_types = ['rogue_ap', 'evil_twin', 'deauth_attack', 'signal_jamming']
        severities = ['critical', 'high', 'medium', 'low']
        mac = ':'.join(['%02X' % random.randint(0,255) for _ in range(6)])

        # Persist to DB
        threat = Threat(
            threat_type=data.get('threat_type', random.choice(threat_types)),
            severity=data.get('severity', random.choice(severities)),
            source_mac=data.get('source_mac', mac),
            ssid=data.get('ssid', 'SimulatedNet-' + ''.join(random.choices(string.digits, k=4))),
            description=data.get('description', 'Simulated threat for demo/testing purposes'),
            is_resolved=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.session.add(threat)
        db.session.flush()

        alert = Alert(
            threat_id=threat.id,
            message=f"[SIMULATED] {threat.threat_type.upper()} ({threat.severity}) detected — {threat.ssid}",
            is_read=False,
            is_acknowledged=False,
            created_at=datetime.utcnow(),
        )
        db.session.add(alert)
        db.session.commit()

        threat_data = {
            'id': threat.id,
            'threat_type': threat.threat_type,
            'severity': threat.severity,
            'source_mac': threat.source_mac,
            'ssid': threat.ssid,
            'description': threat.description,
            'is_resolved': threat.is_resolved,
            'created_at': threat.created_at.isoformat(),
            'simulated_by': current_user.get('username', 'anonymous'),
        }
        broadcast_threat_event(threat_data)

        return jsonify({
            'message': 'Threat simulated, persisted to DB, and broadcasted',
            'threat': threat_data,
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to simulate threat: {str(e)}'}), 500


# ==================== Sensor Routes ====================

@sensors_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def get_sensors():
    """Get list of sensors — real data from DB + live WebSocket status overlay"""
    try:
        from models import Sensor
        from websocket_server import get_connected_sensors
        live = get_connected_sensors()
        sensors = Sensor.query.all()
        result = []
        for s in sensors:
            is_live = s.hostname in live
            result.append({
                'id': s.id,
                'name': s.name,
                'hostname': s.hostname,
                'ip_address': s.ip_address,
                'mac_address': s.mac_address,
                'location': s.location,
                'is_active': s.is_active,
                'firmware_version': s.firmware_version,
                'status': 'online' if is_live else 'offline',
                'last_heartbeat': live[s.hostname]['last_seen'] if is_live else (
                    s.updated_at.isoformat() if s.updated_at else None
                ),
                'created_at': s.created_at.isoformat() if s.created_at else None,
            })
        return jsonify({'data': result, 'total': len(result)}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch sensors: {str(e)}'}), 500


@sensors_bp.route('/<int:sensor_id>/health', methods=['GET'])
@jwt_required(optional=True)
def get_sensor_health(sensor_id):
    """Get sensor health metrics"""
    try:
        health = {
            'sensor_id': sensor_id,
            'status': 'online',
            'signal_strength': 95,
            'cpu_usage': 25.5,
            'memory_usage': 45.2,
            'uptime': 86400,  # 24 hours
            'last_heartbeat': datetime.now().isoformat(),
            'events_24h': 150,
            'threats_detected_24h': 2
        }
        return jsonify(health), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to fetch sensor health: {str(e)}'}), 500


# ==================== Alert Routes ====================

@alerts_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def get_alerts():
    """Get list of alerts — real data from DB"""
    try:
        from models import Alert
        limit = request.args.get('limit', default=100, type=int)
        alerts = Alert.query.order_by(Alert.created_at.desc()).limit(limit).all()
        return jsonify({'data': [{
            'id': a.id,
            'threat_id': a.threat_id,
            'rule_id': a.rule_id,
            'message': a.message,
            'is_read': a.is_read,
            'is_acknowledged': a.is_acknowledged,
            'acknowledged_by': a.acknowledged_by,
            'acknowledged_at': a.acknowledged_at.isoformat() if a.acknowledged_at else None,
            'created_at': a.created_at.isoformat() if a.created_at else None,
        } for a in alerts]}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch alerts: {str(e)}'}), 500


@alerts_bp.route('/<int:alert_id>/acknowledge', methods=['POST'])
@jwt_required(optional=True)
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        from models import Alert, db
        current_user = AuthService.get_current_user() or {}
        alert = Alert.query.get(alert_id)
        if alert:
            alert.is_acknowledged = True
            alert.acknowledged_by = current_user.get('username', 'anonymous')
            alert.acknowledged_at = datetime.utcnow()
            db.session.commit()
        return jsonify({
            'message': 'Alert acknowledged',
            'alert_id': alert_id,
            'acknowledged_by': current_user.get('username', 'anonymous'),
            'acknowledged_at': datetime.utcnow().isoformat(),
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to acknowledge alert: {str(e)}'}), 500


# ==================== Analytics Routes ====================

@analytics_bp.route('/threat-stats', methods=['GET'])
@jwt_required(optional=True)
def get_threat_stats():
    """Get threat statistics from DB"""
    try:
        from models import Threat, db
        from sqlalchemy import func
        total = Threat.query.count()
        today = datetime.utcnow().date()
        threats_today = Threat.query.filter(
            func.date(Threat.created_at) == today
        ).count()
        resolved = Threat.query.filter_by(is_resolved=True).count()
        active = Threat.query.filter_by(is_resolved=False).count()
        by_severity = dict(
            db.session.query(Threat.severity, func.count(Threat.id))
            .group_by(Threat.severity).all()
        )
        by_type = dict(
            db.session.query(Threat.threat_type, func.count(Threat.id))
            .group_by(Threat.threat_type).all()
        )
        return jsonify({
            'total_threats': total,
            'threats_today': threats_today,
            'critical_threats': by_severity.get('critical', 0),
            'high_threats': by_severity.get('high', 0),
            'medium_threats': by_severity.get('medium', 0),
            'low_threats': by_severity.get('low', 0),
            'resolved_threats': resolved,
            'active_threats': active,
            'threat_types': by_type,
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch threat stats: {str(e)}'}), 500


@analytics_bp.route('/trends', methods=['GET'])
@jwt_required(optional=True)
def get_trends():
    """Get last-7-day daily threat counts from DB"""
    try:
        from models import Threat, Sensor, db
        from sqlalchemy import func
        from datetime import timedelta
        daily = []
        for i in range(6, -1, -1):
            d = (datetime.utcnow() - timedelta(days=i)).date()
            count = Threat.query.filter(func.date(Threat.created_at) == d).count()
            daily.append({'date': str(d), 'count': count})
        sensors = Sensor.query.filter_by(is_active=True).all()
        uptime = [{'sensor': s.name, 'uptime': 100.0} for s in sensors]
        return jsonify({'daily_threats': daily, 'sensor_uptime': uptime}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch trends: {str(e)}'}), 500


# ==================== User Routes ====================

@users_bp.route('/profile', methods=['GET'])
@jwt_required(optional=True)
def get_user_profile():
    """Get current user's profile"""
    try:
        current_user = AuthService.get_current_user() or {}

        profile = {
            'id': current_user.get('user_id'),
            'username': current_user.get('username'),
            'email': current_user.get('email'),
            'is_admin': current_user.get('is_admin', False),
            'created_at': datetime.now().isoformat()
        }
        
        return jsonify(profile), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to fetch profile: {str(e)}'}), 500


def register_blueprints(app):
    """Register all API blueprints"""
    from routes_dashboard import dashboard_bp
    from routes_topology import topology_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(sensors_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(topology_bp)
