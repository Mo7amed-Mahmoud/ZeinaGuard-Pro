"""
WebSocket Server for ZeinaGuard Pro
Handles real-time events from both web clients (dashboard) and physical sensors (Raspberry Pi).

Events from web clients:  subscribe_threats, subscribe_sensors
Events from sensors:       sensor_register, network_scan, new_threat
Events broadcast out:      threat_event, sensor_status, live_scan
"""

import os
import json
from datetime import datetime
from flask_socketio import SocketIO, emit
from flask import request

try:
    from redis import Redis
    redis_client = Redis.from_url(
        os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
        decode_responses=True,
        socket_connect_timeout=2,
    )
    redis_client.ping()
    print("[Redis] Connected successfully")
except Exception:
    print("[Redis] Not available — running without Redis event persistence")
    redis_client = None

# Registry of connected clients (both web dashboards and physical sensors)
connected_clients = {}   # sid → {connected_at, subscriptions, type, sensor_id}
connected_sensors = {}   # sensor_id → {sid, hostname, last_seen}


def init_socketio(app):
    """Initialize Socket.io with Flask app."""
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        ping_timeout=60,
        ping_interval=25,
        async_mode='threading',
    )

    # ── Generic connection events ────────────────────────────────────────────

    @socketio.on('connect')
    def handle_connect(data=None):
        client_id = request.sid
        connected_clients[client_id] = {
            'connected_at': datetime.now().isoformat(),
            'subscriptions': [],
            'type': 'web',       # overwritten to 'sensor' on sensor_register
            'sensor_id': None,
        }
        emit('connection_response', {
            'data': 'Connected to ZeinaGuard Pro',
            'client_id': client_id,
        })
        print(f"[WS] Client connected: {client_id}")

    @socketio.on('disconnect')
    def handle_disconnect():
        client_id = request.sid
        meta = connected_clients.pop(client_id, {})
        sensor_id = meta.get('sensor_id')
        if sensor_id and sensor_id in connected_sensors:
            del connected_sensors[sensor_id]
            socketio.emit('sensor_status', {
                'type': 'sensor_status',
                'timestamp': datetime.now().isoformat(),
                'data': {
                    'sensor_id': sensor_id,
                    'hostname': meta.get('hostname', sensor_id),
                    'status': 'offline',
                },
            })
            print(f"[WS] Sensor disconnected: {sensor_id}")
        else:
            print(f"[WS] Web client disconnected: {client_id}")

    # ── Web dashboard subscription events ───────────────────────────────────

    @socketio.on('subscribe_threats')
    def handle_subscribe_threats():
        client_id = request.sid
        if client_id in connected_clients:
            subs = connected_clients[client_id]['subscriptions']
            if 'threats' not in subs:
                subs.append('threats')
        emit('subscription_response', {'channel': 'threats', 'subscribed': True})

    @socketio.on('unsubscribe_threats')
    def handle_unsubscribe_threats():
        client_id = request.sid
        if client_id in connected_clients:
            subs = connected_clients[client_id]['subscriptions']
            if 'threats' in subs:
                subs.remove('threats')
        emit('subscription_response', {'channel': 'threats', 'subscribed': False})

    @socketio.on('subscribe_sensors')
    def handle_subscribe_sensors():
        client_id = request.sid
        if client_id in connected_clients:
            subs = connected_clients[client_id]['subscriptions']
            if 'sensors' not in subs:
                subs.append('sensors')
        emit('subscription_response', {'channel': 'sensors', 'subscribed': True})

    @socketio.on('unsubscribe_sensors')
    def handle_unsubscribe_sensors():
        client_id = request.sid
        if client_id in connected_clients:
            subs = connected_clients[client_id]['subscriptions']
            if 'sensors' in subs:
                subs.remove('sensors')
        emit('subscription_response', {'channel': 'sensors', 'subscribed': False})

    # ── Sensor → Backend events ──────────────────────────────────────────────

    @socketio.on('sensor_register')
    def handle_sensor_register(data):
        """
        Called when a physical sensor (Raspberry Pi) connects.
        Payload: { sensor_id, hostname }
        """
        client_id = request.sid
        sensor_id = data.get('sensor_id', client_id)
        hostname = data.get('hostname', 'unknown')

        if client_id in connected_clients:
            connected_clients[client_id]['type'] = 'sensor'
            connected_clients[client_id]['sensor_id'] = sensor_id
            connected_clients[client_id]['hostname'] = hostname

        connected_sensors[sensor_id] = {
            'sid': client_id,
            'hostname': hostname,
            'last_seen': datetime.now().isoformat(),
        }

        # Persist / upsert sensor in database
        try:
            from flask import current_app
            from models import db, Sensor
            with current_app.app_context():
                sensor = Sensor.query.filter_by(hostname=hostname).first()
                if not sensor:
                    sensor = Sensor(
                        name=f"Sensor {hostname}",
                        hostname=hostname,
                        is_active=True,
                    )
                    db.session.add(sensor)
                else:
                    sensor.is_active = True
                db.session.commit()
        except Exception as e:
            print(f"[WS] DB sensor upsert failed: {e}")

        emit('registration_success', {
            'sensor_id': sensor_id,
            'message': 'Sensor registered successfully',
        })

        # Broadcast sensor online status to all web clients
        socketio.emit('sensor_status', {
            'type': 'sensor_status',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'sensor_id': sensor_id,
                'hostname': hostname,
                'status': 'online',
            },
        })
        print(f"[WS] Sensor registered: {sensor_id} ({hostname})")

    @socketio.on('network_scan')
    def handle_network_scan(data):
        """
        Batch of network scan results from a physical sensor.
        Payload: { sensor_id, hostname, sent_at, networks: [...] }
        Forwarded to all subscribed web clients as 'live_scan'.
        """
        sensor_id = data.get('sensor_id', request.sid)
        if sensor_id in connected_sensors:
            connected_sensors[sensor_id]['last_seen'] = datetime.now().isoformat()

        # Forward to web clients
        socketio.emit('live_scan', {
            'sensor_id': sensor_id,
            'hostname': data.get('hostname'),
            'sent_at': data.get('sent_at'),
            'networks': data.get('networks', []),
        })

        # Persist ROGUE / SUSPICIOUS networks as threats
        try:
            from flask import current_app
            from models import db, Sensor, Threat, Alert
            networks = data.get('networks', [])
            with current_app.app_context():
                sensor = Sensor.query.filter_by(hostname=data.get('hostname')).first()
                for net in networks:
                    classification = net.get('classification', 'LEGIT')
                    if classification not in ('ROGUE', 'SUSPICIOUS'):
                        continue
                    severity = 'critical' if classification == 'ROGUE' else 'high'
                    threat = Threat(
                        threat_type='rogue_ap' if classification == 'ROGUE' else 'suspicious_ap',
                        severity=severity,
                        source_mac=net.get('bssid'),
                        ssid=net.get('ssid'),
                        detected_by=sensor.id if sensor else None,
                        description=f"{classification}: score={net.get('score',0)}, reasons={net.get('reasons',[])}",
                        is_resolved=False,
                    )
                    db.session.add(threat)
                    db.session.flush()
                    alert = Alert(
                        threat_id=threat.id,
                        message=f"{classification} AP detected: {net.get('ssid')} ({net.get('bssid')})",
                        is_read=False,
                        is_acknowledged=False,
                    )
                    db.session.add(alert)
                db.session.commit()
        except Exception as e:
            print(f"[WS] DB scan persist failed: {e}")

    @socketio.on('new_threat')
    def handle_new_threat(data):
        """
        Threat event from a physical sensor (high-confidence rogue AP detection).
        Payload: { threat_type, ssid, source_mac, signal, severity, score, reasons, sensor_id }
        """
        sensor_id = data.get('sensor_id', request.sid)
        broadcast_threat_event(data)
        print(f"[WS] Threat from sensor {sensor_id}: {data.get('threat_type')} — {data.get('ssid')}")

    return socketio


def broadcast_threat_event(threat_data):
    """Broadcast a threat event to all connected web clients."""
    event = {
        'type': 'threat_detected',
        'timestamp': datetime.now().isoformat(),
        'severity': threat_data.get('severity', 'high'),
        'threat_type': threat_data.get('threat_type', 'rogue_ap'),
        'data': threat_data,
    }

    if redis_client:
        try:
            redis_client.lpush('threat_events', json.dumps(event))
            redis_client.ltrim('threat_events', 0, 999)
        except Exception as e:
            print(f"[Redis] Error storing threat: {e}")

    from flask import current_app
    current_app.socketio.emit('threat_event', event)


def broadcast_sensor_status(sensor_data):
    """Broadcast a sensor status update to all connected web clients."""
    event = {
        'type': 'sensor_status',
        'timestamp': datetime.now().isoformat(),
        'data': sensor_data,
    }

    if redis_client:
        try:
            sid = sensor_data.get('sensor_id', 'unknown')
            redis_client.hset(f"sensor:{sid}", mapping={'status': json.dumps(event)})
        except Exception as e:
            print(f"[Redis] Error storing sensor status: {e}")

    from flask import current_app
    current_app.socketio.emit('sensor_status', event)


def get_connected_clients_count():
    return len(connected_clients)


def get_connected_sensors():
    return dict(connected_sensors)


def get_client_subscriptions(client_id):
    if client_id in connected_clients:
        return connected_clients[client_id]['subscriptions']
    return []
