"""Socket.IO server and real-time WIPS event bridge."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from flask import current_app, request
from flask_socketio import SocketIO, emit

from .models import Sensor, SensorHealth, db
from .wips_engine import WIPSDetectionService


connected_clients: dict[str, dict[str, Any]] = {}
connected_sensors: dict[str, dict[str, Any]] = {}


def init_socketio(app):
    settings = app.extensions["zeinaguard.settings"]
    socketio = SocketIO(
        app,
        cors_allowed_origins=list(settings.cors_origins) or "*",
        ping_timeout=60,
        ping_interval=25,
        async_mode="threading",
    )
    app.extensions["zeinaguard.wips_service"] = WIPSDetectionService(settings)

    @socketio.on("connect")
    def handle_connect(data=None):
        client_id = request.sid
        connected_clients[client_id] = {
            "connected_at": datetime.utcnow().isoformat(),
            "subscriptions": [],
            "type": "web",
            "sensor_id": None,
        }
        emit(
            "connection_response",
            {
                "data": "Connected to ZeinaGuard Pro",
                "client_id": client_id,
            },
        )

    @socketio.on("disconnect")
    def handle_disconnect():
        client_id = request.sid
        metadata = connected_clients.pop(client_id, {})
        sensor_id = metadata.get("sensor_id")
        if sensor_id:
            connected_sensors.pop(sensor_id, None)
            _mark_sensor_status(sensor_id=sensor_id, hostname=metadata.get("hostname", sensor_id), status="offline")

    @socketio.on("subscribe_threats")
    def handle_subscribe_threats():
        _update_subscription("threats", subscribe=True)

    @socketio.on("unsubscribe_threats")
    def handle_unsubscribe_threats():
        _update_subscription("threats", subscribe=False)

    @socketio.on("subscribe_sensors")
    def handle_subscribe_sensors():
        _update_subscription("sensors", subscribe=True)

    @socketio.on("unsubscribe_sensors")
    def handle_unsubscribe_sensors():
        _update_subscription("sensors", subscribe=False)

    @socketio.on("sensor_register")
    def handle_sensor_register(data):
        payload = data or {}
        sensor_id = str(payload.get("sensor_id") or request.sid)
        hostname = str(payload.get("hostname") or sensor_id)

        metadata = connected_clients.setdefault(
            request.sid,
            {
                "connected_at": datetime.utcnow().isoformat(),
                "subscriptions": [],
                "type": "sensor",
                "sensor_id": sensor_id,
            },
        )
        metadata["type"] = "sensor"
        metadata["sensor_id"] = sensor_id
        metadata["hostname"] = hostname

        connected_sensors[sensor_id] = {
            "sid": request.sid,
            "hostname": hostname,
            "last_seen": datetime.utcnow().isoformat(),
        }
        _upsert_sensor(hostname=hostname, sensor_id=sensor_id, is_active=True)

        emit(
            "registration_success",
            {
                "sensor_id": sensor_id,
                "message": "Sensor registered successfully",
            },
        )
        _mark_sensor_status(sensor_id=sensor_id, hostname=hostname, status="online")

    @socketio.on("sensor_heartbeat")
    def handle_sensor_heartbeat(data):
        payload = data or {}
        sensor_id = str(payload.get("sensor_id") or request.sid)
        hostname = str(payload.get("hostname") or sensor_id)
        connected_sensors.setdefault(sensor_id, {"sid": request.sid, "hostname": hostname})
        connected_sensors[sensor_id]["last_seen"] = datetime.utcnow().isoformat()
        _record_sensor_health(hostname=hostname, status="online")

    @socketio.on("network_scan")
    def handle_network_scan(data):
        payload = data or {}
        sensor_id = str(payload.get("sensor_id") or request.sid)
        hostname = str(payload.get("hostname") or sensor_id)
        _touch_sensor(sensor_id=sensor_id, hostname=hostname)

        service: WIPSDetectionService = current_app.extensions["zeinaguard.wips_service"]
        normalized_networks, alerts = service.process_network_scan(payload)

        socketio.emit(
            "live_scan",
            {
                "sensor_id": sensor_id,
                "hostname": hostname,
                "sent_at": payload.get("sent_at") or datetime.utcnow().isoformat(),
                "networks": normalized_networks,
            },
        )
        for alert in alerts:
            broadcast_threat_event(alert)

    @socketio.on("packet_telemetry")
    def handle_packet_telemetry(data):
        payload = data or {}
        sensor_id = str(payload.get("sensor_id") or request.sid)
        hostname = str(payload.get("hostname") or sensor_id)
        _touch_sensor(sensor_id=sensor_id, hostname=hostname)

        service: WIPSDetectionService = current_app.extensions["zeinaguard.wips_service"]
        alerts = service.process_packet_batch(payload)
        for alert in alerts:
            broadcast_threat_event(alert)

        emit(
            "packet_telemetry_ack",
            {
                "received": len(payload.get("packets", [])),
                "sensor_id": sensor_id,
                "hostname": hostname,
            },
        )

    @socketio.on("new_threat")
    def handle_new_threat(data):
        payload = data or {}
        sensor_id = str(payload.get("sensor_id") or request.sid)
        hostname = str(payload.get("hostname") or sensor_id)
        _touch_sensor(sensor_id=sensor_id, hostname=hostname)

        service: WIPSDetectionService = current_app.extensions["zeinaguard.wips_service"]
        for alert in service.ingest_external_threat(payload):
            broadcast_threat_event(alert)

    return socketio


def broadcast_threat_event(threat_data):
    event = threat_data if threat_data.get("type") == "threat_detected" else _wrap_legacy_threat(threat_data)
    _persist_realtime_event(event)
    current_app.socketio.emit("threat_event", event)


def broadcast_sensor_status(sensor_data):
    event = {
        "type": "sensor_status",
        "timestamp": datetime.utcnow().isoformat(),
        "data": sensor_data,
    }
    _persist_realtime_event(event, bucket="sensor_events")
    current_app.socketio.emit("sensor_status", event)


def get_connected_clients_count():
    return len(connected_clients)


def get_connected_sensors():
    return dict(connected_sensors)


def get_client_subscriptions(client_id):
    if client_id in connected_clients:
        return connected_clients[client_id]["subscriptions"]
    return []


def _update_subscription(channel: str, subscribe: bool) -> None:
    client = connected_clients.get(request.sid)
    if client is None:
        return

    subscriptions = client["subscriptions"]
    if subscribe and channel not in subscriptions:
        subscriptions.append(channel)
    elif not subscribe and channel in subscriptions:
        subscriptions.remove(channel)

    emit("subscription_response", {"channel": channel, "subscribed": subscribe})


def _touch_sensor(sensor_id: str, hostname: str) -> None:
    connected_sensors.setdefault(sensor_id, {"sid": request.sid, "hostname": hostname})
    now = datetime.utcnow()
    connected_sensors[sensor_id]["last_seen"] = now.isoformat()

    last_db_heartbeat = connected_sensors[sensor_id].get("last_db_heartbeat")
    should_persist = last_db_heartbeat is None
    if isinstance(last_db_heartbeat, datetime):
        should_persist = (now - last_db_heartbeat).total_seconds() >= 60

    if should_persist:
        connected_sensors[sensor_id]["last_db_heartbeat"] = now
        _record_sensor_health(hostname=hostname, status="online")
        db.session.commit()


def _upsert_sensor(hostname: str, sensor_id: str, is_active: bool) -> Sensor:
    sensor = Sensor.query.filter_by(hostname=hostname).first()
    if sensor is None:
        sensor = Sensor(
            name=f"Sensor {hostname}",
            hostname=hostname,
            is_active=is_active,
        )
        db.session.add(sensor)
        db.session.flush()
    else:
        sensor.is_active = is_active

    _record_sensor_health(hostname=hostname, status="online" if is_active else "offline")
    db.session.commit()
    return sensor


def _record_sensor_health(hostname: str, status: str) -> None:
    sensor = Sensor.query.filter_by(hostname=hostname).first()
    if sensor is None:
        return

    db.session.add(
        SensorHealth(
            sensor_id=sensor.id,
            status=status,
            last_heartbeat=datetime.utcnow(),
            created_at=datetime.utcnow(),
        )
    )


def _mark_sensor_status(sensor_id: str, hostname: str, status: str) -> None:
    try:
        sensor = _upsert_sensor(hostname=hostname, sensor_id=sensor_id, is_active=status != "offline")
    except Exception:
        db.session.rollback()
        sensor = None

    broadcast_sensor_status(
        {
            "sensor_id": sensor_id,
            "hostname": hostname,
            "status": status,
            "last_heartbeat": datetime.utcnow().isoformat(),
            "detected_by": sensor.id if sensor else None,
        }
    )


def _wrap_legacy_threat(payload: dict[str, Any]) -> dict[str, Any]:
    timestamp = payload.get("timestamp") or datetime.utcnow().isoformat()
    return {
        "type": "threat_detected",
        "timestamp": timestamp,
        "classification": payload.get("classification", "ATTACK"),
        "severity": payload.get("severity", "high"),
        "threat_type": payload.get("threat_type", "rogue_access_point"),
        "title": payload.get("title", "Threat detected"),
        "message": payload.get("description") or payload.get("message") or "Threat detected",
        "data": payload,
    }


def _persist_realtime_event(event: dict[str, Any], bucket: str = "threat_events") -> None:
    settings = current_app.extensions["zeinaguard.settings"]
    if not settings.redis_url:
        return

    try:
        from redis import Redis

        redis_client = Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
        )
        redis_client.lpush(bucket, json.dumps(event))
        redis_client.ltrim(bucket, 0, 999)
    except Exception:
        current_app.logger.warning("Redis persistence unavailable for realtime events")
