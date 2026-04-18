from __future__ import annotations

import socket
import threading
import time
from datetime import datetime
from queue import Empty

import socketio

from sensor.communication.api_client import APIClient
from sensor.config import BACKEND_URL, SENSOR_ID, settings
from sensor.core.event_bus import dashboard_queue, scan_queue, telemetry_queue
from sensor.local_data_logger import LocalDataLogger
from sensor.ui.terminal_ui import mark_sent, update_status


class WSClient:
    def __init__(self, backend_url=None, token=None, sensor_id=None, api_client: APIClient | None = None):
        self.backend_url = (backend_url or BACKEND_URL).rstrip("/")
        self.hostname = socket.gethostname()
        self.sensor_id = sensor_id or SENSOR_ID
        self.started_at = time.time()
        self.is_running = False
        self.emit_lock = threading.Lock()
        self.last_sent_cache: dict[str, dict[str, object]] = {}
        self.scan_buffer: list[dict[str, object]] = []
        self.packet_buffer: list[dict[str, object]] = []

        self.token = token
        self.api_client = api_client or APIClient(self.backend_url)
        if self.token:
            self.api_client.token = self.token

        self.local_logger = LocalDataLogger()
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=0,
            reconnection_delay=2,
            reconnection_delay_max=10,
            logger=False,
            engineio_logger=False,
        )
        self._register_handlers()

    def _register_handlers(self):
        @self.sio.event
        def connect():
            update_status(backend_status="connected", message=f"Connected to {self.backend_url}")
            self.sio.emit(
                "sensor_register",
                {
                    "sensor_id": self.sensor_id,
                    "hostname": self.hostname,
                },
            )

        @self.sio.event
        def disconnect():
            update_status(backend_status="disconnected", message="Backend connection lost")

        @self.sio.event
        def connect_error(_data):
            update_status(backend_status="offline", message="Backend connection failed")

        @self.sio.on("registration_success")
        def registration_success(_data):
            update_status(backend_status="registered", message="Sensor registered with backend")

    def start(self):
        self.is_running = True
        threading.Thread(target=self._scan_listener, daemon=True, name="WSScanListener").start()
        threading.Thread(target=self._packet_listener, daemon=True, name="WSPacketListener").start()
        threading.Thread(target=self._threat_listener, daemon=True, name="WSThreatListener").start()
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="WSHeartbeat").start()

        backoff_seconds = 2
        while self.is_running:
            if self.sio.connected:
                time.sleep(1)
                continue

            token = self._ensure_token()
            if not token:
                update_status(backend_status="offline", message="Backend unavailable; retrying authentication")
                time.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2, 30)
                continue

            try:
                update_status(backend_status="connecting", message=f"Connecting to {self.backend_url}")
                self.sio.connect(
                    self.backend_url,
                    headers={"Authorization": f"Bearer {token}"},
                    transports=["websocket", "polling"],
                    wait=True,
                )
                backoff_seconds = 2
                self.sio.wait()
            except Exception:
                self.token = None
                update_status(backend_status="offline", message="Retrying backend connection")
                time.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2, 30)

    def _ensure_token(self) -> str | None:
        if self.token:
            return self.token

        self.token = self.api_client.authenticate_sensor()
        return self.token

    def _heartbeat_loop(self) -> None:
        while self.is_running:
            if self.sio.connected:
                try:
                    self.sio.emit(
                        "sensor_heartbeat",
                        {
                            "sensor_id": self.sensor_id,
                            "hostname": self.hostname,
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
                except Exception:
                    update_status(backend_status="degraded", message="Heartbeat send failed")
            time.sleep(15)

    def _threat_listener(self) -> None:
        while self.is_running:
            try:
                threat = dashboard_queue.get(timeout=0.5)
            except Empty:
                continue

            if not threat or threat.get("type") == "REMOVED":
                continue

            event = threat.get("event", {})
            payload = {
                "threat_type": threat.get("status"),
                "classification": "ATTACK" if threat.get("status") == "ROGUE" else "SUSPICIOUS",
                "ssid": event.get("ssid"),
                "source_mac": event.get("bssid"),
                "signal_strength": event.get("signal"),
                "severity": "high",
                "score": threat.get("score", 0),
                "reasons": threat.get("reasons", []),
                "sensor_id": self.sensor_id,
                "hostname": self.hostname,
                "description": f"Sensor-side rogue AP heuristic fired for {event.get('ssid')}",
            }
            self._emit("new_threat", payload)

    def _scan_listener(self) -> None:
        next_flush_deadline = time.monotonic() + settings.scan_emit_interval_seconds
        while self.is_running:
            try:
                timeout = max(0.1, next_flush_deadline - time.monotonic())
                scan = scan_queue.get(timeout=timeout)
            except Empty:
                scan = None

            if scan is not None:
                if not self._should_process_scan(scan):
                    continue
                payload = self._build_scan_payload(scan)
                self.local_logger.log_scan(payload)
                self.scan_buffer.append(payload)
                self._update_last_sent_cache(payload)

            should_flush = (
                len(self.scan_buffer) >= settings.scan_emit_batch_size
                or (self.scan_buffer and time.monotonic() >= next_flush_deadline)
            )
            if should_flush and self.sio.connected:
                sent = self._emit("network_scan", self._build_scan_batch_payload(self.scan_buffer))
                if sent:
                    self._mark_scan_batch_sent(self.scan_buffer)
                    self.scan_buffer = []
                    next_flush_deadline = time.monotonic() + settings.scan_emit_interval_seconds

    def _packet_listener(self) -> None:
        next_flush_deadline = time.monotonic() + settings.packet_emit_interval_seconds
        while self.is_running:
            try:
                timeout = max(0.1, next_flush_deadline - time.monotonic())
                packet_event = telemetry_queue.get(timeout=timeout)
            except Empty:
                packet_event = None

            if packet_event is not None:
                self.packet_buffer.append(packet_event)

            should_flush = (
                len(self.packet_buffer) >= settings.packet_emit_batch_size
                or (self.packet_buffer and time.monotonic() >= next_flush_deadline)
            )
            if should_flush and self.sio.connected:
                sent = self._emit(
                    "packet_telemetry",
                    {
                        "sensor_id": self.sensor_id,
                        "hostname": self.hostname,
                        "sent_at": datetime.utcnow().isoformat(),
                        "packets": list(self.packet_buffer),
                    },
                )
                if sent:
                    self.packet_buffer = []
                    next_flush_deadline = time.monotonic() + settings.packet_emit_interval_seconds

    def _emit(self, event_name: str, payload: dict[str, object]) -> bool:
        if not self.sio.connected:
            return False

        try:
            with self.emit_lock:
                self.sio.emit(event_name, payload)
            return True
        except Exception:
            update_status(backend_status="degraded", message=f"{event_name} send failed")
            return False

    def _should_process_scan(self, scan):
        bssid = str(scan.get("bssid") or "").strip().upper()
        if not bssid:
            return False
        now = time.time()
        cached = self.last_sent_cache.get(bssid)
        if cached is None:
            return True
        if self._signal_changed(cached.get("signal"), scan.get("signal")):
            return True
        if cached.get("classification") != scan.get("classification", "UNKNOWN"):
            return True
        return (now - float(cached.get("last_sent", 0))) > settings.scan_dedup_max_age_seconds

    def _signal_changed(self, previous, current):
        if previous is None or current is None:
            return previous != current
        try:
            return abs(int(current) - int(previous)) >= settings.scan_dedup_signal_delta
        except (TypeError, ValueError):
            return previous != current

    def _update_last_sent_cache(self, payload):
        bssid = str(payload.get("bssid") or "").strip().upper()
        if bssid:
            self.last_sent_cache[bssid] = {
                "signal": payload.get("signal"),
                "classification": payload.get("classification", "UNKNOWN"),
                "last_sent": time.time(),
            }

    def _build_scan_batch_payload(self, batch):
        return {
            "sensor_id": self.sensor_id,
            "hostname": self.hostname,
            "sent_at": datetime.utcnow().isoformat(),
            "networks": [
                {key: value for key, value in scan.items() if key not in {"sensor_id", "hostname"}}
                for scan in batch
            ],
        }

    def _mark_scan_batch_sent(self, batch):
        sample = batch[0]
        mark_sent({"ssid": sample.get("ssid"), "bssid": sample.get("bssid"), "batch_size": len(batch)})

    def _build_scan_payload(self, scan):
        return {
            "sensor_id": self.sensor_id,
            "hostname": self.hostname,
            "timestamp": scan.get("timestamp") or datetime.utcnow().isoformat(),
            "ssid": scan.get("ssid"),
            "bssid": scan.get("bssid"),
            "channel": scan.get("channel"),
            "signal": scan.get("signal"),
            "encryption": scan.get("encryption"),
            "manufacturer": scan.get("manufacturer", "Unknown"),
            "clients": scan.get("clients", 0),
            "classification": scan.get("classification", "UNKNOWN"),
            "score": scan.get("score", 0),
            "auth": scan.get("auth"),
            "wps": scan.get("wps"),
            "distance": scan.get("distance"),
            "raw_beacon": scan.get("raw_beacon"),
            "uptime": self._format_uptime(),
            "uptime_seconds": int(time.time() - self.started_at),
        }

    def _format_uptime(self):
        seconds = max(int(time.time() - self.started_at), 0)
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, _ = divmod(seconds, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes or not parts:
            parts.append(f"{minutes}m")
        return " ".join(parts)
