from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from flask import current_app

from .config import BackendSettings


CLASSIFICATION_NORMAL = "NORMAL"
CLASSIFICATION_SUSPICIOUS = "SUSPICIOUS"
CLASSIFICATION_ATTACK = "ATTACK"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_mac(value: str | None) -> str:
    if not value:
        return ""
    sanitized = str(value).strip().upper().replace("-", ":")
    parts = [part.zfill(2) for part in sanitized.split(":") if part]
    if len(parts) != 6:
        return sanitized
    return ":".join(parts)


def _trim_window(values: deque[datetime], now: datetime, window_seconds: int) -> None:
    while values and (now - values[0]).total_seconds() > window_seconds:
        values.popleft()


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return _utcnow()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return _utcnow()


def _is_locally_administered(mac_address: str) -> bool:
    normalized = _normalize_mac(mac_address)
    if len(normalized) < 2:
        return False
    try:
        first_octet = int(normalized[:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0b10)


def _is_invalid_source_mac(mac_address: str) -> bool:
    normalized = _normalize_mac(mac_address)
    return normalized in {"", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


def _map_severity(threat_type: str, classification: str) -> str:
    if classification == CLASSIFICATION_ATTACK:
        if threat_type == "deauthentication_attack":
            return "critical"
        if threat_type in {"rogue_access_point", "probe_request_flood"}:
            return "high"
        return "medium"
    if classification == CLASSIFICATION_SUSPICIOUS:
        return "medium"
    return "info"


def _classification_rank(value: str) -> int:
    return {
        CLASSIFICATION_NORMAL: 0,
        CLASSIFICATION_SUSPICIOUS: 1,
        CLASSIFICATION_ATTACK: 2,
    }.get(value, 0)


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class DetectionAlert:
    threat_type: str
    classification: str
    severity: str
    title: str
    message: str
    timestamp: datetime
    sensor_id: str
    hostname: str
    source_mac: str | None = None
    target_mac: str | None = None
    bssid: str | None = None
    ssid: str | None = None
    packet_count: int | None = None
    signal_strength: int | None = None
    dedupe_key: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class WIPSDetectionEngine:
    def __init__(self, settings: BackendSettings):
        self.settings = settings
        self.deauth_windows: dict[str, deque[datetime]] = defaultdict(deque)
        self.probe_windows: dict[str, deque[datetime]] = defaultdict(deque)
        self.mac_activity: dict[str, dict[str, Any]] = {}
        self.alert_cooldowns: dict[str, datetime] = {}

    def process_network(self, network: dict[str, Any], sensor_context: dict[str, str]) -> tuple[dict[str, Any], list[DetectionAlert]]:
        annotated = dict(network)
        alerts: list[DetectionAlert] = []

        ssid = str(network.get("ssid") or "Hidden")
        bssid = _normalize_mac(network.get("bssid"))
        channel = network.get("channel")
        encryption = str(network.get("encryption") or network.get("auth") or "UNKNOWN").upper()
        reasons: list[str] = []
        classification = CLASSIFICATION_NORMAL

        trusted = self.settings.trusted_aps.get(ssid)
        if trusted:
            trusted_bssids = {_normalize_mac(item) for item in trusted.get("bssids", []) if item}
            trusted_channels = {int(item) for item in trusted.get("channels", []) if str(item).isdigit()}
            trusted_encryption = str(trusted.get("encryption") or "UNKNOWN").upper()

            if trusted_bssids and bssid and bssid not in trusted_bssids:
                classification = CLASSIFICATION_ATTACK
                reasons.append("Untrusted BSSID advertising a trusted SSID")

            if trusted_channels and channel is not None and int(channel) not in trusted_channels:
                classification = max(classification, CLASSIFICATION_SUSPICIOUS, key=_classification_rank)
                reasons.append("Trusted SSID observed on an unexpected channel")

            if trusted_encryption not in {"", "UNKNOWN"} and encryption != trusted_encryption:
                classification = CLASSIFICATION_ATTACK
                reasons.append(f"Security downgrade detected ({trusted_encryption} -> {encryption})")

        if trusted and _is_locally_administered(bssid):
            classification = CLASSIFICATION_ATTACK
            reasons.append("Locally administered BSSID advertising a trusted SSID")

        annotated["classification"] = classification
        annotated["reasons"] = reasons
        annotated["sensor_id"] = sensor_context["sensor_id"]
        annotated["hostname"] = sensor_context["hostname"]

        if classification != CLASSIFICATION_NORMAL:
            alert = self._build_alert(
                threat_type="rogue_access_point",
                classification=classification,
                title="Rogue access point detected" if classification == CLASSIFICATION_ATTACK else "Suspicious access point detected",
                message=f"{ssid} ({bssid or 'unknown'}) triggered rogue AP checks: {', '.join(reasons)}",
                timestamp=_parse_timestamp(network.get("timestamp")),
                sensor_context=sensor_context,
                source_mac=bssid or None,
                bssid=bssid or None,
                ssid=ssid,
                signal_strength=_safe_int(network.get("signal")),
                packet_count=1,
                metadata={
                    "channel": channel,
                    "encryption": encryption,
                    "reasons": reasons,
                    "network": annotated,
                },
                dedupe_key=f"rogue_ap:{ssid}:{bssid}:{classification}",
            )
            if self._should_emit(alert.dedupe_key, alert.timestamp):
                alerts.append(alert)

        return annotated, alerts

    def process_packet(self, packet: dict[str, Any], sensor_context: dict[str, str]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        timestamp = _parse_timestamp(packet.get("timestamp"))
        source_mac = _normalize_mac(packet.get("source_mac"))
        target_mac = _normalize_mac(packet.get("dest_mac") or packet.get("target_mac"))
        bssid = _normalize_mac(packet.get("bssid"))
        frame_subtype = str(packet.get("frame_subtype") or "").lower()
        signal_strength = _safe_int(packet.get("signal"))
        ssid = str(packet.get("ssid") or "Hidden")

        self._update_mac_activity(packet, timestamp, source_mac, bssid, ssid)

        if frame_subtype in {"deauth", "disassoc"}:
            alert = self._check_deauth_window(
                packet=packet,
                sensor_context=sensor_context,
                timestamp=timestamp,
                source_mac=source_mac,
                target_mac=target_mac,
                bssid=bssid,
                ssid=ssid,
                signal_strength=signal_strength,
            )
            if alert is not None:
                alerts.append(alert)

        if frame_subtype == "probe_request":
            alert = self._check_probe_flood(
                packet=packet,
                sensor_context=sensor_context,
                timestamp=timestamp,
                source_mac=source_mac,
                signal_strength=signal_strength,
            )
            if alert is not None:
                alerts.append(alert)

        mac_alert = self._check_abnormal_mac_behavior(
            packet=packet,
            sensor_context=sensor_context,
            timestamp=timestamp,
            source_mac=source_mac,
            signal_strength=signal_strength,
            ssid=ssid,
        )
        if mac_alert is not None:
            alerts.append(mac_alert)

        return alerts

    def _build_alert(
        self,
        threat_type: str,
        classification: str,
        title: str,
        message: str,
        timestamp: datetime,
        sensor_context: dict[str, str],
        source_mac: str | None = None,
        target_mac: str | None = None,
        bssid: str | None = None,
        ssid: str | None = None,
        packet_count: int | None = None,
        signal_strength: int | None = None,
        metadata: dict[str, Any] | None = None,
        dedupe_key: str = "",
    ) -> DetectionAlert:
        return DetectionAlert(
            threat_type=threat_type,
            classification=classification,
            severity=_map_severity(threat_type, classification),
            title=title,
            message=message,
            timestamp=timestamp,
            sensor_id=sensor_context["sensor_id"],
            hostname=sensor_context["hostname"],
            source_mac=source_mac,
            target_mac=target_mac,
            bssid=bssid,
            ssid=ssid,
            packet_count=packet_count,
            signal_strength=signal_strength,
            metadata=metadata or {},
            dedupe_key=dedupe_key,
        )

    def _should_emit(self, dedupe_key: str, now: datetime) -> bool:
        last_emitted = self.alert_cooldowns.get(dedupe_key)
        if last_emitted is None or (now - last_emitted).total_seconds() >= self.settings.alert_cooldown_seconds:
            self.alert_cooldowns[dedupe_key] = now
            return True
        return False

    def _check_deauth_window(
        self,
        packet: dict[str, Any],
        sensor_context: dict[str, str],
        timestamp: datetime,
        source_mac: str,
        target_mac: str,
        bssid: str,
        ssid: str,
        signal_strength: int | None,
    ) -> DetectionAlert | None:
        key = f"{source_mac}:{target_mac}:{bssid}"
        window = self.deauth_windows[key]
        window.append(timestamp)
        _trim_window(window, timestamp, self.settings.deauth_window_seconds)
        count = len(window)

        classification = CLASSIFICATION_NORMAL
        if count >= self.settings.deauth_attack_threshold:
            classification = CLASSIFICATION_ATTACK
        elif count >= self.settings.deauth_suspicious_threshold:
            classification = CLASSIFICATION_SUSPICIOUS

        if classification == CLASSIFICATION_NORMAL:
            return None

        dedupe_key = f"deauth:{key}:{classification}"
        if not self._should_emit(dedupe_key, timestamp):
            return None

        return self._build_alert(
            threat_type="deauthentication_attack",
            classification=classification,
            title="Deauthentication attack detected" if classification == CLASSIFICATION_ATTACK else "Suspicious deauthentication activity",
            message=(
                f"Observed {count} {packet.get('frame_subtype', 'deauth')} frames "
                f"from {source_mac or 'unknown'} targeting {target_mac or 'broadcast'} "
                f"on {bssid or 'unknown BSSID'} within {self.settings.deauth_window_seconds}s"
            ),
            timestamp=timestamp,
            sensor_context=sensor_context,
            source_mac=source_mac or None,
            target_mac=target_mac or None,
            bssid=bssid or None,
            ssid=ssid,
            packet_count=count,
            signal_strength=signal_strength,
            metadata={
                "window_seconds": self.settings.deauth_window_seconds,
                "frame_subtype": packet.get("frame_subtype"),
                "reason_code": packet.get("reason_code"),
            },
            dedupe_key=dedupe_key,
        )

    def _check_probe_flood(
        self,
        packet: dict[str, Any],
        sensor_context: dict[str, str],
        timestamp: datetime,
        source_mac: str,
        signal_strength: int | None,
    ) -> DetectionAlert | None:
        if not source_mac:
            return None

        window = self.probe_windows[source_mac]
        window.append(timestamp)
        _trim_window(window, timestamp, self.settings.probe_window_seconds)
        count = len(window)

        classification = CLASSIFICATION_NORMAL
        if count >= self.settings.probe_attack_threshold:
            classification = CLASSIFICATION_ATTACK
        elif count >= self.settings.probe_suspicious_threshold:
            classification = CLASSIFICATION_SUSPICIOUS

        if classification == CLASSIFICATION_NORMAL:
            return None

        dedupe_key = f"probe_flood:{source_mac}:{classification}"
        if not self._should_emit(dedupe_key, timestamp):
            return None

        return self._build_alert(
            threat_type="probe_request_flood",
            classification=classification,
            title="Probe request flood detected" if classification == CLASSIFICATION_ATTACK else "Probe request spike detected",
            message=f"Observed {count} probe requests from {source_mac} within {self.settings.probe_window_seconds}s",
            timestamp=timestamp,
            sensor_context=sensor_context,
            source_mac=source_mac,
            ssid=str(packet.get("ssid") or "Hidden"),
            packet_count=count,
            signal_strength=signal_strength,
            metadata={"window_seconds": self.settings.probe_window_seconds},
            dedupe_key=dedupe_key,
        )

    def _update_mac_activity(
        self,
        packet: dict[str, Any],
        timestamp: datetime,
        source_mac: str,
        bssid: str,
        ssid: str,
    ) -> None:
        if not source_mac:
            return

        profile = self.mac_activity.setdefault(
            source_mac,
            {
                "events": deque(),
                "roles": set(),
                "ssids": set(),
                "bssids": set(),
            },
        )

        events: deque[datetime] = profile["events"]
        events.append(timestamp)
        _trim_window(events, timestamp, self.settings.abnormal_mac_window_seconds)

        frame_subtype = str(packet.get("frame_subtype") or "").lower()
        frame_type = str(packet.get("frame_type") or "").lower()

        if frame_subtype in {"beacon", "probe_response"}:
            profile["roles"].add("ap")
        elif frame_subtype in {"probe_request", "association_request", "reassociation_request"} or frame_type == "data":
            profile["roles"].add("client")

        if ssid and ssid != "Hidden":
            profile["ssids"].add(ssid)
        if bssid:
            profile["bssids"].add(bssid)

    def _check_abnormal_mac_behavior(
        self,
        packet: dict[str, Any],
        sensor_context: dict[str, str],
        timestamp: datetime,
        source_mac: str,
        signal_strength: int | None,
        ssid: str,
    ) -> DetectionAlert | None:
        if _is_invalid_source_mac(source_mac):
            dedupe_key = f"abnormal_mac:invalid:{source_mac or 'empty'}"
            if not self._should_emit(dedupe_key, timestamp):
                return None

            return self._build_alert(
                threat_type="abnormal_mac_behavior",
                classification=CLASSIFICATION_ATTACK,
                title="Invalid MAC behavior detected",
                message="A frame was received with an invalid or broadcast source MAC address",
                timestamp=timestamp,
                sensor_context=sensor_context,
                source_mac=source_mac or None,
                signal_strength=signal_strength,
                metadata={"frame_subtype": packet.get("frame_subtype")},
                dedupe_key=dedupe_key,
            )

        profile = self.mac_activity.get(source_mac)
        if not profile:
            return None

        event_count = len(profile["events"])
        unique_bssids = len(profile["bssids"])
        unique_ssids = len(profile["ssids"])
        roles = profile["roles"]

        classification = CLASSIFICATION_NORMAL
        reasons: list[str] = []

        if _is_locally_administered(source_mac) and unique_ssids >= self.settings.abnormal_mac_ssid_threshold:
            classification = CLASSIFICATION_SUSPICIOUS
            reasons.append("Locally administered MAC is cycling through many SSIDs")

        if unique_bssids >= self.settings.abnormal_mac_bssid_threshold:
            classification = CLASSIFICATION_ATTACK
            reasons.append("MAC address observed across too many BSSIDs in a short window")

        if len(roles) > 1 and event_count >= 20:
            classification = max(classification, CLASSIFICATION_SUSPICIOUS, key=_classification_rank)
            reasons.append("MAC address is switching between access-point and client behavior")

        if classification == CLASSIFICATION_NORMAL:
            return None

        dedupe_key = f"abnormal_mac:{source_mac}:{classification}"
        if not self._should_emit(dedupe_key, timestamp):
            return None

        return self._build_alert(
            threat_type="abnormal_mac_behavior",
            classification=classification,
            title="Abnormal MAC behavior detected",
            message=f"{source_mac} triggered MAC anomaly checks: {', '.join(reasons)}",
            timestamp=timestamp,
            sensor_context=sensor_context,
            source_mac=source_mac,
            ssid=ssid,
            packet_count=event_count,
            signal_strength=signal_strength,
            metadata={
                "roles": sorted(roles),
                "unique_bssids": unique_bssids,
                "unique_ssids": unique_ssids,
                "window_seconds": self.settings.abnormal_mac_window_seconds,
                "reasons": reasons,
            },
            dedupe_key=dedupe_key,
        )


class WIPSDetectionService:
    def __init__(self, settings: BackendSettings):
        self.settings = settings
        self.engine = WIPSDetectionEngine(settings)

    def process_network_scan(self, payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        sensor_context = self._sensor_context(payload)
        normalized_networks: list[dict[str, Any]] = []
        pending_alerts: list[DetectionAlert] = []

        for network in payload.get("networks", []):
            if not isinstance(network, dict):
                continue
            annotated, alerts = self.engine.process_network(network, sensor_context)
            normalized_networks.append(annotated)
            pending_alerts.extend(alerts)

        return normalized_networks, self._persist_alerts(pending_alerts)

    def process_packet_batch(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        sensor_context = self._sensor_context(payload)
        pending_alerts: list[DetectionAlert] = []

        for packet in payload.get("packets", []):
            if not isinstance(packet, dict):
                continue
            pending_alerts.extend(self.engine.process_packet(packet, sensor_context))

        return self._persist_alerts(pending_alerts)

    def ingest_external_threat(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        sensor_context = self._sensor_context(payload)
        timestamp = _parse_timestamp(payload.get("timestamp"))
        classification = str(payload.get("classification") or CLASSIFICATION_ATTACK).upper()

        alert = self.engine._build_alert(
            threat_type=str(payload.get("threat_type") or "rogue_access_point"),
            classification=classification,
            title=str(payload.get("title") or "Sensor-reported wireless threat"),
            message=str(payload.get("description") or payload.get("message") or "Sensor reported a wireless threat"),
            timestamp=timestamp,
            sensor_context=sensor_context,
            source_mac=_normalize_mac(payload.get("source_mac")) or None,
            target_mac=_normalize_mac(payload.get("target_mac")) or None,
            bssid=_normalize_mac(payload.get("source_mac")) or None,
            ssid=str(payload.get("ssid") or "Hidden"),
            packet_count=_safe_int(payload.get("packet_count") or payload.get("score")),
            signal_strength=_safe_int(payload.get("signal") or payload.get("signal_strength")),
            metadata=dict(payload),
            dedupe_key=f"external:{payload.get('threat_type')}:{payload.get('source_mac')}:{classification}",
        )
        if not self.engine._should_emit(alert.dedupe_key, alert.timestamp):
            return []

        return self._persist_alerts([alert])

    def _persist_alerts(self, alerts: list[DetectionAlert]) -> list[dict[str, Any]]:
        if not alerts:
            return []

        from .models import Alert, Threat, ThreatEvent, db

        persisted_events: list[dict[str, Any]] = []
        try:
            for alert in alerts:
                sensor = self._get_sensor_record(alert.hostname)
                sensor_db_id = sensor.id if sensor else None

                threat = Threat(
                    threat_type=alert.threat_type,
                    severity=alert.severity,
                    source_mac=alert.source_mac,
                    target_mac=alert.target_mac,
                    ssid=alert.ssid,
                    detected_by=sensor_db_id,
                    description=alert.message,
                    is_resolved=False,
                    created_at=alert.timestamp.replace(tzinfo=None),
                    updated_at=alert.timestamp.replace(tzinfo=None),
                )
                db.session.add(threat)
                db.session.flush()

                event_data = dict(alert.metadata)
                event_data.update(
                    {
                        "classification": alert.classification,
                        "title": alert.title,
                        "hostname": alert.hostname,
                        "sensor_id": alert.sensor_id,
                        "bssid": alert.bssid,
                    }
                )

                db.session.add(
                    ThreatEvent(
                        threat_id=threat.id,
                        sensor_id=sensor_db_id,
                        time=alert.timestamp.replace(tzinfo=None),
                        event_data=event_data,
                        packet_count=alert.packet_count,
                        signal_strength=alert.signal_strength,
                    )
                )
                db.session.add(
                    Alert(
                        threat_id=threat.id,
                        message=alert.message,
                        is_read=False,
                        is_acknowledged=False,
                        created_at=alert.timestamp.replace(tzinfo=None),
                    )
                )

                persisted_events.append(
                    {
                        "type": "threat_detected",
                        "timestamp": alert.timestamp.isoformat(),
                        "classification": alert.classification,
                        "severity": alert.severity,
                        "threat_type": alert.threat_type,
                        "title": alert.title,
                        "message": alert.message,
                        "data": {
                            "id": threat.id,
                            "threat_type": alert.threat_type,
                            "severity": alert.severity,
                            "classification": alert.classification,
                            "source_mac": alert.source_mac,
                            "target_mac": alert.target_mac,
                            "ssid": alert.ssid,
                            "bssid": alert.bssid,
                            "detected_by": sensor_db_id,
                            "detected_by_sensor": alert.hostname,
                            "sensor_identifier": alert.sensor_id,
                            "description": alert.message,
                            "signal_strength": alert.signal_strength,
                            "packet_count": alert.packet_count or 1,
                            "is_resolved": False,
                            "created_at": alert.timestamp.isoformat(),
                            "metadata": event_data,
                        },
                    }
                )

            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            current_app.logger.exception("Failed to persist detection alerts: %s", exc)
            for alert in alerts:
                persisted_events.append(
                    {
                        "type": "threat_detected",
                        "timestamp": alert.timestamp.isoformat(),
                        "classification": alert.classification,
                        "severity": alert.severity,
                        "threat_type": alert.threat_type,
                        "title": alert.title,
                        "message": alert.message,
                        "data": {
                            "id": None,
                            "threat_type": alert.threat_type,
                            "severity": alert.severity,
                            "classification": alert.classification,
                            "source_mac": alert.source_mac,
                            "target_mac": alert.target_mac,
                            "ssid": alert.ssid,
                            "bssid": alert.bssid,
                            "detected_by": None,
                            "detected_by_sensor": alert.hostname,
                            "sensor_identifier": alert.sensor_id,
                            "description": alert.message,
                            "signal_strength": alert.signal_strength,
                            "packet_count": alert.packet_count or 1,
                            "is_resolved": False,
                            "created_at": alert.timestamp.isoformat(),
                            "metadata": alert.metadata,
                        },
                    }
                )

        return persisted_events

    def _sensor_context(self, payload: dict[str, Any]) -> dict[str, str]:
        return {
            "sensor_id": str(payload.get("sensor_id") or payload.get("hostname") or "unknown-sensor"),
            "hostname": str(payload.get("hostname") or payload.get("sensor_id") or "unknown-host"),
        }

    def _get_sensor_record(self, hostname: str):
        from .models import Sensor, db

        sensor = Sensor.query.filter_by(hostname=hostname).first()
        if sensor is None:
            sensor = Sensor(
                name=f"Sensor {hostname}",
                hostname=hostname,
                is_active=True,
            )
            db.session.add(sensor)
            db.session.flush()
        else:
            sensor.is_active = True
        return sensor
