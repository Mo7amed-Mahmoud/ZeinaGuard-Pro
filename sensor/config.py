from __future__ import annotations

import json
import os
import socket as socket_lib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
SENSOR_DIR = BASE_DIR / "sensor"


def _load_env_files() -> None:
    for env_path in (BASE_DIR / ".env", SENSOR_DIR / ".env"):
        if env_path.exists():
            load_dotenv(env_path, override=False)


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _parse_float(value: str | None, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _load_trusted_aps() -> dict[str, dict[str, Any]]:
    inline_json = os.getenv("SENSOR_TRUSTED_APS_JSON")
    file_path = os.getenv("SENSOR_TRUSTED_APS_FILE")

    if inline_json:
        try:
            return json.loads(inline_json)
        except json.JSONDecodeError:
            print("[SensorConfig] Ignoring invalid SENSOR_TRUSTED_APS_JSON payload")

    if file_path:
        path = Path(file_path)
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as handle:
                    return json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"[SensorConfig] Could not load trusted AP file {path}: {exc}")

    return {}


def get_wireless_interface() -> str:
    try:
        interfaces = os.listdir("/sys/class/net/")
        for iface in interfaces:
            if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                return iface
    except Exception:
        pass
    return "wlan0mon"


@dataclass(slots=True)
class SensorSettings:
    interface: str = field(default_factory=get_wireless_interface)
    backend_url: str = "http://localhost:8000"
    sensor_username: str = "admin"
    sensor_password: str = "admin123"
    sensor_id: str = field(default_factory=socket_lib.gethostname)
    locked_channel: int | None = None
    trusted_aps: dict[str, dict[str, Any]] = field(default_factory=dict)
    enable_active_containment: bool = False
    deauth_count: int = 40
    deauth_interval: float = 0.1
    scan_emit_batch_size: int = 25
    scan_emit_interval_seconds: float = 3.0
    packet_emit_batch_size: int = 100
    packet_emit_interval_seconds: float = 2.0
    scan_dedup_signal_delta: int = 5
    scan_dedup_max_age_seconds: float = 30.0
    raw_packet_queue_size: int = 2000
    parsed_packet_queue_size: int = 2000


def load_settings() -> SensorSettings:
    _load_env_files()
    return SensorSettings(
        interface=os.getenv("SENSOR_INTERFACE", get_wireless_interface()),
        backend_url=os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/"),
        sensor_username=os.getenv("SENSOR_USER", "admin"),
        sensor_password=os.getenv("SENSOR_PASSWORD", "admin123"),
        sensor_id=os.getenv("ZEINAGUARD_SENSOR_ID", socket_lib.gethostname()),
        trusted_aps=_load_trusted_aps(),
        enable_active_containment=_parse_bool(os.getenv("ENABLE_CONTAINMENT"), default=False),
        deauth_count=_parse_int(os.getenv("DEAUTH_COUNT"), 40),
        deauth_interval=_parse_float(os.getenv("DEAUTH_INTERVAL"), 0.1),
        scan_emit_batch_size=_parse_int(os.getenv("SCAN_EMIT_BATCH_SIZE"), 25),
        scan_emit_interval_seconds=_parse_float(os.getenv("SCAN_EMIT_INTERVAL_SECONDS"), 3.0),
        packet_emit_batch_size=_parse_int(os.getenv("PACKET_EMIT_BATCH_SIZE"), 100),
        packet_emit_interval_seconds=_parse_float(os.getenv("PACKET_EMIT_INTERVAL_SECONDS"), 2.0),
        scan_dedup_signal_delta=_parse_int(os.getenv("SCAN_DEDUP_SIGNAL_DELTA"), 5),
        scan_dedup_max_age_seconds=_parse_float(os.getenv("SCAN_DEDUP_MAX_AGE_SECONDS"), 30.0),
        raw_packet_queue_size=_parse_int(os.getenv("RAW_PACKET_QUEUE_SIZE"), 2000),
        parsed_packet_queue_size=_parse_int(os.getenv("PARSED_PACKET_QUEUE_SIZE"), 2000),
    )


settings = load_settings()


AUTO_IFACE = settings.interface
INTERFACE = settings.interface
BACKEND_URL = settings.backend_url
SENSOR_USERNAME = settings.sensor_username
SENSOR_PASSWORD = settings.sensor_password
SENSOR_ID = settings.sensor_id
LOCKED_CHANNEL = settings.locked_channel
TRUSTED_APS = settings.trusted_aps
ENABLE_ACTIVE_CONTAINMENT = settings.enable_active_containment
DEAUTH_COUNT = settings.deauth_count
DEAUTH_INTERVAL = settings.deauth_interval
