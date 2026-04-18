from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DEFAULT_DATA_DIR = BASE_DIR / "data"
DEFAULT_SQLITE_PATH = DEFAULT_DATA_DIR / "zeinaguard.db"


def _load_env_files() -> None:
    for env_path in (BASE_DIR / ".env", BACKEND_DIR / ".env"):
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


def _parse_origins(value: str | None) -> tuple[str, ...]:
    if not value:
        return (
            "http://localhost:3000",
            "http://localhost:5000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5000",
        )

    return tuple(
        origin.strip()
        for origin in value.split(",")
        if origin.strip()
    )


def _normalize_mac(value: str | None) -> str:
    if not value:
        return ""
    sanitized = str(value).strip().upper().replace("-", ":")
    parts = [part.zfill(2) for part in sanitized.split(":") if part]
    if len(parts) != 6:
        return sanitized
    return ":".join(parts)


def _normalize_trusted_aps(raw_data: Any) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    if not raw_data:
        return normalized

    source_items: list[tuple[str, Any]] = []
    if isinstance(raw_data, dict):
        source_items.extend(raw_data.items())
    elif isinstance(raw_data, list):
        for entry in raw_data:
            if not isinstance(entry, dict):
                continue
            ssid = str(entry.get("ssid") or "").strip()
            if ssid:
                source_items.append((ssid, entry))

    for ssid, entry in source_items:
        if not ssid:
            continue
        payload = entry if isinstance(entry, dict) else {}

        bssid_value = payload.get("bssids") or payload.get("bssid") or []
        if isinstance(bssid_value, str):
            bssids = [_normalize_mac(bssid_value)]
        else:
            bssids = [
                _normalize_mac(item)
                for item in bssid_value
                if _normalize_mac(str(item))
            ]

        channel_value = payload.get("channels") or payload.get("channel") or []
        if isinstance(channel_value, int):
            channels = [channel_value]
        elif isinstance(channel_value, str):
            channels = [
                int(part.strip())
                for part in channel_value.split(",")
                if part.strip().isdigit()
            ]
        else:
            channels = [
                int(item)
                for item in channel_value
                if str(item).strip().isdigit()
            ]

        normalized[ssid] = {
            "bssids": [item for item in bssids if item],
            "channels": channels,
            "encryption": str(payload.get("encryption") or payload.get("auth") or "UNKNOWN").upper(),
            "manufacturer": str(payload.get("manufacturer") or "").strip(),
            "hidden": bool(payload.get("hidden", False)),
        }

    return normalized


def _load_trusted_aps() -> dict[str, dict[str, Any]]:
    inline_json = os.getenv("TRUSTED_APS_JSON")
    file_path = os.getenv("TRUSTED_APS_FILE")

    if inline_json:
        try:
            return _normalize_trusted_aps(json.loads(inline_json))
        except json.JSONDecodeError:
            print("[Config] Ignoring invalid TRUSTED_APS_JSON payload")

    candidate_paths = []
    if file_path:
        candidate_paths.append(Path(file_path))
    candidate_paths.append(BACKEND_DIR / "trusted_aps.json")

    for path in candidate_paths:
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                return _normalize_trusted_aps(json.load(handle))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[Config] Could not load trusted AP file {path}: {exc}")

    return {}


@dataclass(slots=True)
class BackendSettings:
    environment: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    jwt_secret_key: str = field(default_factory=lambda: secrets.token_hex(48))
    db_url: str = f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"
    cors_origins: tuple[str, ...] = field(default_factory=tuple)
    redis_url: str | None = None
    trusted_aps: dict[str, dict[str, Any]] = field(default_factory=dict)
    deauth_window_seconds: int = 10
    deauth_suspicious_threshold: int = 10
    deauth_attack_threshold: int = 25
    probe_window_seconds: int = 15
    probe_suspicious_threshold: int = 25
    probe_attack_threshold: int = 80
    abnormal_mac_window_seconds: int = 60
    abnormal_mac_bssid_threshold: int = 6
    abnormal_mac_ssid_threshold: int = 10
    alert_cooldown_seconds: int = 20

    @property
    def flask_config(self) -> dict[str, Any]:
        return {
            "JWT_SECRET_KEY": self.jwt_secret_key,
            "JSON_SORT_KEYS": False,
            "SQLALCHEMY_DATABASE_URI": self.db_url,
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_ENGINE_OPTIONS": {
                "pool_pre_ping": True,
                "pool_recycle": 3600,
            },
        }


def load_backend_settings() -> BackendSettings:
    _load_env_files()
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)

    db_url = (
        os.getenv("DB_URL")
        or os.getenv("DATABASE_URL")
        or f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"
    )

    jwt_secret_key = os.getenv("JWT_SECRET_KEY")
    if not jwt_secret_key:
        jwt_secret_key = secrets.token_hex(48)
        print(
            "[Config] JWT_SECRET_KEY is not set. A temporary key was generated for this process. "
            "Set JWT_SECRET_KEY in .env for production."
        )

    return BackendSettings(
        environment=os.getenv("FLASK_ENV", "development"),
        debug=_parse_bool(os.getenv("FLASK_DEBUG"), default=False),
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=_parse_int(os.getenv("FLASK_PORT"), 8000),
        jwt_secret_key=jwt_secret_key,
        db_url=db_url,
        cors_origins=_parse_origins(os.getenv("CORS_ORIGINS")),
        redis_url=os.getenv("REDIS_URL") or None,
        trusted_aps=_load_trusted_aps(),
        deauth_window_seconds=_parse_int(os.getenv("DEAUTH_WINDOW_SECONDS"), 10),
        deauth_suspicious_threshold=_parse_int(os.getenv("DEAUTH_SUSPICIOUS_THRESHOLD"), 10),
        deauth_attack_threshold=_parse_int(os.getenv("DEAUTH_ATTACK_THRESHOLD"), 25),
        probe_window_seconds=_parse_int(os.getenv("PROBE_WINDOW_SECONDS"), 15),
        probe_suspicious_threshold=_parse_int(os.getenv("PROBE_SUSPICIOUS_THRESHOLD"), 25),
        probe_attack_threshold=_parse_int(os.getenv("PROBE_ATTACK_THRESHOLD"), 80),
        abnormal_mac_window_seconds=_parse_int(os.getenv("ABNORMAL_MAC_WINDOW_SECONDS"), 60),
        abnormal_mac_bssid_threshold=_parse_int(os.getenv("ABNORMAL_MAC_BSSID_THRESHOLD"), 6),
        abnormal_mac_ssid_threshold=_parse_int(os.getenv("ABNORMAL_MAC_SSID_THRESHOLD"), 10),
        alert_cooldown_seconds=_parse_int(os.getenv("ALERT_COOLDOWN_SECONDS"), 20),
    )
