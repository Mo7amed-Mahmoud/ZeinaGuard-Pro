# config.py — ZeinaGuard Sensor configuration
# All values can be overridden with environment variables
import os
import socket as _socket


def get_wireless_interface():
    """Auto-detect the first wireless interface available."""
    try:
        interfaces = os.listdir('/sys/class/net/')
        for iface in interfaces:
            if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                return iface
    except Exception:
        pass
    return "wlan0"


AUTO_IFACE = get_wireless_interface()
INTERFACE = os.getenv("SENSOR_INTERFACE", AUTO_IFACE)

# ── Backend connection ────────────────────────────────────────────────────────
# Set BACKEND_URL to your Replit backend domain when running on a Raspberry Pi.
# Examples:
#   Local dev:   http://localhost:8000
#   Replit:      https://<your-replit-dev-domain>
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# Sensor credentials for backend authentication (override with env vars)
SENSOR_USERNAME = os.getenv("SENSOR_USER", "admin")
SENSOR_PASSWORD = os.getenv("SENSOR_PASSWORD", "admin123")

# Unique ID for this sensor node (defaults to hostname)
SENSOR_ID = os.getenv("ZEINAGUARD_SENSOR_ID", _socket.gethostname())

LOCKED_CHANNEL = None

# ── Trusted access points (Evil-Twin / Rogue AP baseline) ────────────────────
TRUSTED_APS = {}

# ── Active containment (deauth) settings ─────────────────────────────────────
ENABLE_ACTIVE_CONTAINMENT = os.getenv("ENABLE_CONTAINMENT", "True").lower() == "true"
DEAUTH_COUNT = int(os.getenv("DEAUTH_COUNT", "40"))
DEAUTH_INTERVAL = float(os.getenv("DEAUTH_INTERVAL", "0.1"))
