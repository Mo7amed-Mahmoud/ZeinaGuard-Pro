#!/usr/bin/env bash
# ── ZeinaGuard Sensor — Startup Script ────────────────────────────────────────
# Run this on your Raspberry Pi to start the sensor agent.
# Requirements: Python 3.10+, a Wi-Fi adapter that supports monitor mode, root access.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Load .env if present ──────────────────────────────────────────────────────
if [ -f .env ]; then
    echo "[Sensor] Loading environment from .env"
    set -a; source .env; set +a
fi

# ── Validate required config ──────────────────────────────────────────────────
if [ -z "$BACKEND_URL" ]; then
    echo "[Sensor] ERROR: BACKEND_URL is not set."
    echo "         Set it in .env or export it before running this script."
    echo "         Example: export BACKEND_URL=https://your-replit-dev-domain"
    exit 1
fi

echo "[Sensor] Backend URL: $BACKEND_URL"
echo "[Sensor] Sensor ID:   ${ZEINAGUARD_SENSOR_ID:-$(hostname)}"

# ── Check for root ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "[Sensor] WARNING: Not running as root. Packet capture may fail."
    echo "         Use: sudo bash start.sh"
fi

# ── Install Python dependencies if missing ────────────────────────────────────
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "[Sensor] Installing Python dependencies..."
    pip3 install -r requirements.txt
fi

# ── Put Wi-Fi adapter in monitor mode ────────────────────────────────────────
if [ -n "$SENSOR_INTERFACE" ]; then
    echo "[Sensor] Setting $SENSOR_INTERFACE to monitor mode..."
    ip link set "$SENSOR_INTERFACE" down 2>/dev/null || true
    iw dev "$SENSOR_INTERFACE" set type monitor 2>/dev/null || true
    ip link set "$SENSOR_INTERFACE" up 2>/dev/null || true
fi

# ── Start sensor ──────────────────────────────────────────────────────────────
echo "[Sensor] Starting ZeinaGuard sensor agent..."
python3 main.py
