#!/usr/bin/env bash
# ── ZeinaGuard Pro — Main Startup Script ──────────────────────────────────────
# Manages the Python virtual environment and launches all project components
# in the correct sequence: Backend API → Sensor Agent.
#
# Usage:  bash run.sh
#         sudo bash run.sh          (required for packet capture)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/venv"
BACKEND_DIR="$SCRIPT_DIR/backend"
SENSOR_DIR="$SCRIPT_DIR/sensor"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[ZeinaGuard]${RESET} $*"; }
success() { echo -e "${GREEN}[ZeinaGuard]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[ZeinaGuard]${RESET} $*"; }
error()   { echo -e "${RED}[ZeinaGuard] ERROR:${RESET} $*"; }

# ── PIDs of background processes ──────────────────────────────────────────────
BACKEND_PID=""

# ── Graceful shutdown on Ctrl+C (SIGINT) ──────────────────────────────────────
cleanup() {
    echo ""
    warn "Shutdown signal received — cleaning up…"

    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        info "Stopping backend (PID $BACKEND_PID)…"
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi

    if [ -n "${VIRTUAL_ENV:-}" ]; then
        info "Deactivating virtual environment…"
        deactivate 2>/dev/null || true
    fi

    success "ZeinaGuard stopped cleanly. Goodbye."
    exit 0
}

trap cleanup SIGINT SIGTERM

# ── Virtual Environment Setup ──────────────────────────────────────────────────
setup_venv() {
    if [ -d "$VENV_DIR" ]; then
        info "Virtual environment found — activating…"
    else
        info "No virtual environment found — creating one at $VENV_DIR …"
        python3 -m venv --system-site-packages "$VENV_DIR"
        success "Virtual environment created (inherits system packages)."

        info "Installing backend dependencies…"
        PIP_USER=0 "$VENV_DIR/bin/pip" install --upgrade pip --quiet 2>/dev/null || true
        PIP_USER=0 "$VENV_DIR/bin/pip" install -r "$BACKEND_DIR/requirements.txt" --quiet 2>/dev/null \
            && success "Backend dependencies installed." \
            || warn "Pip install failed — system-wide packages will be used."

        info "Installing sensor dependencies…"
        PIP_USER=0 "$VENV_DIR/bin/pip" install -r "$SENSOR_DIR/requirements.txt" --quiet 2>/dev/null \
            && success "Sensor dependencies installed." \
            || warn "Pip install failed — system-wide packages will be used."
    fi

    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    success "Virtual environment active: $VIRTUAL_ENV"
}

# ── Root .env loader ───────────────────────────────────────────────────────────
load_env() {
    if [ -f "$SCRIPT_DIR/.env" ]; then
        info "Loading environment from .env…"
        set -a; source "$SCRIPT_DIR/.env"; set +a
    fi
}

# ── Root privilege check ───────────────────────────────────────────────────────
check_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        warn "Not running as root. Packet capture (sensor) may fail."
        warn "Re-run with: sudo bash run.sh"
    else
        success "Running as root — full packet-capture capability enabled."
    fi
}

# ── Launch backend ─────────────────────────────────────────────────────────────
start_backend() {
    info "Starting ZeinaGuard backend…"

    # Redirect backend stdout/stderr to a log file so it never bleeds into
    # the sensor's interactive interface-selection prompt.
    local LOG_DIR="$SCRIPT_DIR/logs"
    mkdir -p "$LOG_DIR"
    BACKEND_LOG="$LOG_DIR/backend.log"

    cd "$BACKEND_DIR"

    if [ -f .env ]; then
        set -a; source .env; set +a
    fi

    python3 app.py > "$BACKEND_LOG" 2>&1 &
    BACKEND_PID=$!
    cd "$SCRIPT_DIR"

    # Give the backend a moment to bind its port
    sleep 2

    if kill -0 "$BACKEND_PID" 2>/dev/null; then
        success "Backend running (PID $BACKEND_PID). Logs → $BACKEND_LOG"
    else
        error "Backend failed to start. Check $BACKEND_LOG for details."
        exit 1
    fi
}

# ── Launch sensor (foreground — interactive interface selection) ───────────────
start_sensor() {
    info "Starting ZeinaGuard sensor agent…"
    cd "$SENSOR_DIR"

    if [ -f .env ]; then
        set -a; source .env; set +a
    fi

    python3 main.py
    cd "$SCRIPT_DIR"
}

# ── Main ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}   ZeinaGuard Pro — Startup              ${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
echo ""

load_env
setup_venv
check_root
start_backend
start_sensor
