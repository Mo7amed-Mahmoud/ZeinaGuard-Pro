#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${PROJECT_ROOT}/logs"
FRONTEND_LOG="${LOG_DIR}/frontend.log"
BACKEND_LOG="${LOG_DIR}/backend.log"

if [[ -d "${PROJECT_ROOT}/venv" ]]; then
  VENV_DIR="${PROJECT_ROOT}/venv"
elif [[ -d "${PROJECT_ROOT}/.venv" ]]; then
  VENV_DIR="${PROJECT_ROOT}/.venv"
else
  VENV_DIR="${PROJECT_ROOT}/venv"
fi

VENV_ACTIVATE="${VENV_DIR}/bin/activate"
VENV_PYTHON="${VENV_DIR}/bin/python"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

FRONTEND_PID=""
BACKEND_PID=""
CLEANED_UP=0

info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
  echo -e "${GREEN}[OK]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
  echo -e "${RED}[ERROR]${NC} $*"
}

require_sudo() {
  if [[ "${EUID}" -ne 0 ]]; then
    error "This script must be run with sudo."
    echo -e "${CYAN}Usage:${NC} sudo ./start_all.sh"
    exit 1
  fi

  if [[ -z "${SUDO_USER:-}" || "${SUDO_USER}" == "root" ]]; then
    error "Please run this script with sudo from your normal user account."
    echo -e "${CYAN}Example:${NC} sudo ./start_all.sh"
    exit 1
  fi
}

check_requirements() {
  if [[ ! -f "${PROJECT_ROOT}/package.json" ]]; then
    error "package.json not found in project root."
    exit 1
  fi

  if [[ ! -f "${PROJECT_ROOT}/backend/app.py" ]]; then
    error "backend/app.py not found."
    exit 1
  fi

  if [[ ! -f "${PROJECT_ROOT}/sensor/main.py" ]]; then
    error "sensor/main.py not found."
    exit 1
  fi

  if [[ ! -f "${VENV_ACTIVATE}" || ! -x "${VENV_PYTHON}" ]]; then
    error "Virtual environment not found at ${VENV_DIR}."
    exit 1
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    error "'sudo' is required but not installed."
    exit 1
  fi

  if ! sudo -u "${SUDO_USER}" bash -lc 'command -v npm >/dev/null 2>&1'; then
    error "npm is not available for user ${SUDO_USER}."
    exit 1
  fi
}

prepare_logs() {
  mkdir -p "${LOG_DIR}"
  touch "${FRONTEND_LOG}" "${BACKEND_LOG}"
  chown -R "${SUDO_USER}":"${SUDO_USER}" "${LOG_DIR}"
}

stop_process() {
  local pid="${1:-}"
  local name="${2:-Process}"

  if [[ -z "${pid}" ]]; then
    return 0
  fi

  if ! kill -0 "${pid}" >/dev/null 2>&1; then
    return 0
  fi

  warn "Stopping ${name} (PID ${pid})..."
  kill -TERM "${pid}" >/dev/null 2>&1 || true

  for _ in {1..20}; do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      success "${name} stopped cleanly."
      wait "${pid}" 2>/dev/null || true
      return 0
    fi
    sleep 0.5
  done

  warn "${name} did not stop in time. Sending SIGKILL..."
  kill -KILL "${pid}" >/dev/null 2>&1 || true
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  local exit_code="${1:-$?}"

  if [[ "${CLEANED_UP}" -eq 1 ]]; then
    return
  fi

  CLEANED_UP=1
  trap - EXIT INT TERM

  echo
  info "Cleaning up background services..."
  stop_process "${BACKEND_PID}" "Backend"
  stop_process "${FRONTEND_PID}" "Frontend"
  success "Shutdown complete."
  exit "${exit_code}"
}

start_frontend() {
  info "Starting Frontend (Next.js) as ${SUDO_USER} on port 3000..."
  (
    cd "${PROJECT_ROOT}"
    exec sudo -u "${SUDO_USER}" bash -lc 'cd "$1" && exec npm run dev' _ "${PROJECT_ROOT}"
  ) >>"${FRONTEND_LOG}" 2>&1 &
  FRONTEND_PID=$!

  sleep 2
  if ! kill -0 "${FRONTEND_PID}" >/dev/null 2>&1; then
    error "Frontend failed to start. Check ${FRONTEND_LOG}"
    exit 1
  fi

  success "Frontend started in background. Log: ${FRONTEND_LOG}"
}

start_backend() {
  info "Starting Backend (Flask) in background on port 8000..."
  (
    cd "${PROJECT_ROOT}"
    # shellcheck disable=SC1090
    source "${VENV_ACTIVATE}"
    exec python backend/app.py
  ) >>"${BACKEND_LOG}" 2>&1 &
  BACKEND_PID=$!

  sleep 2
  if ! kill -0 "${BACKEND_PID}" >/dev/null 2>&1; then
    error "Backend failed to start. Check ${BACKEND_LOG}"
    exit 1
  fi

  success "Backend started in background. Log: ${BACKEND_LOG}"
}

run_sensor() {
  info "Starting Sensor in foreground (interactive mode)..."
  warn "Press Ctrl+C to stop the sensor and automatically shut down Frontend + Backend."
  cd "${PROJECT_ROOT}"
  sudo "${VENV_PYTHON}" sensor/main.py
}

main() {
  trap 'cleanup $?' EXIT
  trap 'warn "Interrupt received. Shutting down..."; cleanup 130' INT TERM

  require_sudo
  check_requirements
  prepare_logs

  echo -e "${CYAN}========================================${NC}"
  echo -e "${CYAN}  ZeinaGuard Pro Master Startup Script  ${NC}"
  echo -e "${CYAN}========================================${NC}"

  info "Project root: ${PROJECT_ROOT}"
  info "Using virtual environment: ${VENV_DIR}"

  start_frontend
  start_backend
  run_sensor
}

main "$@"
