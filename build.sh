#!/usr/bin/env bash
# ── ZeinaGuard Pro — Build & Package Script ────────────────────────────────────
# 1. Activates (or creates) the Python virtual environment
# 2. Installs dependencies
# 3. Runs the sensor test suite
# 4. Packages the project into a distributable .zip (excluding venv, .git, caches)
#
# Usage:  bash build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/venv"
SENSOR_DIR="$SCRIPT_DIR/sensor"
BACKEND_DIR="$SCRIPT_DIR/backend"
OUTPUT_ZIP="$SCRIPT_DIR/ZeinaGuard-Pro.zip"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[build]${RESET} $*"; }
success() { echo -e "${GREEN}[build]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[build]${RESET} $*"; }
error()   { echo -e "${RED}[build] ERROR:${RESET} $*"; exit 1; }

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}   ZeinaGuard Pro — Build & Package       ${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
echo ""

# ── Step 1: Virtual environment ────────────────────────────────────────────────
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment found — activating…"
else
    info "Creating virtual environment…"
    python3 -m venv --system-site-packages "$VENV_DIR"
    success "Virtual environment created (inherits system packages)."

    info "Installing backend dependencies…"
    PIP_USER=0 "$VENV_DIR/bin/pip" install --upgrade pip --quiet 2>/dev/null || true
    PIP_USER=0 "$VENV_DIR/bin/pip" install -r "$BACKEND_DIR/requirements.txt" --quiet 2>/dev/null \
        && success "Backend dependencies installed." \
        || warn "Pip install skipped — using system-wide packages."

    info "Installing sensor dependencies…"
    PIP_USER=0 "$VENV_DIR/bin/pip" install -r "$SENSOR_DIR/requirements.txt" --quiet 2>/dev/null \
        && success "Sensor dependencies installed." \
        || warn "Pip install skipped — using system-wide packages."
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
success "Virtual environment active."

# ── Step 2: Run sensor tests ───────────────────────────────────────────────────
info "Running sensor test suite…"
echo ""

# Install pytest into venv if missing
if ! python3 -c "import pytest" 2>/dev/null; then
    info "Installing pytest…"
    pip install pytest --quiet
fi

# Set a dummy interface so the prompt_interface_selection() env-var path is used
export SENSOR_INTERFACE="lo"

cd "$SENSOR_DIR"
if python3 -m pytest tests/ -v --tb=short; then
    echo ""
    success "All tests passed."
else
    echo ""
    error "Tests failed — packaging aborted. Fix the issues above and retry."
fi
cd "$SCRIPT_DIR"

# ── Step 3: Package into .zip ──────────────────────────────────────────────────
info "Packaging project into $OUTPUT_ZIP …"

rm -f "$OUTPUT_ZIP"

# Build the exclusion list for zip
# zip uses -x patterns (shell globs, relative to the working directory)
zip -r "$OUTPUT_ZIP" . \
    -x "venv/*" \
    -x ".git/*" \
    -x ".git" \
    -x "__pycache__/*" \
    -x "*/__pycache__/*" \
    -x "**/__pycache__/*" \
    -x "*.pyc" \
    -x "*.pyo" \
    -x ".env" \
    -x "node_modules/*" \
    -x ".next/*" \
    -x "*.egg-info/*" \
    -x ".pytest_cache/*" \
    -x "*/.pytest_cache/*" \
    -x "*.log" \
    -x "logs/*" \
    -x "ZeinaGuard-Pro.zip" \
    -x "zipFile.zip" \
    > /dev/null

ZIP_SIZE=$(du -sh "$OUTPUT_ZIP" | cut -f1)
echo ""
success "Package created: $OUTPUT_ZIP  ($ZIP_SIZE)"
echo ""
echo -e "${BOLD}  Build complete. The file is ready for download.${RESET}"
echo ""
