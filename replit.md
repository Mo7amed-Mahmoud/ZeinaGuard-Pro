# ZeinaGuard Pro — WIPS Project

## Overview
Enterprise-grade Wireless Intrusion Prevention System (WIPS) with three tiers:
- **Sensor Agent** (`sensor/`) — Python/Scapy, runs on Raspberry Pi hardware
- **Backend API** (`backend/`) — Flask + Socket.IO REST & WebSocket server
- **Dashboard** (`app/`, `components/`) — Next.js real-time monitoring UI

## Architecture
```
sensor/main.py          → sensor entry point (interactive interface selection)
sensor/monitoring/      → WiFi sniffing & channel hopping (sniffer.py)
sensor/detection/       → risk scoring & threat management
sensor/prevention/      → active containment (deauth engine)
sensor/communication/   → backend API + WebSocket client
sensor/ui/              → rich terminal UI
backend/app.py          → Flask entry point (port 8000)
backend/websocket_server.py → Socket.IO hub
app/dashboard/          → Next.js pages
```

## Running the Project

### Full startup (recommended)
```bash
bash run.sh        # creates/activates venv, starts backend, then sensor
sudo bash run.sh   # required for packet capture (monitor mode)
```

### Backend only
```bash
cd backend && python3 app.py
```

### Sensor only
```bash
cd sensor && python3 main.py   # prompts for interface selection
```

## Build & Package
```bash
bash build.sh
```
Runs the test suite (18 tests), then packages the project into `ZeinaGuard-Pro.zip`.
The zip excludes: `venv/`, `.git/`, `__pycache__/`, `node_modules/`, `.next/`, `.env`.

## Testing
```bash
cd sensor && SENSOR_INTERFACE=lo python3 -m pytest tests/ -v
```

## Key Scripts
| File | Purpose |
|------|---------|
| `run.sh` | Main startup — venv management, sequential launch, SIGINT cleanup |
| `build.sh` | CI-style build — tests then zip packaging |
| `sensor/main.py` | Sensor entry with interactive interface picker |
| `sensor/tests/test_sensor.py` | 18-test suite for sensor components |

## Environment Variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `BACKEND_URL` | `http://localhost:8000` | Backend API URL |
| `SENSOR_INTERFACE` | auto-detected | Skip interactive prompt and use this interface |
| `ZEINAGUARD_SENSOR_ID` | hostname | Unique sensor identifier |
| `DATABASE_URL` | local postgres | PostgreSQL connection string |
| `JWT_SECRET_KEY` | random (dev) | Set in Secrets for production |

## Dependencies
- Python 3.11+
- Flask, Flask-SocketIO, Flask-JWT-Extended, SQLAlchemy, psycopg2
- Scapy, rich, readchar, python-socketio, requests
- Node.js (for Next.js dashboard)
- PostgreSQL (for production backend)
