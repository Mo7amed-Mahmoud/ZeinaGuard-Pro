# ZeinaGuard Pro — Deployment & Walkthrough Guide

## Overview

ZeinaGuard Pro is a real-time wireless threat detection system with three parts:

| Component | Technology | Where it runs |
|-----------|-----------|---------------|
| **Dashboard** | Next.js 14 | Replit (port 5000) |
| **Backend API + WebSocket** | Flask + Socket.IO | Replit (port 8000) |
| **Sensor Agent** | Python + Scapy | Raspberry Pi (physical hardware) |

---

## 1. Running on Replit

### Start the backend

1. Open the **Shell** tab in Replit.
2. The workflow `Backend API` is already configured. Click **Run** next to it, or:
   ```bash
   cd backend && python app.py
   ```
3. The API will be available at `http://localhost:8000`. From the browser, it's proxied through your Replit dev domain.

### Start the frontend

The workflow `Start application` runs:
```bash
npm run dev
```
The Next.js dashboard serves on **port 5000** and appears in the Replit preview pane.

### Default credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Administrator |
| `analyst` | `analyst123` | Security Analyst |

> **Important:** Change these before any production use.

---

## 2. Environment Variables / Secrets

Set these in **Replit Secrets** (padlock icon):

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes (auto-set) | PostgreSQL connection string — Replit provisions this automatically |
| `JWT_SECRET_KEY` | **Strongly recommended** | Secret for signing JWT tokens. Without it, sessions reset on every restart. Use a 48+ char random string |
| `REDIS_URL` | Optional | Redis for event persistence. Falls back gracefully if absent |
| `NEXT_PUBLIC_API_URL` | Optional | Override API base URL for the frontend |

### Generate a strong JWT secret

```bash
python3 -c "import secrets; print(secrets.token_hex(48))"
```

Paste the output as the value of `JWT_SECRET_KEY` in Replit Secrets.

---

## 3. API Endpoints Reference

All endpoints are prefixed with `/api/`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login → returns JWT token |
| `GET` | `/api/auth/me` | Get current user info |
| `POST` | `/api/auth/refresh` | Refresh JWT token |

### Threats

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/threats/` | List all threats (DB) |
| `GET` | `/api/threats/?severity=critical` | Filter by severity |
| `GET` | `/api/threats/{id}` | Get single threat |
| `POST` | `/api/threats/{id}/resolve` | Mark threat resolved |
| `POST` | `/api/threats/demo/simulate-threat` | Simulate + persist a threat (demo) |

### Sensors

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/sensors/` | List sensors with live status |
| `GET` | `/api/sensors/{id}/health` | Sensor health detail |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/alerts/` | List alerts (DB) |
| `POST` | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |

### Analytics

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/analytics/threat-stats` | Aggregate counts by severity/type |
| `GET` | `/api/analytics/trends` | 7-day daily threat trend |

### Dashboard & Topology

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/dashboard/overview` | Combined dashboard data |
| `GET` | `/api/dashboard/stats` | Quick stats |
| `GET` | `/api/topology` | Network topology map |

---

## 4. WebSocket Events

The backend exposes a Socket.IO server (same port 8000).

### Events emitted by the server (client listens)

| Event | Payload | Description |
|-------|---------|-------------|
| `threat_event` | Threat object | New threat detected/created |
| `live_scan` | `{sensor_id, devices, ...}` | Real-time scan data from sensor |
| `sensor_status` | `{sensor_id, status, ...}` | Sensor online/offline status change |
| `alert_created` | Alert object | New alert created |

### Events sent by sensor (server listens)

| Event | Payload | Description |
|-------|---------|-------------|
| `sensor_register` | `{sensor_id, hostname, location, ...}` | Sensor connects and identifies itself |
| `network_scan` | `{sensor_id, devices, channel, ...}` | Periodic scan results |
| `new_threat` | `{sensor_id, threat_type, severity, ...}` | Threat detected by sensor |

---

## 5. Sensor (Raspberry Pi) Setup

### Prerequisites

- Raspberry Pi 3B+ or newer running Raspberry Pi OS
- A Wi-Fi adapter that supports **monitor mode** (e.g. Alfa AWUS036ACH)
- Python 3.10+
- Root access (`sudo`)

### Installation

```bash
# Clone or copy the sensor/ directory to your Raspberry Pi
git clone <your-repo-url>
cd ZeinaGuard/sensor

# Copy and configure the environment file
cp .env.example .env
nano .env
```

Edit `.env`:
```env
# URL of your Replit backend (copy from Replit dev domain or deployed URL)
BACKEND_URL=https://your-project.your-username.repl.co

# Credentials to authenticate sensor with backend
SENSOR_USER=admin
SENSOR_PASSWORD=admin123

# Optional: override sensor identity
ZEINAGUARD_SENSOR_ID=rpi-sensor-01
SENSOR_INTERFACE=wlan1   # Wi-Fi adapter for monitor mode
```

### Run the sensor

```bash
sudo bash start.sh
```

The script will:
1. Load `.env`
2. Install Python dependencies if missing
3. Put the Wi-Fi adapter into monitor mode
4. Start the sensor agent

The sensor will connect to the backend via Socket.IO, register itself, and begin scanning.

### Sensor .env variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_URL` | *required* | Full URL to your Replit backend |
| `SENSOR_USER` | `admin` | Username for backend API login |
| `SENSOR_PASSWORD` | `admin123` | Password for backend API login |
| `ZEINAGUARD_SENSOR_ID` | hostname | Unique sensor identifier |
| `SENSOR_INTERFACE` | `wlan0` | Network interface for scanning |
| `SCAN_INTERVAL` | `30` | Seconds between scans |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 6. Production Deployment on Replit

1. Go to **Deployments** in Replit (rocket icon).
2. Click **Deploy**.
3. Replit will:
   - Build the Next.js frontend
   - Start the Flask backend
   - Assign a permanent `*.replit.app` domain
4. Update `BACKEND_URL` in your sensor `.env` to use the deployed domain.
5. Update CORS origins if needed (see `backend/app.py`, `ALLOWED_ORIGINS`).

### Deployed URL format

```
https://your-project.your-username.replit.app
```

The sensor connects to this URL's Socket.IO endpoint:
```
wss://your-project.your-username.replit.app/socket.io/
```

---

## 7. Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                      Replit Cloud                        │
│                                                         │
│  ┌──────────────────┐   REST/WS    ┌─────────────────┐  │
│  │  Next.js Frontend│◄────────────►│  Flask Backend  │  │
│  │  (port 5000)     │  /api/*      │  (port 8000)    │  │
│  │                  │  /socket.io/ │                 │  │
│  └──────────────────┘             └────────┬────────┘  │
│                                            │            │
│                                            │ SQLAlchemy  │
│                                    ┌───────▼────────┐   │
│                                    │  PostgreSQL DB  │   │
│                                    └────────────────┘   │
└─────────────────────────────────────────────────────────┘
                              ▲
                              │ Socket.IO (WSS)
                              │ sensor_register
                              │ network_scan
                              │ new_threat
                              │
┌─────────────────────────────┴───────────────────────────┐
│                  Raspberry Pi (Local Network)            │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  ZeinaGuard Sensor Agent (sensor/main.py)        │   │
│  │  - Scapy packet capture (monitor mode)           │   │
│  │  - Rogue AP / Evil Twin / Deauth detection       │   │
│  │  - Reports to backend via Socket.IO              │   │
│  └──────────────────────────────────────────────────┘   │
│         │                                               │
│  [wlan1 monitor mode]                                   │
└─────────────────────────────────────────────────────────┘
```

---

## 8. Troubleshooting

### "JWT Invalid token" after restart
- The `JWT_SECRET_KEY` secret is not set. Each restart generates a new random key, invalidating all tokens.
- **Fix:** Set `JWT_SECRET_KEY` in Replit Secrets.

### Sensor can't connect to backend
- Check `BACKEND_URL` in `sensor/.env` — must be HTTPS, no trailing slash.
- Ensure the backend workflow is running.
- Check backend logs for `sensor_register` events.

### No threats appearing in dashboard
- Use the **Simulate Threat** button/endpoint (`POST /api/threats/demo/simulate-threat`) to create test data.
- Sensor data only appears when a physical sensor is connected.

### Database tables missing
- Tables are auto-created on startup via `db.create_all()` in `backend/app.py`.
- Check backend logs for DB connection errors.

### Frontend can't reach backend
- Verify `next.config.mjs` rewrites point to `localhost:8000`.
- Check that the backend workflow is running on port 8000.

---

## 9. File Structure

```
ZeinaGuard/
├── backend/                  # Flask API + WebSocket server
│   ├── app.py                # App factory, startup
│   ├── models.py             # SQLAlchemy ORM models
│   ├── routes.py             # Auth, threats, sensors, alerts, analytics
│   ├── routes_dashboard.py   # Dashboard sub-routes
│   ├── routes_topology.py    # Network topology routes
│   ├── websocket_server.py   # Socket.IO event handlers
│   ├── auth.py               # JWT auth, user management
│   └── requirements.txt
├── sensor/                   # Raspberry Pi sensor agent
│   ├── main.py               # Entry point
│   ├── config.py             # Configuration (env vars)
│   ├── start.sh              # Startup script
│   ├── .env.example          # Environment template
│   ├── requirements.txt      # Python dependencies
│   ├── communication/
│   │   ├── api_client.py     # REST API client
│   │   └── ws_client.py      # WebSocket client
│   └── detection/            # Threat detection algorithms
├── app/                      # Next.js pages + components
├── components/               # React UI components
├── hooks/
│   └── use-socket.ts         # WebSocket hook (frontend)
├── lib/
│   └── api.ts                # API client (frontend)
├── next.config.mjs           # Next.js config + API proxy
└── DEPLOYMENT_GUIDE.md       # This file
```
