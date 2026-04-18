import requests


class APIClient:
    """REST client for authenticating the sensor with the ZeinaGuard backend."""

    def __init__(self, backend_url=None):
        from sensor.config import BACKEND_URL, SENSOR_USERNAME, SENSOR_PASSWORD

        self.backend_url = (backend_url or BACKEND_URL).rstrip("/")
        self.username = SENSOR_USERNAME
        self.password = SENSOR_PASSWORD
        self.token = None

    def authenticate_sensor(self):
        from sensor.ui.terminal_ui import update_status

        url = f"{self.backend_url}/api/auth/login"
        payload = {"username": self.username, "password": self.password}

        try:
            update_status(backend_status="authenticating", message="Authenticating with backend")
            response = requests.post(url, json=payload, timeout=5)

            if response.status_code != 200:
                update_status(
                    backend_status="offline",
                    message=f"Auth failed ({response.status_code}): check SENSOR_USER/SENSOR_PASSWORD",
                )
                return None

            data = response.json()
            self.token = data.get("access_token") or data.get("token")
            if not self.token:
                update_status(backend_status="offline", message="No token in backend response")
                return None

            update_status(backend_status="authenticated", message="Authentication successful")
            return self.token

        except requests.exceptions.RequestException as exc:
            update_status(backend_status="offline", message=f"Backend unreachable: {exc}")
            return None

    def get_headers(self):
        if not self.token:
            return {}
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
