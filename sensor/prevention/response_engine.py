from sensor.core.event_bus import containment_queue
from sensor.ui.terminal_ui import log_attack, update_status


class ResponseEngine:
    def start(self):
        while True:
            threat = containment_queue.get()
            bssid = threat.get("event", {}).get("bssid", "unknown")
            log_attack(f"Manual hunt required -> {bssid}", bssid)
            update_status(message=f"Rogue detected: press H and choose {bssid} for manual hunt")
