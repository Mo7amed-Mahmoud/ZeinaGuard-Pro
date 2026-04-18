from __future__ import annotations

import os
import sys
import threading

if __package__ in {None, ""}:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sensor import config
from sensor.communication.api_client import APIClient
from sensor.communication.ws_client import WSClient
from sensor.detection.threat_manager import ThreatManager
from sensor.monitoring.sniffer import start_monitoring
from sensor.prevention.response_engine import ResponseEngine
from sensor.ui.terminal_ui import run_terminal_ui, update_status


def list_wireless_interfaces():
    interfaces = []
    try:
        for iface in os.listdir("/sys/class/net/"):
            if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                interfaces.append(iface)
    except Exception:
        pass
    return interfaces


def list_all_interfaces():
    try:
        return os.listdir("/sys/class/net/")
    except Exception:
        return []


def prompt_interface_selection():
    env_iface = os.getenv("SENSOR_INTERFACE", "").strip()
    if env_iface:
        print(f"[Sensor] Using interface from environment: {env_iface}")
        return env_iface

    if not sys.stdin.isatty():
        print(f"[Sensor] Non-interactive session detected; using auto-selected interface: {config.INTERFACE}")
        return config.INTERFACE

    wireless = list_wireless_interfaces()
    all_ifaces = list_all_interfaces()
    combined = wireless or all_ifaces

    print("\n" + "=" * 55)
    print("  ZeinaGuard Pro - Network Interface Selection")
    print("=" * 55)
    for idx, iface in enumerate(combined, start=1):
        print(f"    [{idx}] {iface}")

    while True:
        user_input = input(f"  Enter interface name or number [1-{len(combined)}]: ").strip()
        if not user_input:
            continue

        if user_input.isdigit():
            idx = int(user_input)
            if 1 <= idx <= len(combined):
                return combined[idx - 1]
            continue

        return user_input


def main():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[Sensor] Warning: not running as root. Packet capture may fail.")

    selected_interface = prompt_interface_selection()
    config.INTERFACE = selected_interface
    config.settings.interface = selected_interface
    os.environ["SENSOR_INTERFACE"] = selected_interface

    ui_thread = threading.Thread(target=run_terminal_ui, daemon=True, name="TerminalUI")
    ui_thread.start()
    update_status(sensor_status="starting", backend_status="connecting", message="Booting sensor")

    api_client = APIClient()
    token = api_client.authenticate_sensor()
    update_status(
        backend_status="authenticated" if token else "offline",
        message="Backend authenticated" if token else "Offline mode: local logging only",
    )

    ws_client = WSClient(token=token, api_client=api_client)
    threading.Thread(target=ws_client.start, daemon=True, name="WSClient").start()

    threat_manager = ThreatManager()
    threading.Thread(target=threat_manager.start, daemon=True, name="ThreatManager").start()

    response_engine = ResponseEngine()
    threading.Thread(target=response_engine.start, daemon=True, name="ResponseEngine").start()

    update_status(sensor_status="monitoring", message="Wireless monitoring active")
    start_monitoring()


if __name__ == "__main__":
    main()
