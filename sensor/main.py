import os
import subprocess
import sys
import threading


REQUIRED_PACKAGES = {
    "flask": "flask",
    "flask-socketio": "flask_socketio",
    "python-socketio": "socketio",
    "redis": "redis",
    "requests": "requests",
    "scapy": "scapy",
    "rich": "rich",
    "readchar": "readchar",
    "flask-sqlalchemy": "flask_sqlalchemy",
}


def install_missing_packages():
    missing = []

    for package, module in REQUIRED_PACKAGES.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if not missing:
        return

    for pkg in missing:
        print(f"Missing package: {pkg}")

    choice = input("Install missing packages now? (y/n): ").lower()
    if choice != "y":
        sys.exit(1)

    subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])


def list_wireless_interfaces():
    """Return a list of wireless interfaces available on this machine."""
    interfaces = []
    try:
        for iface in os.listdir("/sys/class/net/"):
            if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                interfaces.append(iface)
    except Exception:
        pass
    return interfaces


def list_all_interfaces():
    """Return all network interfaces as a fallback."""
    try:
        return os.listdir("/sys/class/net/")
    except Exception:
        return []


def prompt_interface_selection():
    """
    Interactively ask the user which network interface to use for sniffing.
    Returns the selected interface name as a string.
    """
    # 1. If already set by environment variable, honour it and skip prompt.
    env_iface = os.getenv("SENSOR_INTERFACE", "").strip()
    if env_iface:
        print(f"[Sensor] Using interface from environment: {env_iface}")
        return env_iface

    wireless = list_wireless_interfaces()
    all_ifaces = list_all_interfaces()

    print()
    print("=" * 55)
    print("  ZeinaGuard — Network Interface Selection")
    print("=" * 55)

    if wireless:
        print("\n  Detected wireless interfaces:")
        for idx, iface in enumerate(wireless, start=1):
            print(f"    [{idx}] {iface}")

        other_start = len(wireless) + 1
        if all_ifaces:
            others = [i for i in all_ifaces if i not in wireless]
            if others:
                print("\n  Other interfaces:")
                for idx, iface in enumerate(others, start=other_start):
                    print(f"    [{idx}] {iface}")
                combined = wireless + others
            else:
                combined = wireless
        else:
            combined = wireless
    elif all_ifaces:
        print("\n  No wireless interfaces detected. Available interfaces:")
        for idx, iface in enumerate(all_ifaces, start=1):
            print(f"    [{idx}] {iface}")
        combined = all_ifaces
    else:
        print("\n  [!] No network interfaces detected.")
        combined = []

    print()

    while True:
        if combined:
            prompt = f"  Enter interface name or number [1-{len(combined)}]: "
        else:
            prompt = "  Enter interface name manually: "

        user_input = input(prompt).strip()

        if not user_input:
            print("  [!] Input cannot be empty. Please try again.")
            continue

        # Accept a number index
        if user_input.isdigit():
            idx = int(user_input)
            if 1 <= idx <= len(combined):
                selected = combined[idx - 1]
                print(f"\n  Selected interface: {selected}")
                print("=" * 55)
                print()
                return selected
            else:
                print(f"  [!] Number out of range. Enter 1-{len(combined)}.")
                continue

        # Accept a literal interface name
        print(f"\n  Selected interface: {user_input}")
        print("=" * 55)
        print()
        return user_input


def main():
    install_missing_packages()

    from communication.api_client import APIClient
    from communication.ws_client import WSClient
    from detection.threat_manager import ThreatManager
    from monitoring.sniffer import start_monitoring
    from prevention.response_engine import ResponseEngine
    from ui.terminal_ui import run_terminal_ui, update_status
    import config

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Warning: not running as root. Packet capture may fail.")

    # ── Interactive interface selection ────────────────────────────────────────
    selected_interface = prompt_interface_selection()
    config.INTERFACE = selected_interface
    os.environ["SENSOR_INTERFACE"] = selected_interface

    # Flush any residual bytes left in stdin from the input() call above.
    # Without this, readchar picks up a stray character and raises KeyboardInterrupt
    # immediately, killing the UIKeyboard thread before the user interacts.
    try:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass

    ui_thread = threading.Thread(target=run_terminal_ui, daemon=True, name="TerminalUI")
    ui_thread.start()
    update_status(sensor_status="starting", backend_status="connecting", message="Booting sensor")

    token = None
    try:
        api = APIClient()
        token = api.authenticate_sensor()
        update_status(
            backend_status="authenticated" if token else "offline",
            message="Backend authenticated" if token else "Offline mode: local logging only",
        )
    except Exception:
        update_status(backend_status="offline", message="Backend unavailable: local logging only")

    ws_client = WSClient(token=token)
    threading.Thread(target=ws_client.start, daemon=True, name="WSClient").start()

    threat_manager = ThreatManager()
    threading.Thread(target=threat_manager.start, daemon=True, name="ThreatManager").start()

    response_engine = ResponseEngine()
    threading.Thread(target=response_engine.start, daemon=True, name="ResponseEngine").start()

    update_status(sensor_status="monitoring", message="Wireless monitoring active")
    start_monitoring()


if __name__ == "__main__":
    main()
