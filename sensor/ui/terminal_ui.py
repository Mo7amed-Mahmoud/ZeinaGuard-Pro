import _thread
import threading
import time
from collections import deque

import readchar
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


console = Console()
lock = threading.Lock()

aps_view = {}
signal_history = {}
recent_sent = deque(maxlen=12)
attack_log = deque(maxlen=15)

status_state = {
    "sensor_status": "starting",
    "backend_status": "offline",
    "message": "Booting sensor",
    "sent_count": 0,
}

attack_stats = {
    "deauth_count": 0,
    "clients_kicked": 0,
    "target_bssid": None,
    "start_time": None,
}

current_filter = "ALL"
hunt_mode = False
hunt_target_bssid = None
ui_shutdown = threading.Event()
hunt_prompt_requested = threading.Event()
hunt_prompt_active = threading.Event()
manual_attack_thread = None


def update_ap(event_summary):
    """Keep the existing AP update path intact and track UI-only signal history."""
    with lock:
        bssid = event_summary["bssid"]
        signal = event_summary.get("signal")

        if signal is not None:
            history = signal_history.setdefault(bssid, deque(maxlen=6))
            history.append(signal)

        event_summary["last_seen"] = time.time()
        aps_view[bssid] = event_summary


def remove_ap(bssid):
    with lock:
        aps_view.pop(bssid, None)
        signal_history.pop(bssid, None)


def update_status(sensor_status=None, backend_status=None, message=None):
    with lock:
        if sensor_status is not None:
            status_state["sensor_status"] = sensor_status
        if backend_status is not None:
            status_state["backend_status"] = backend_status
        if message is not None:
            status_state["message"] = message


def mark_sent(event_summary):
    batch_size = int(event_summary.get("batch_size") or 1)
    if batch_size > 1:
        ssid = event_summary.get("ssid") or "Hidden"
        line = f"Sent batch: {batch_size} networks (latest {ssid})"
    else:
        ssid = event_summary.get("ssid") or "Hidden"
        bssid = event_summary.get("bssid") or "unknown"
        line = f"Sent: {ssid} ({bssid})"

    with lock:
        status_state["sent_count"] += batch_size
        status_state["message"] = line
        recent_sent.appendleft(line)


def log_attack(message, bssid=None):
    """Keep containment logging intact, while updating hunt-mode activity stats."""
    with lock:
        timestamp = time.strftime("%H:%M:%S")
        attack_log.appendleft(f"[{timestamp}] {message}")
        status_state["message"] = message

        if bssid:
            attack_stats["target_bssid"] = bssid

        if message.startswith("Containment started"):
            attack_stats["start_time"] = time.time()

        if message.startswith("Deauth sent"):
            attack_stats["deauth_count"] += 1


def client_kicked():
    with lock:
        attack_stats["clients_kicked"] += 1
        status_state["message"] = "Containment action sent"


def get_signal_bars(signal):
    if signal is None:
        return "N/A"
    if signal > -50:
        return "▂▄▆█"
    if signal > -60:
        return "▂▄▆"
    if signal > -70:
        return "▂▄"
    return "▂"


def estimate_distance(signal):
    if signal is None:
        return "Unknown"
    if signal > -45:
        return "🔥 ~1m"
    if signal > -55:
        return "~3m"
    if signal > -65:
        return "~7m"
    if signal > -75:
        return "~15m"
    return "20m+"


def radar_meter(signal):
    if signal is None:
        return "[----------]"

    level = int((signal + 90) / 4)
    level = max(0, min(level, 10))
    return "[" + ("█" * level) + ("░" * (10 - level)) + "]"


def _get_last_seen(last_seen):
    age = int(max(time.time() - last_seen, 0))
    if age < 2:
        return "now"
    return f"{age}s"


def _normalize_bssid(value):
    return str(value or "").strip().lower()


def _find_ap_by_bssid(bssid):
    normalized = _normalize_bssid(bssid)
    if not normalized:
        return None

    with lock:
        for ap_bssid, ap in aps_view.items():
            if _normalize_bssid(ap_bssid) == normalized:
                return dict(ap)

    return None


def _get_signal_history(bssid):
    with lock:
        return list(signal_history.get(bssid, []))


def _get_trend(bssid):
    history = _get_signal_history(bssid)
    if len(history) < 2:
        return "Stable"
    if history[-1] > history[0]:
        return "Closer"
    if history[-1] < history[0]:
        return "Away"
    return "Stable"


def _signal_sort_key(ap):
    signal = ap.get("signal")
    return (signal is not None, signal if signal is not None else -100)


def _filter_networks(networks):
    if current_filter == "ALL":
        return networks

    return [
        ap
        for ap in networks
        if str(ap.get("classification") or "").upper() == current_filter
    ]


def _style_classification(classification):
    classification = str(classification or "UNKNOWN").upper()
    if classification == "ROGUE":
        return "[bold white on red]ROGUE[/]"
    if classification == "SUSPICIOUS":
        return "[black on yellow]SUSPICIOUS[/]"
    if classification == "LEGIT":
        return "[green]LEGIT[/]"
    return classification


def _reset_attack_stats(target_bssid):
    with lock:
        attack_stats["deauth_count"] = 0
        attack_stats["clients_kicked"] = 0
        attack_stats["target_bssid"] = target_bssid
        attack_stats["start_time"] = None


def _select_hunt_target(raw_bssid):
    global hunt_mode, hunt_target_bssid

    ap = _find_ap_by_bssid(raw_bssid)
    if not ap:
        update_status(message=f"Target not found: {raw_bssid}")
        log_attack(f"Invalid hunt target -> {raw_bssid}")
        return

    target_bssid = ap.get("bssid")
    _reset_attack_stats(target_bssid)

    with lock:
        hunt_target_bssid = target_bssid
        hunt_mode = True

    log_attack(f"Manual hunt target selected -> {target_bssid}", target_bssid)
    update_status(message="Press ENTER to launch deauth attack on this target...")


def _prompt_for_hunt_target():
    global hunt_mode, hunt_target_bssid

    try:
        target_bssid = console.input("Enter target BSSID: ").strip()
    except (EOFError, KeyboardInterrupt):
        target_bssid = ""

    if not target_bssid:
        with lock:
            hunt_mode = False
            hunt_target_bssid = None
        update_status(message="Hunt mode cancelled")
        return

    _select_hunt_target(target_bssid)


def _launch_manual_attack():
    global manual_attack_thread

    with lock:
        target_bssid = hunt_target_bssid
        attack_running = manual_attack_thread is not None and manual_attack_thread.is_alive()

    if not target_bssid:
        update_status(message="No hunt target selected")
        return

    if attack_running:
        update_status(message="Manual attack already in progress")
        return

    target = _find_ap_by_bssid(target_bssid)
    if not target:
        update_status(message="Target lost")
        log_attack(f"Target lost -> {target_bssid}", target_bssid)
        return

    channel = target.get("channel")
    if channel in (None, "", "-"):
        update_status(message="Attack skipped: target channel unknown")
        return

    from config import INTERFACE
    from monitoring.sniffer import clients_map
    from prevention.containment_engine import ContainmentEngine

    clients = clients_map.get(target_bssid, set())
    containment = ContainmentEngine(INTERFACE)
    _reset_attack_stats(target_bssid)
    log_attack(f"Manual attack requested -> {target_bssid}", target_bssid)
    update_status(message=f"Launching manual containment on {target_bssid}")

    manual_attack_thread = threading.Thread(
        target=containment.contain,
        args=(target_bssid, clients, channel),
        daemon=True,
        name="ManualContainment",
    )
    manual_attack_thread.start()


def _build_status_panel():
    with lock:
        networks = list(aps_view.values())
        sensor_status = status_state["sensor_status"]
        backend_status = status_state["backend_status"]
        message = status_state["message"]
        sent_count = status_state["sent_count"]
        active_filter = current_filter
        target_bssid = hunt_target_bssid

    rogue_count = sum(1 for ap in networks if ap.get("classification") == "ROGUE")
    suspicious_count = sum(1 for ap in networks if ap.get("classification") == "SUSPICIOUS")
    legit_count = sum(1 for ap in networks if ap.get("classification") == "LEGIT")

    content = (
        "A: All | R: Rogue | S: Suspicious | L: Legit | H: Hunt | Q: Quit\n"
        f"Sensor: {sensor_status} | Backend: {backend_status}\n"
        f"Live: {len(networks)} | Rogue: {rogue_count} | Suspicious: {suspicious_count} | Legit: {legit_count}\n"
        f"Filter: {active_filter} | Hunt target: {target_bssid or 'None'}\n"
        f"Sent count: {sent_count}\n"
        f"Status: {message}"
    )

    return Panel(content, title="ZeinaGuard Sensor", border_style="cyan")


def _build_controls_panel():
    with lock:
        target_bssid = hunt_target_bssid
        message = status_state["message"]

    content = (
        "A: All | R: Rogue | S: Suspicious | L: Legit | H: Hunt | Q: Quit\n"
        f"Target: {target_bssid or 'Not selected'}\n"
        "Press ENTER to launch deauth attack on this target.\n"
        f"Status: {message}"
    )

    return Panel(content, title="Hunt Controls", border_style="bright_blue")


def _build_networks_table():
    with lock:
        active_filter = current_filter
        networks = sorted(aps_view.values(), key=_signal_sort_key, reverse=True)
        networks = _filter_networks(networks)

    table = Table(
        title=f"Live Networks [{active_filter}]",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("SSID", style="cyan")
    table.add_column("BSSID", style="magenta")
    table.add_column("CH", justify="center")
    table.add_column("Signal", justify="center")
    table.add_column("Distance", justify="center")
    table.add_column("Class", justify="center")
    table.add_column("Seen", justify="center")

    if not networks:
        placeholder = "Waiting..." if active_filter == "ALL" else "No networks match filter"
        table.add_row(placeholder, "-", "-", "-", "-", "-", "-")
        return table

    for network in networks[:20]:
        signal = network.get("signal")
        signal_text = "N/A" if signal is None else f"{signal} dBm {get_signal_bars(signal)}"
        table.add_row(
            str(network.get("ssid") or "Hidden"),
            str(network.get("bssid") or "-"),
            str(network.get("channel") or "-"),
            signal_text,
            estimate_distance(signal),
            _style_classification(network.get("classification")),
            _get_last_seen(network.get("last_seen", time.time())),
        )

    return table


def _build_hunt_panel():
    with lock:
        target_bssid = hunt_target_bssid

    if not target_bssid:
        return Panel("No hunt target selected", title="Rogue Tracker", border_style="red")

    target = _find_ap_by_bssid(target_bssid)
    if not target:
        content = (
            f"Target: {target_bssid}\n"
            "Status: Target lost\n"
            "Press H to choose another BSSID."
        )
        return Panel(content, title="Rogue Tracker", border_style="red")

    signal = target.get("signal")
    signal_text = "N/A" if signal is None else f"{signal} dBm"
    content = (
        f"SSID: {target.get('ssid') or 'Hidden'}\n"
        f"BSSID: {target.get('bssid') or '-'}\n"
        f"Signal: {signal_text}\n"
        f"Radar: {radar_meter(signal)}\n"
        f"Distance: {estimate_distance(signal)}\n"
        f"Trend: {_get_trend(target.get('bssid'))}\n"
        f"Last seen: {_get_last_seen(target.get('last_seen', time.time()))}"
    )

    return Panel(content, title="Rogue Tracker", border_style="bright_red")


def _build_attack_stats_panel():
    with lock:
        deauth_count = attack_stats["deauth_count"]
        clients_kicked = attack_stats["clients_kicked"]
        target_bssid = attack_stats["target_bssid"]
        start_time = attack_stats["start_time"]
        attack_running = manual_attack_thread is not None and manual_attack_thread.is_alive()

    elapsed = max(time.time() - start_time, 1) if start_time else 1
    rate = deauth_count / elapsed if start_time else 0.0

    content = (
        f"Target: {target_bssid or 'None'}\n"
        f"Attack active: {'Yes' if attack_running else 'No'}\n"
        f"Deauth/sec: {rate:.2f}\n"
        f"Deauth frames logged: {deauth_count}\n"
        f"Clients kicked: {clients_kicked}"
    )

    return Panel(content, title="Attack Stats", border_style="red")


def _build_recent_sent_panel():
    with lock:
        lines = list(recent_sent)

    content = "\n".join(lines) if lines else "No transmissions yet"
    return Panel(content, title="Recent Sent", border_style="green")


def _build_recent_activity_panel():
    with lock:
        lines = list(attack_log)

    content = "\n".join(lines) if lines else "No hunt activity yet"
    return Panel(content, title="Recent Activity", border_style="yellow")


def _build_layout():
    with lock:
        hunting = hunt_mode

    layout = Layout()

    if hunting:
        layout.split_column(
            Layout(_build_controls_panel(), size=6),
            Layout(_build_hunt_panel(), ratio=3),
            Layout(_build_attack_stats_panel(), size=7),
            Layout(_build_recent_activity_panel(), size=10),
        )
    else:
        layout.split_column(
            Layout(_build_status_panel(), size=8),
            Layout(_build_networks_table(), ratio=3),
            Layout(_build_recent_sent_panel(), size=14),
        )

    return layout


def _is_enter_key(key):
    return key in ("\r", "\n", readchar.key.ENTER)


def keyboard_listener():
    global current_filter

    while not ui_shutdown.is_set():
        if hunt_prompt_requested.is_set():
            time.sleep(0.05)
            continue

        try:
            key = readchar.readkey()
        except KeyboardInterrupt:
            # readchar raises KeyboardInterrupt on Ctrl+C byte or residual
            # stdin characters — catch it here so the thread stays alive.
            time.sleep(0.1)
            continue
        except Exception:
            time.sleep(0.1)
            continue

        key_lower = key.lower() if isinstance(key, str) else key

        if key_lower == "a":
            with lock:
                current_filter = "ALL"
        elif key_lower == "r":
            with lock:
                current_filter = "ROGUE"
        elif key_lower == "s":
            with lock:
                current_filter = "SUSPICIOUS"
        elif key_lower == "l":
            with lock:
                current_filter = "LEGIT"
        elif key_lower == "h":
            hunt_prompt_requested.set()

            while not hunt_prompt_active.is_set() and not ui_shutdown.is_set():
                time.sleep(0.05)

            if ui_shutdown.is_set():
                return

            _prompt_for_hunt_target()
            hunt_prompt_requested.clear()
        elif _is_enter_key(key):
            _launch_manual_attack()
        elif key_lower == "q":
            ui_shutdown.set()
            _thread.interrupt_main()
            return


def run_terminal_ui():
    ui_shutdown.clear()
    keyboard_thread = threading.Thread(
        target=keyboard_listener,
        daemon=True,
        name="UIKeyboard",
    )
    keyboard_thread.start()

    try:
        while not ui_shutdown.is_set():
            with Live(_build_layout(), refresh_per_second=4, console=console, screen=False) as live:
                while not ui_shutdown.is_set() and not hunt_prompt_requested.is_set():
                    live.update(_build_layout())
                    time.sleep(0.25)

            if hunt_prompt_requested.is_set():
                hunt_prompt_active.set()

                while hunt_prompt_requested.is_set() and not ui_shutdown.is_set():
                    time.sleep(0.05)

                hunt_prompt_active.clear()
    finally:
        ui_shutdown.set()
        hunt_prompt_requested.clear()
        hunt_prompt_active.clear()
