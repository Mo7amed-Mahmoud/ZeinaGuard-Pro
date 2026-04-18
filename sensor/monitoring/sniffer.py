from datetime import datetime
import os
import threading
import time

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon

from config import INTERFACE
from core.event_bus import event_queue
from ui.terminal_ui import update_status
from utils import (
    estimate_distance,
    extract_channel,
    get_auth_type,
    get_manufacturer,
    get_raw_beacon,
    get_ssid,
    get_uptime,
    get_wps_info,
)


clients_map = {}
aps_state = {}

AP_TIMEOUT = 60
START_TIME = time.time()
FIRST_PACKET = True


def is_open_network(packet):
    if packet.haslayer(Dot11Beacon):
        cap = packet[Dot11Beacon].cap
        return not cap.privacy
    return False


def build_event(packet):
    global FIRST_PACKET

    if FIRST_PACKET:
        update_status(sensor_status="capturing", message="First WiFi packet captured")
        FIRST_PACKET = False

    dot11 = packet[Dot11]
    bssid = dot11.addr2
    ssid = get_ssid(packet)
    channel = extract_channel(packet)
    signal = getattr(packet, "dBm_AntSignal", None)
    clients_count = len(clients_map.get(bssid, set()))

    return {
        "timestamp": datetime.now().isoformat(),
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "signal": signal,
        "distance": estimate_distance(signal),
        "auth": get_auth_type(packet),
        "wps": get_wps_info(packet),
        "manufacturer": get_manufacturer(bssid),
        "uptime": get_uptime(packet),
        "raw_beacon": get_raw_beacon(packet),
        "elapsed_time": round(time.time() - START_TIME, 2),
        "encryption": "OPEN" if is_open_network(packet) else "SECURED",
        "clients": clients_count,
    }


def handle_packet(packet):
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if packet.haslayer(Dot11Beacon) and dot11.addr2:
        event = build_event(packet)
        bssid = event["bssid"]
        aps_state[bssid] = {
            "last_seen": time.time(),
            "event": event,
        }
        event_queue.put(event)

    if dot11.type == 2:
        bssid = dot11.addr3
        src = dot11.addr2
        if bssid and src and bssid != src:
            clients_map.setdefault(bssid, set()).add(src)


def ap_cleaner():
    while True:
        now = time.time()

        for bssid in list(aps_state.keys()):
            if now - aps_state[bssid]["last_seen"] > AP_TIMEOUT:
                del aps_state[bssid]
                event_queue.put(
                    {
                        "type": "AP_REMOVED",
                        "bssid": bssid,
                    }
                )

        time.sleep(5)


def channel_hopper():
    import config

    while True:
        if config.LOCKED_CHANNEL is not None:
            os.system(f"iwconfig {INTERFACE} channel {config.LOCKED_CHANNEL} 2>/dev/null")
            time.sleep(1)
            continue

        for ch in range(1, 14):
            if config.LOCKED_CHANNEL is not None:
                break

            os.system(f"iwconfig {INTERFACE} channel {ch} 2>/dev/null")
            time.sleep(0.4)


def start_monitoring():
    if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
        update_status(sensor_status="error", message=f"Interface not found: {INTERFACE}")
        return

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        update_status(sensor_status="error", message="Root privileges required for sniffing")
        return

    threading.Thread(target=channel_hopper, daemon=True).start()
    threading.Thread(target=ap_cleaner, daemon=True).start()
    update_status(sensor_status="monitoring", message=f"Sniffing on {INTERFACE}")

    try:
        sniff(iface=INTERFACE, prn=handle_packet, store=False)
    except Exception as exc:
        update_status(sensor_status="error", message=f"Sniffing failed: {exc}")
