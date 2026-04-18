from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from datetime import datetime
from queue import Empty, Full

from scapy.all import AsyncSniffer
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11ProbeReq, Dot11ProbeResp

from sensor import config
from sensor.core.event_bus import event_queue, raw_packet_queue, telemetry_queue
from sensor.ui.terminal_ui import update_status
from sensor.utils import (
    estimate_distance,
    extract_channel,
    get_auth_type,
    get_manufacturer,
    get_raw_beacon,
    get_ssid,
    get_uptime,
    get_wps_info,
)


clients_map: dict[str, set[str]] = {}
aps_state: dict[str, dict[str, object]] = {}

AP_TIMEOUT = 60
START_TIME = time.time()
FIRST_PACKET = True


MANAGEMENT_SUBTYPES = {
    4: "probe_request",
    5: "probe_response",
    8: "beacon",
    10: "disassoc",
    12: "deauth",
}


def is_open_network(packet):
    if packet.haslayer(Dot11Beacon):
        cap = packet[Dot11Beacon].cap
        return not cap.privacy
    return False


class SensorSniffer:
    def __init__(self, interface: str | None = None):
        self.interface = interface or config.INTERFACE
        self.stop_event = threading.Event()
        self.sniffer: AsyncSniffer | None = None
        self.worker_threads: list[threading.Thread] = []

    def start(self) -> None:
        if not os.path.exists(f"/sys/class/net/{self.interface}"):
            update_status(sensor_status="error", message=f"Interface not found: {self.interface}")
            return

        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
            update_status(sensor_status="error", message="Root privileges required for sniffing")
            return

        self.stop_event.clear()
        self._start_threads()
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self._enqueue_packet, store=False)
        self.sniffer.start()
        update_status(sensor_status="monitoring", message=f"Sniffing on {self.interface}")

        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        finally:
            self.stop()

    def stop(self) -> None:
        self.stop_event.set()
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass

    def _start_threads(self) -> None:
        self.worker_threads = [
            threading.Thread(target=self._packet_worker, daemon=True, name="PacketWorker-1"),
            threading.Thread(target=self._packet_worker, daemon=True, name="PacketWorker-2"),
            threading.Thread(target=self._ap_cleaner, daemon=True, name="APCleaner"),
            threading.Thread(target=self._channel_hopper, daemon=True, name="ChannelHopper"),
        ]
        for thread in self.worker_threads:
            thread.start()

    def _enqueue_packet(self, packet) -> None:
        try:
            raw_packet_queue.put_nowait(packet)
        except Full:
            update_status(sensor_status="degraded", message="Raw packet queue is full; dropping capture frames")

    def _packet_worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                packet = raw_packet_queue.get(timeout=0.5)
            except Empty:
                continue
            self._handle_packet(packet)

    def _handle_packet(self, packet) -> None:
        global FIRST_PACKET

        if not packet.haslayer(Dot11):
            return

        if FIRST_PACKET:
            FIRST_PACKET = False
            update_status(sensor_status="capturing", message="First WiFi packet captured")

        dot11 = packet[Dot11]
        packet_event = self._build_packet_event(packet)
        if packet_event is not None:
            try:
                telemetry_queue.put_nowait(packet_event)
            except Full:
                update_status(sensor_status="degraded", message="Packet telemetry queue is full; dropping telemetry")

        if packet.haslayer(Dot11Beacon) and dot11.addr2:
            event = self._build_scan_event(packet)
            bssid = event["bssid"]
            aps_state[bssid] = {
                "last_seen": time.time(),
                "event": event,
            }
            try:
                event_queue.put_nowait(event)
            except Full:
                update_status(sensor_status="degraded", message="Scan event queue is full; dropping AP update")

        if dot11.type == 2:
            bssid = dot11.addr3
            src = dot11.addr2
            if bssid and src and bssid != src:
                clients_map.setdefault(bssid, set()).add(src)

    def _build_scan_event(self, packet) -> dict[str, object]:
        dot11 = packet[Dot11]
        bssid = dot11.addr2
        ssid = get_ssid(packet)
        channel = extract_channel(packet)
        signal = getattr(packet, "dBm_AntSignal", None)
        clients_count = len(clients_map.get(bssid, set()))

        return {
            "timestamp": datetime.utcnow().isoformat(),
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

    def _build_packet_event(self, packet) -> dict[str, object] | None:
        dot11 = packet[Dot11]
        frame_type = self._frame_type_name(dot11.type)
        frame_subtype = MANAGEMENT_SUBTYPES.get(dot11.subtype, f"subtype_{dot11.subtype}")
        relevant = frame_subtype in {"probe_request", "probe_response", "beacon", "deauth", "disassoc"}
        if not relevant:
            return None

        bssid = dot11.addr3 or dot11.addr2 or dot11.addr1
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "frame_type": frame_type,
            "frame_subtype": frame_subtype,
            "source_mac": dot11.addr2,
            "dest_mac": dot11.addr1,
            "bssid": bssid,
            "ssid": get_ssid(packet),
            "channel": extract_channel(packet),
            "signal": getattr(packet, "dBm_AntSignal", None),
            "packet_length": len(packet),
            "manufacturer": get_manufacturer(dot11.addr2),
        }

        if packet.haslayer(Dot11Deauth):
            event["reason_code"] = int(packet[Dot11Deauth].reason)
        elif packet.haslayer(Dot11Disas):
            event["reason_code"] = int(packet[Dot11Disas].reason)

        return event

    def _ap_cleaner(self) -> None:
        while not self.stop_event.is_set():
            now = time.time()
            for bssid in list(aps_state.keys()):
                if now - float(aps_state[bssid]["last_seen"]) > AP_TIMEOUT:
                    del aps_state[bssid]
                    event_queue.put({"type": "AP_REMOVED", "bssid": bssid})
            time.sleep(5)

    def _channel_hopper(self) -> None:
        if shutil.which("iwconfig") is None:
            return

        while not self.stop_event.is_set():
            if config.LOCKED_CHANNEL is not None:
                self._set_channel(config.LOCKED_CHANNEL)
                time.sleep(1)
                continue

            for channel in range(1, 14):
                if self.stop_event.is_set() or config.LOCKED_CHANNEL is not None:
                    break
                self._set_channel(channel)
                time.sleep(0.4)

    def _set_channel(self, channel: int) -> None:
        try:
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass

    @staticmethod
    def _frame_type_name(frame_type: int) -> str:
        return {
            0: "management",
            1: "control",
            2: "data",
        }.get(frame_type, "unknown")


def start_monitoring() -> None:
    SensorSniffer().start()
