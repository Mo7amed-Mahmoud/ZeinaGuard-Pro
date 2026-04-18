from __future__ import annotations

from queue import Queue

from sensor.config import settings


raw_packet_queue = Queue(maxsize=settings.raw_packet_queue_size)
event_queue = Queue(maxsize=settings.parsed_packet_queue_size)
telemetry_queue = Queue(maxsize=settings.parsed_packet_queue_size)
containment_queue = Queue()
dashboard_queue = Queue()
scan_queue = Queue(maxsize=settings.parsed_packet_queue_size)
