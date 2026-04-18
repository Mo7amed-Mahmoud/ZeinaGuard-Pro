import csv
import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any


class LocalDataLogger:
    CSV_FIELDS = [
        "timestamp",
        "ssid",
        "bssid",
        "channel",
        "signal",
        "encryption",
        "manufacturer",
        "classification",
        "score",
        "uptime",
        "uptime_seconds",
    ]

    def __init__(
        self,
        base_dir: Path | None = None,
        max_bytes: int | None = None,
        rotation_seconds: int | None = None,
    ):
        self.base_dir = Path(base_dir or Path(__file__).resolve().parent / "data-logs")
        os.makedirs(self.base_dir, exist_ok=True)

        # Rotate aggressively so long-running sensors stay bounded on disk.
        self.max_bytes = int(max_bytes or os.getenv("SENSOR_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
        self.rotation_seconds = int(rotation_seconds or os.getenv("SENSOR_LOG_ROTATION_SECONDS", "300"))
        self._lock = threading.Lock()
        self._csv_path: Path | None = None
        self._json_path: Path | None = None
        self._csv_file = None
        self._json_file = None
        self._csv_writer = None
        self._opened_at = 0.0

    def log_scan(self, payload: dict[str, Any]) -> None:
        row = self._build_row(payload)

        with self._lock:
            try:
                self._ensure_handles()
                self._csv_writer.writerow(row)
                self._json_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
                self._csv_file.flush()
                self._json_file.flush()
            except Exception as exc:
                print(f"[DataLogger] Write failed: {exc}")

    def _build_row(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": payload.get("timestamp") or datetime.utcnow().isoformat(),
            "ssid": payload.get("ssid", "Hidden"),
            "bssid": payload.get("bssid", ""),
            "channel": payload.get("channel"),
            "signal": payload.get("signal"),
            "encryption": payload.get("encryption", "UNKNOWN"),
            "manufacturer": payload.get("manufacturer", "Unknown"),
            "classification": payload.get("classification", "UNKNOWN"),
            "score": payload.get("score", 0),
            "uptime": payload.get("uptime", ""),
            "uptime_seconds": payload.get("uptime_seconds", 0),
        }

    def _ensure_handles(self) -> None:
        if self._needs_rotation():
            self._open_new_files()
        elif self._csv_file is None or self._json_file is None:
            self._open_new_files()

    def _needs_rotation(self) -> bool:
        if self._csv_file is None or self._json_file is None:
            return True

        if (time.time() - self._opened_at) >= self.rotation_seconds:
            return True

        if self._csv_path and self._csv_path.exists() and self._csv_path.stat().st_size >= self.max_bytes:
            return True

        if self._json_path and self._json_path.exists() and self._json_path.stat().st_size >= self.max_bytes:
            return True

        return False

    def _open_new_files(self) -> None:
        self._close_files()

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self._csv_path = self.base_dir / f"network_scan_{timestamp}.csv"
        self._json_path = self.base_dir / f"network_scan_{timestamp}.json"

        self._csv_file = self._csv_path.open("a", newline="", encoding="utf-8")
        self._json_file = self._json_path.open("a", encoding="utf-8")
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=self.CSV_FIELDS)

        if self._csv_path.stat().st_size == 0:
            self._csv_writer.writeheader()
            self._csv_file.flush()

        self._opened_at = time.time()
        print(f"[DataLogger] CSV log started: {self._csv_path.name}")
        print(f"[DataLogger] JSON log started: {self._json_path.name}")

    def _close_files(self) -> None:
        if self._csv_file:
            self._csv_file.close()
        if self._json_file:
            self._json_file.close()

        self._csv_file = None
        self._json_file = None
        self._csv_writer = None
