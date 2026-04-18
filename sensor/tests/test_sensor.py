"""
ZeinaGuard Sensor — Basic Test Suite
Run with: python3 -m pytest sensor/tests/ -v
         or: python3 sensor/tests/test_sensor.py
"""

import importlib
import os
import sys
import unittest

# Ensure the sensor package root is on the path so imports work
SENSOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SENSOR_DIR not in sys.path:
    sys.path.insert(0, SENSOR_DIR)


# ---------------------------------------------------------------------------
# 1. Config Tests
# ---------------------------------------------------------------------------
class TestConfig(unittest.TestCase):
    """Verify config.py loads correctly and exposes expected attributes."""

    def test_config_imports(self):
        import config
        self.assertTrue(hasattr(config, "INTERFACE"), "config.INTERFACE missing")
        self.assertTrue(hasattr(config, "BACKEND_URL"), "config.BACKEND_URL missing")
        self.assertTrue(hasattr(config, "SENSOR_ID"), "config.SENSOR_ID missing")

    def test_interface_is_string(self):
        import config
        self.assertIsInstance(config.INTERFACE, str)
        self.assertGreater(len(config.INTERFACE), 0)

    def test_backend_url_format(self):
        import config
        self.assertTrue(
            config.BACKEND_URL.startswith("http"),
            f"BACKEND_URL should start with 'http', got: {config.BACKEND_URL}",
        )

    def test_sensor_id_non_empty(self):
        import config
        self.assertIsInstance(config.SENSOR_ID, str)
        self.assertGreater(len(config.SENSOR_ID), 0)

    def test_containment_flag_is_bool(self):
        import config
        self.assertIsInstance(config.ENABLE_ACTIVE_CONTAINMENT, bool)

    def test_deauth_count_positive(self):
        import config
        self.assertIsInstance(config.DEAUTH_COUNT, int)
        self.assertGreater(config.DEAUTH_COUNT, 0)


# ---------------------------------------------------------------------------
# 2. Interface-Detection Tests (main.py helpers)
# ---------------------------------------------------------------------------

# Load sensor/main.py by spec so we always get the right file regardless of
# what else might be on sys.path under the name "main".
import importlib.util as _ilu

_SENSOR_MAIN_SPEC = _ilu.spec_from_file_location(
    "sensor_main",
    os.path.join(SENSOR_DIR, "main.py"),
)
_sensor_main = _ilu.module_from_spec(_SENSOR_MAIN_SPEC)
# Execute the module-level code (function definitions, constants)
_SENSOR_MAIN_SPEC.loader.exec_module(_sensor_main)


class TestInterfaceHelpers(unittest.TestCase):
    """Verify the interface listing helpers in main.py work correctly."""

    def test_list_all_interfaces_returns_list(self):
        result = _sensor_main.list_all_interfaces()
        self.assertIsInstance(result, list)

    def test_list_wireless_interfaces_returns_list(self):
        result = _sensor_main.list_wireless_interfaces()
        self.assertIsInstance(result, list)

    def test_wireless_subset_of_all(self):
        wireless = set(_sensor_main.list_wireless_interfaces())
        all_ifaces = set(_sensor_main.list_all_interfaces())
        self.assertTrue(
            wireless.issubset(all_ifaces),
            "Wireless interfaces should be a subset of all interfaces",
        )

    def test_prompt_honours_env_var(self):
        """If SENSOR_INTERFACE is set in the environment, the prompt must return it immediately."""
        test_iface = "test_iface0"
        os.environ["SENSOR_INTERFACE"] = test_iface
        try:
            result = _sensor_main.prompt_interface_selection()
            self.assertEqual(result, test_iface)
        finally:
            del os.environ["SENSOR_INTERFACE"]


# ---------------------------------------------------------------------------
# 3. Utils / Helper Tests
# ---------------------------------------------------------------------------
class TestUtils(unittest.TestCase):
    """Smoke-test the utility functions used by the sniffer."""

    def test_utils_module_importable(self):
        import utils  # noqa: F401

    def test_estimate_distance_with_signal(self):
        from utils import estimate_distance
        result = estimate_distance(-60)
        self.assertIsNotNone(result)

    def test_estimate_distance_with_none(self):
        from utils import estimate_distance
        result = estimate_distance(None)
        self.assertEqual(result, -1)

    def test_get_ssid_returns_string_or_none(self):
        """get_ssid returns 'Hidden' when no Dot11Elt layer is present."""
        from utils import get_ssid

        class FakePacket:
            def haslayer(self, _):
                return False
            def getlayer(self, _):
                return None

        result = get_ssid(FakePacket())
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# 4. Event Bus Tests
# ---------------------------------------------------------------------------
class TestEventBus(unittest.TestCase):
    """Verify the core event queue is functional."""

    def test_event_queue_importable(self):
        from core.event_bus import event_queue
        self.assertIsNotNone(event_queue)

    def test_event_queue_put_and_get(self):
        from core.event_bus import event_queue
        test_event = {"type": "TEST", "value": 42}
        event_queue.put(test_event)
        got = event_queue.get(timeout=1)
        self.assertEqual(got, test_event)


# ---------------------------------------------------------------------------
# 5. Detection / Risk Engine Smoke Tests
# ---------------------------------------------------------------------------
class TestRiskEngine(unittest.TestCase):
    """Basic smoke tests for the risk engine."""

    def test_risk_engine_importable(self):
        from detection import risk_engine  # noqa: F401

    def test_threat_manager_importable(self):
        from detection import threat_manager  # noqa: F401


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("  ZeinaGuard Sensor — Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)
