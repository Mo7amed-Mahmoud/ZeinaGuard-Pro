import os
import unittest


class TestSensorConfig(unittest.TestCase):
    def test_config_imports(self):
        from sensor import config

        self.assertTrue(hasattr(config, "INTERFACE"))
        self.assertTrue(hasattr(config, "BACKEND_URL"))
        self.assertTrue(hasattr(config, "SENSOR_ID"))

    def test_interface_selection_helpers(self):
        from sensor import main

        self.assertIsInstance(main.list_all_interfaces(), list)
        self.assertIsInstance(main.list_wireless_interfaces(), list)

    def test_prompt_honours_env_var(self):
        from sensor import main

        os.environ["SENSOR_INTERFACE"] = "test_iface0"
        try:
            self.assertEqual(main.prompt_interface_selection(), "test_iface0")
        finally:
            del os.environ["SENSOR_INTERFACE"]


class TestSensorModules(unittest.TestCase):
    def test_event_bus(self):
        from sensor.core.event_bus import event_queue

        payload = {"type": "TEST"}
        event_queue.put(payload)
        self.assertEqual(event_queue.get(timeout=1), payload)

    def test_risk_engine(self):
        from sensor.detection.risk_engine import RiskEngine

        engine = RiskEngine({})
        result = engine.analyze(
            {
                "ssid": "Unknown",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 1,
                "signal": -40,
                "encryption": "OPEN",
                "clients": 3,
            }
        )
        self.assertIn("classification", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
