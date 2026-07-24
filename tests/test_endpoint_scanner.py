"""Tests for endpoint scanner coverage."""
import unittest
from modules.profiles.endpoint_scanner import (
    ENDPOINT_DB, MQTT_TOPICS, EndpointResult, summarize_scan, _optimal_workers,
)
from modules.profiles.profile_library import DEVICE_TYPES


class TestEndpointDB(unittest.TestCase):
    def test_all_types_have_endpoints(self):
        for dtype in DEVICE_TYPES:
            self.assertIn(dtype, ENDPOINT_DB, f"No HTTP endpoints for {dtype}")

    def test_some_types_have_mqtt(self):
        mqtt_types = set(MQTT_TOPICS.keys())
        self.assertGreater(len(mqtt_types), 3, "At least 4 types should have MQTT")

    def test_endpoint_count(self):
        total = sum(len(eps) for db in ENDPOINT_DB.values() for eps in db.values())
        self.assertGreater(total, 80, f"Only {total} endpoints")

    def test_mqtt_topic_count(self):
        total = sum(len(t) for t in MQTT_TOPICS.values())
        self.assertGreater(total, 10, f"Only {total} MQTT topics")


class TestSummarizeScan(unittest.TestCase):
    def test_available(self):
        results = {"action": [EndpointResult(endpoint="/test", available=True, status_code=200)]}
        s = summarize_scan(results)
        self.assertEqual(s["action"]["status"], "available")

    def test_needs_auth(self):
        results = {"action": [EndpointResult(endpoint="/test", needs_auth=True, status_code=401)]}
        s = summarize_scan(results)
        self.assertEqual(s["action"]["status"], "needs_auth")

    def test_unavailable(self):
        results = {"action": [EndpointResult(endpoint="/test", unavailable=True)]}
        s = summarize_scan(results)
        self.assertEqual(s["action"]["status"], "unavailable")


class TestOptimalWorkers(unittest.TestCase):
    def test_range(self):
        w = _optimal_workers()
        self.assertGreaterEqual(w, 3)
        self.assertLessEqual(w, 20)


if __name__ == "__main__":
    unittest.main()
