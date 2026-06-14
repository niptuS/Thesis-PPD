"""Tests for benign profiles and endpoint scanner."""
import unittest
from modules.profiles.profile_schema import BenignProfile, DeviceAction
from modules.profiles.profile_library import DEVICE_TYPES, create_template_profile
from modules.profiles.endpoint_scanner import (
    ENDPOINT_DB, EndpointResult, summarize_scan, _optimal_workers,
)


class TestDeviceAction(unittest.TestCase):
    def test_create(self):
        a = DeviceAction(name="turn_on", protocol="http", method="POST",
                         endpoint="/api/light", payload='{"state":"on"}')
        self.assertEqual(a.name, "turn_on")
        self.assertTrue(a.action_id)

    def test_to_dict_from_dict(self):
        a = DeviceAction(name="snap", endpoint="/snapshot")
        d = a.to_dict()
        a2 = DeviceAction.from_dict(d)
        self.assertEqual(a2.name, "snap")
        self.assertEqual(a2.endpoint, "/snapshot")


class TestBenignProfile(unittest.TestCase):
    def test_create(self):
        p = BenignProfile(device_type="camera", device_ip="192.168.1.81")
        self.assertTrue(p.profile_id)
        self.assertEqual(p.protocol, "http")

    def test_action_names(self):
        p = BenignProfile(actions=[
            DeviceAction(name="on"), DeviceAction(name="of"),
        ])
        self.assertEqual(p.action_names(), ["on", "of"])

    def test_get_action(self):
        p = BenignProfile(actions=[DeviceAction(name="snap", endpoint="/snap")])
        a = p.get_action("snap")
        self.assertIsNotNone(a)
        self.assertEqual(a.endpoint, "/snap")
        self.assertIsNone(p.get_action("nonexistent"))

    def test_to_dict_from_dict(self):
        p = BenignProfile(device_type="bulb", device_ip="10.0.0.1",
                          device_tag="living-room",
                          actions=[DeviceAction(name="on")])
        d = p.to_dict()
        p2 = BenignProfile.from_dict(d)
        self.assertEqual(p2.device_type, "bulb")
        self.assertEqual(p2.device_tag, "living-room")
        self.assertEqual(len(p2.actions), 1)


class TestDeviceTypes(unittest.TestCase):
    def test_minimum_types(self):
        self.assertGreaterEqual(len(DEVICE_TYPES), 10)
        for expected in ["camera", "bulb", "plug", "sensor", "speaker",
                         "thermostat", "lock", "doorbell", "vacuum", "tv"]:
            self.assertIn(expected, DEVICE_TYPES)

    def test_all_types_have_endpoints(self):
        for dtype in DEVICE_TYPES:
            self.assertIn(dtype, ENDPOINT_DB, f"No endpoints for {dtype}")
            self.assertGreater(len(ENDPOINT_DB[dtype]), 0, f"Empty endpoints for {dtype}")

    def test_create_template_profile(self):
        p = create_template_profile("camera", "10.0.0.1", "cam-01")
        self.assertEqual(p.device_type, "camera")
        self.assertEqual(p.device_ip, "10.0.0.1")


class TestEndpointScanner(unittest.TestCase):
    def test_endpoint_db_coverage(self):
        total = sum(len(eps) for db in ENDPOINT_DB.values() for eps in db.values())
        self.assertGreater(total, 80, f"Only {total} endpoints (expected 80+)")

    def test_summarize_scan_available(self):
        results = {
            "turn_on": [
                EndpointResult(endpoint="/relay/on", available=True, status_code=200),
                EndpointResult(endpoint="/api/on", unavailable=True),
            ]
        }
        summary = summarize_scan(results)
        self.assertEqual(summary["turn_on"]["status"], "available")
        self.assertEqual(summary["turn_on"]["endpoint"], "/relay/on")

    def test_summarize_scan_needs_auth(self):
        results = {
            "snapshot": [
                EndpointResult(endpoint="/snap", needs_auth=True, status_code=401),
            ]
        }
        summary = summarize_scan(results)
        self.assertEqual(summary["snapshot"]["status"], "needs_auth")

    def test_summarize_scan_unavailable(self):
        results = {
            "reboot": [
                EndpointResult(endpoint="/reboot", unavailable=True),
            ]
        }
        summary = summarize_scan(results)
        self.assertEqual(summary["reboot"]["status"], "unavailable")

    def test_optimal_workers(self):
        w = _optimal_workers()
        self.assertGreaterEqual(w, 3)
        self.assertLessEqual(w, 20)


if __name__ == "__main__":
    unittest.main()
