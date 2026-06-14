"""Tests for device registry, schema, and scanner utilities."""
import unittest
from modules.devices.device_schema import DeviceEntry, PortInfo
from modules.devices.device_registry import DeviceRegistry
from modules.devices.host_detector import get_host_ip, get_host_mac, get_host_hostname
from modules.devices.scanner import merge_by_mac, SCAN_METHODS


class TestDeviceEntry(unittest.TestCase):
    def test_create_default(self):
        d = DeviceEntry(ip="192.168.1.10")
        self.assertEqual(d.ip, "192.168.1.10")
        self.assertEqual(d.role, "target")
        self.assertEqual(d.status, "online")
        self.assertEqual(d.device_type, "unknown")
        self.assertIsInstance(d.tags, list)

    def test_create_with_all_fields(self):
        d = DeviceEntry(
            ip="10.0.0.1", mac="aa:bb:cc:dd:ee:f",
            hostname="cam-01", vendor="Dahua", role="target",
            device_type="camera", tags=["living", "camera"],
            open_ports=[PortInfo(port=80, protocol="http")],
        )
        self.assertEqual(d.mac, "aa:bb:cc:dd:ee:f")
        self.assertEqual(d.vendor, "Dahua")
        self.assertEqual(d.role, "target")
        self.assertEqual(len(d.open_ports), 1)
        self.assertEqual(d.open_ports[0].port, 80)

    def test_port_info(self):
        p = PortInfo(port=554, protocol="rtsp", banner="streaming")
        self.assertEqual(p.port, 554)
        self.assertEqual(p.protocol, "rtsp")


class TestDeviceRegistry(unittest.TestCase):
    def setUp(self):
        self.reg = DeviceRegistry()

    def test_upsert_and_get(self):
        d = DeviceEntry(ip="192.168.1.1", hostname="router")
        self.reg.upsert(d)
        result = self.reg.get("192.168.1.1")
        self.assertIsNotNone(result)
        self.assertEqual(result.hostname, "router")

    def test_upsert_update(self):
        d1 = DeviceEntry(ip="192.168.1.1", hostname="old")
        d2 = DeviceEntry(ip="192.168.1.1", hostname="new")
        self.reg.upsert(d1)
        self.reg.upsert(d2)
        self.assertEqual(len(self.reg.all()), 1)
        self.assertEqual(self.reg.get("192.168.1.1").hostname, "new")

    def test_remove(self):
        self.reg.upsert(DeviceEntry(ip="192.168.1.1"))
        self.reg.remove("192.168.1.1")
        self.assertEqual(len(self.reg.all()), 0)

    def test_remove_nonexistent_raises(self):
        with self.assertRaises(KeyError):
            self.reg.remove("10.0.0.99")

    def test_contains(self):
        self.reg.upsert(DeviceEntry(ip="192.168.1.5"))
        self.assertIn("192.168.1.5", self.reg)
        self.assertNotIn("10.0.0.1", self.reg)

    def test_clear(self):
        self.reg.upsert(DeviceEntry(ip="192.168.1.1"))
        self.reg.upsert(DeviceEntry(ip="192.168.1.2"))
        self.reg.clear()
        self.assertEqual(len(self.reg.all()), 0)


class TestMergeByMac(unittest.TestCase):
    def test_merge_new_device(self):
        existing = [DeviceEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01")]
        new = [DeviceEntry(ip="192.168.1.2", mac="aa:bb:cc:dd:ee:02")]
        result = merge_by_mac(existing, new)
        self.assertEqual(len(result), 2)

    def test_merge_ip_change_by_mac(self):
        existing = [DeviceEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", role="target")]
        new = [DeviceEntry(ip="192.168.1.99", mac="aa:bb:cc:dd:ee:01")]
        result = merge_by_mac(existing, new)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].ip, "192.168.1.99")
        self.assertEqual(result[0].role, "target")  # preserved

    def test_merge_preserves_tags(self):
        existing = [DeviceEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", tags=["camera"])]
        new = [DeviceEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", tags=["new_tag"])]
        result = merge_by_mac(existing, new)
        self.assertIn("camera", result[0].tags)
        self.assertIn("new_tag", result[0].tags)

    def test_offline_marking(self):
        existing = [DeviceEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01")]
        new = []  # nothing found
        result = merge_by_mac(existing, new)
        self.assertEqual(result[0].status, "offline")


class TestHostDetector(unittest.TestCase):
    def test_get_host_ip_returns_string(self):
        ip = get_host_ip()
        self.assertIsInstance(ip, str)
        self.assertGreater(len(ip), 0)

    def test_get_host_mac_format(self):
        mac = get_host_mac()
        self.assertIsInstance(mac, str)
        self.assertEqual(mac.count(":"), 5)

    def test_get_host_hostname(self):
        hostname = get_host_hostname()
        self.assertIsInstance(hostname, str)


class TestScanMethods(unittest.TestCase):
    def test_valid_methods(self):
        self.assertIn("nmap", SCAN_METHODS)
        self.assertIn("arp", SCAN_METHODS)
        self.assertIn("all", SCAN_METHODS)
        self.assertNotIn("mdns", SCAN_METHODS)


if __name__ == "__main__":
    unittest.main()
