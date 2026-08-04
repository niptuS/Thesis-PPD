"""Tests for the active discovery module (fingerprinting, crawling, fuzzing)."""
import unittest
from unittest.mock import patch, MagicMock
from modules.profiles.discovery import (
    DeviceFingerprint,
    CrawledEndpoint,
    DiscoveryResult,
    SERVER_VENDORS,
    VENDOR_ENDPOINT_PREFIXES,
    GENERIC_DISCOVERY_PATHS,
    COMMON_PARAMS,
    extract_paths_from_response,
    fingerprint_device,
    crawl_endpoints,
    fuzz_parameters,
    mqtt_active_discovery,
    run_active_discovery,
)


class TestVendorFingerprintDB(unittest.TestCase):

    def test_known_vendors_present(self):
        expected = {
            "hikvision", "dahua", "shelly", "tasmota",
            "sonoff", "axis", "foscam", "reolink",
            "tplink", "philips", "dlink",
        }
        found = set(SERVER_VENDORS.values())
        for vendor in expected:
            self.assertIn(vendor, found, f"Missing vendor: {vendor}")

    def test_vendor_prefixes_cover_main_vendors(self):
        expected = {"hikvision", "dahua", "shelly", "tasmota", "axis"}
        for v in expected:
            self.assertIn(v, VENDOR_ENDPOINT_PREFIXES, f"Missing prefix for: {v}")


class TestExtractPaths(unittest.TestCase):

    def test_html_links(self):
        html = '<a href="/api/status">Status</a> <a href="/config">Config</a>'
        paths = extract_paths_from_response(html)
        self.assertIn("/api/status", paths)
        self.assertIn("/config", paths)

    def test_json_refs(self):
        json_body = '{"endpoints": ["/api/v1", "/api/v2", "/health"]}'
        paths = extract_paths_from_response(json_body)
        self.assertIn("/api/v1", paths)
        self.assertIn("/api/v2", paths)
        self.assertIn("/health", paths)

    def test_strips_query_strings(self):
        html = '<a href="/api/data?format=json">Data</a>'
        paths = extract_paths_from_response(html)
        self.assertIn("/api/data", paths)
        self.assertNotIn("/api/data?format=json", paths)

    def test_ignores_external_urls(self):
        html = '<a href="https://example.com/api">External</a> <a href="/local">Local</a>'
        paths = extract_paths_from_response(html)
        self.assertIn("/local", paths)
        self.assertNotIn("https://example.com/api", paths)

    def test_empty_body(self):
        self.assertEqual(extract_paths_from_response(""), [])

    def test_deduplicates(self):
        html = '<a href="/api">A</a> <a href="/api">B</a>'
        paths = extract_paths_from_response(html)
        self.assertEqual(paths.count("/api"), 1)


class TestFingerprintDevice(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_identifies_hikvision(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Hikvision-Webs"}
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        fp = fingerprint_device("192.168.1.1", 80, timeout=1)
        self.assertEqual(fp.vendor, "hikvision")
        self.assertEqual(fp.confidence, "medium")
        self.assertEqual(fp.source, "server_header")

    @patch("urllib.request.urlopen")
    def test_identifies_shelly(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Shelly"}
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        fp = fingerprint_device("192.168.1.2", 80, timeout=1)
        self.assertEqual(fp.vendor, "shelly")

    @patch("urllib.request.urlopen")
    def test_unknown_vendor(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "CustomHTTP/1.0"}
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        fp = fingerprint_device("192.168.1.3", 80, timeout=1)
        self.assertEqual(fp.vendor, "")
        self.assertEqual(fp.server_header, "CustomHTTP/1.0")

    @patch("urllib.request.urlopen")
    def test_connection_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("no route")
        fp = fingerprint_device("10.0.0.99", 80, timeout=1)
        self.assertEqual(fp.vendor, "")
        self.assertEqual(fp.confidence, "low")


class TestCrawlEndpoints(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_crawls_seed_path(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'<a href="/api/status">Status</a>'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        results = crawl_endpoints("192.168.1.1", 80, seed_paths=["/"])
        paths = [r.path for r in results]
        self.assertIn("/", paths)
        self.assertIn("/api/status", paths)

    @patch("urllib.request.urlopen")
    def test_skips_unreachable(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("no route")
        results = crawl_endpoints("10.0.0.99", 80, seed_paths=["/api"])
        self.assertEqual(len(results), 0)


class TestFuzzParameters(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_detects_changed_response(self, mock_urlopen):
        # Baseline: 200 with 100 bytes
        baseline = MagicMock()
        baseline.status = 200
        baseline.read.return_value = b"x" * 100
        baseline.__enter__ = MagicMock(return_value=baseline)
        baseline.__exit__ = MagicMock(return_value=False)

        # With param: 200 with 200 bytes (different)
        with_param = MagicMock()
        with_param.status = 200
        with_param.read.return_value = b"x" * 200
        with_param.__enter__ = MagicMock(return_value=with_param)
        with_param.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [baseline] + [with_param] * len(COMMON_PARAMS)
        params = fuzz_parameters("192.168.1.1", 80, "/api", timeout=1)
        self.assertIn("debug", params)

    @patch("urllib.request.urlopen")
    def test_returns_empty_on_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("no route")
        params = fuzz_parameters("10.0.0.99", 80, "/api", timeout=1)
        self.assertEqual(params, [])


class TestMQTTActiveDiscovery(unittest.TestCase):

    def test_returns_empty_on_import_error(self):
        # When paho-mqtt is not installed, returns empty
        with patch("builtins.__import__", side_effect=ImportError):
            topics, sys_info = mqtt_active_discovery(
                "192.168.1.1", 1883, listen_window=1,
            )
            self.assertEqual(topics, [])
            self.assertEqual(sys_info, {})


class TestRunActiveDiscovery(unittest.TestCase):

    @patch("modules.profiles.discovery.fingerprint_device")
    @patch("modules.profiles.discovery.crawl_endpoints")
    @patch("modules.profiles.discovery.fuzz_parameters")
    def test_pipeline_runs_all_phases(
        self, mock_fuzz, mock_crawl, mock_fp,
    ):
        mock_fp.return_value = DeviceFingerprint(vendor="shelly")
        mock_crawl.return_value = [
            CrawledEndpoint(path="/status", source="seed", status_code=200, available=True),
            CrawledEndpoint(path="/relay/0", source="crawl", status_code=200, available=True),
        ]
        mock_fuzz.return_value = ["debug"]

        result = run_active_discovery(
            "192.168.1.1", port=80, device_type="plug",
            mqtt_port=0,  # skip MQTT
        )
        self.assertEqual(result.fingerprint.vendor, "shelly")
        self.assertEqual(len(result.crawled_endpoints), 2)
        self.assertIn("/status", result.fuzzed_params)
        self.assertEqual(result.fuzzed_params["/status"], ["debug"])


class TestEndpointScannerIntegration(unittest.TestCase):
    """Verifies that scan_endpoints accepts the new active_discovery parameter."""

    def test_scan_endpoints_has_active_discovery_param(self):
        import inspect
        from modules.profiles.endpoint_scanner import scan_endpoints
        sig = inspect.signature(scan_endpoints)
        self.assertIn("active_discovery", sig.parameters)
        self.assertTrue(sig.parameters["active_discovery"].default)

    def test_scan_mqtt_has_active_discovery_param(self):
        import inspect
        from modules.profiles.endpoint_scanner import scan_mqtt
        sig = inspect.signature(scan_mqtt)
        self.assertIn("active_discovery", sig.parameters)
        self.assertTrue(sig.parameters["active_discovery"].default)


if __name__ == "__main__":
    unittest.main()
