"""Tests for communication module (SSH, HTTP, MQTT executors)."""
import unittest
from unittest.mock import patch, MagicMock
from modules.communication.executor_base import ExecutionResult
from modules.communication.attacker_profile import AttackerProfile
from modules.communication.http_executor import HTTPExecutor


class TestExecutionResult(unittest.TestCase):
    def test_success(self):
        r = ExecutionResult(success=True, output="hello", duration=0.5)
        self.assertTrue(r.success)

    def test_failure(self):
        r = ExecutionResult(success=False, error="timeout")
        self.assertFalse(r.success)
        self.assertEqual(r.error, "timeout")


class TestAttackerProfile(unittest.TestCase):
    def test_create_local(self):
        p = AttackerProfile(device_ip="192.168.1.1", mode="local", tag="host")
        self.assertTrue(p.is_local)
        self.assertEqual(p.label, "host")

    def test_create_ssh(self):
        p = AttackerProfile(device_ip="10.0.0.1", mode="ssh",
                            ssh_user="kali", ssh_password="pass123")
        self.assertFalse(p.is_local)
        self.assertTrue(p.has_credentials)

    def test_no_credentials(self):
        p = AttackerProfile(device_ip="10.0.0.1", mode="ssh")
        self.assertFalse(p.has_credentials)

    def test_to_dict_no_password(self):
        p = AttackerProfile(device_ip="10.0.0.1", ssh_password="secret")
        d = p.to_dict()
        self.assertNotIn("ssh_password", d)
        self.assertIn("device_ip", d)

    def test_from_dict(self):
        d = {"device_ip": "10.0.0.1", "mode": "ssh", "ssh_user": "root"}
        p = AttackerProfile.from_dict(d)
        self.assertEqual(p.ssh_user, "root")
        self.assertEqual(p.ssh_password, "")  # not in dict

    def test_label_fallback(self):
        p = AttackerProfile(device_ip="10.0.0.1")
        self.assertEqual(p.label, "10.0.0.1")


class TestHTTPExecutor(unittest.TestCase):
    def test_create(self):
        ex = HTTPExecutor(timeout=5)
        self.assertEqual(ex.timeout, 5)

    @patch("urllib.request.urlopen")
    def test_execute_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ex = HTTPExecutor(timeout=5)
        result = ex.execute("192.168.1.1", "test", port=80, method="GET", endpoint="/status")
        self.assertTrue(result.success)

    def test_send_action(self):
        action = MagicMock()
        action.name = "turn_on"
        action.method = "POST"
        action.endpoint = "/api/light"
        action.payload = '{"state":"on"}'
        action.headers = {}
        ex = HTTPExecutor(timeout=1)
        # will fail (no real device) but should not crash
        result = ex.send_action("192.168.1.99", action, port=80)
        self.assertFalse(result.success)


if __name__ == "__main__":
    unittest.main()
