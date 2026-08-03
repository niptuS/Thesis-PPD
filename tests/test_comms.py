"""Tests for the unified communication layer (modules.comms)."""
import unittest
from unittest.mock import MagicMock, patch

from modules.comms import (
    BaseChannel, ChannelResult, ExecutionResult,
    LocalChannel, HTTPChannel, MQTTChannel, SSHChannel,
    HTTPResult, MQTTResult, SSHResult,
    AttackerProfile, CommandDispatcher, DispatchResult,
    # Legacy aliases
    BaseExecutor, SSHExecutor, HTTPExecutor, MQTTExecutor,
)
from modules.comms.base import BaseChannel as BaseChannel2


class TestBaseChannel(unittest.TestCase):

    def test_channel_result_default_fields(self):
        r = ChannelResult(success=True)
        self.assertTrue(r.success)
        self.assertEqual(r.output, "")
        self.assertEqual(r.error, "")
        self.assertEqual(r.duration, 0.0)

    def test_execution_result_is_channel_result(self):
        # ExecutionResult must be an alias for ChannelResult
        self.assertIs(ExecutionResult, ChannelResult)

    def test_base_executor_is_base_channel(self):
        self.assertIs(BaseExecutor, BaseChannel)

    def test_base_channel_is_abstract(self):
        with self.assertRaises(TypeError):
            BaseChannel()  # type: ignore[abstract]


class TestLocalChannel(unittest.TestCase):

    def test_test_connection_always_true(self):
        ch = LocalChannel()
        self.assertTrue(ch.test_connection("anything"))

    def test_execute_success(self):
        ch = LocalChannel()
        result = ch.execute("", "echo hello", timeout=5)
        self.assertTrue(result.success)
        self.assertIn("hello", result.output)

    def test_execute_failure(self):
        ch = LocalChannel()
        result = ch.execute("", "exit 7", timeout=5)
        self.assertFalse(result.success)
        self.assertIn("7", result.error)


class TestHTTPChannel(unittest.TestCase):

    def test_create(self):
        ch = HTTPChannel(timeout=5)
        self.assertEqual(ch.timeout, 5)

    @patch("urllib.request.urlopen")
    def test_execute_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ch = HTTPChannel(timeout=5)
        result = ch.execute("192.168.1.1", "test", port=80, method="GET", endpoint="/status")
        self.assertTrue(result.success)
        self.assertIn("ok", result.output)

    def test_send_action_fails_gracefully(self):
        action = MagicMock()
        action.name = "turn_on"
        action.method = "POST"
        action.endpoint = "/api/light"
        action.payload = '{"state":"on"}'
        action.headers = {}
        ch = HTTPChannel(timeout=1)
        result = ch.send_action("192.168.1.99", action, port=80)
        self.assertFalse(result.success)


class TestMQTTChannel(unittest.TestCase):

    def test_create(self):
        ch = MQTTChannel(broker_host="broker.local", broker_port=1883)
        self.assertEqual(ch.broker_host, "broker.local")
        self.assertEqual(ch.broker_port, 1883)


class TestSSHChannel(unittest.TestCase):

    def test_create(self):
        ch = SSHChannel(host="10.0.0.1", user="kali", port=22)
        self.assertEqual(ch.host, "10.0.0.1")
        self.assertEqual(ch.user, "kali")
        self.assertEqual(ch.port, 22)


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


class TestCommandDispatcher(unittest.TestCase):

    def test_dispatch_http_returns_success(self):
        client = MagicMock(spec=HTTPChannel)
        client.execute.return_value = ChannelResult(
            success=True, output='{"ok": true}', duration=0.1,
        )
        disp = CommandDispatcher()
        disp.register_http("192.168.1.10", client)

        from modules.benign_profiles.profile_schema import ActionDefinition
        action = ActionDefinition(
            name="turn_on", protocol="http", method="POST",
            endpoint="/api/light", payload='{"state":"on"}',
        )
        result = disp.dispatch(action=action, target_ip="192.168.1.10")
        self.assertIsInstance(result, DispatchResult)
        self.assertTrue(result.success)
        self.assertEqual(result.protocol, "http")
        self.assertIn("POST", result.detail)
        client.execute.assert_called_once()

    def test_dispatch_unknown_protocol(self):
        disp = CommandDispatcher()
        from modules.benign_profiles.profile_schema import ActionDefinition
        action = ActionDefinition(
            name="x", protocol="ftp", method="GET",
            endpoint="/", payload="",
        )
        result = disp.dispatch(action=action, target_ip="1.2.3.4")
        self.assertFalse(result.success)
        self.assertIn("unsupported protocol", result.error)


class TestLegacyAliases(unittest.TestCase):
    """Verifies that the old class names (SSHExecutor, HTTPExecutor, etc.)
    are aliases for the new channel classes. These are defined in
    modules.comms.__init__ for backwards compatibility."""

    def test_legacy_ssh_executor_is_ssh_channel(self):
        self.assertIs(SSHExecutor, SSHChannel)

    def test_legacy_http_executor_is_http_channel(self):
        self.assertIs(HTTPExecutor, HTTPChannel)

    def test_legacy_mqtt_executor_is_mqtt_channel(self):
        self.assertIs(MQTTExecutor, MQTTChannel)

    def test_legacy_base_executor_is_base_channel(self):
        self.assertIs(BaseExecutor, BaseChannel)

    def test_legacy_execution_result_is_channel_result(self):
        self.assertIs(ExecutionResult, ChannelResult)


if __name__ == "__main__":
    unittest.main()
