"""
Command Dispatcher — routes actions to the correct communication client.
Resolves action templates with device-specific parameters.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass

from modules.benign_profiles.profile_schema import ActionDefinition
from modules.comms.ssh_client import SSHClient
from modules.comms.http_client import HTTPClient
from modules.comms.mqtt_client import MQTTClient

logger = logging.getLogger(__name__)


@dataclass
class DispatchResult:
    success: bool
    protocol: str = ""
    detail: str = ""
    error: str = ""


class CommandDispatcher:
    """Routes action definitions to the appropriate communication client."""

    def __init__(self) -> None:
        self._ssh_clients: dict[str, SSHClient] = {}   # ip → client
        self._http_clients: dict[str, HTTPClient] = {}  # ip → client
        self._mqtt_client: MQTTClient | None = None

    def register_ssh(self, ip: str, client: SSHClient) -> None:
        self._ssh_clients[ip] = client

    def register_http(self, ip: str, client: HTTPClient) -> None:
        self._http_clients[ip] = client

    def set_mqtt(self, client: MQTTClient) -> None:
        self._mqtt_client = client

    def dispatch(self, action: ActionDefinition, target_ip: str,
                 params: dict | None = None, device_id: str = "") -> DispatchResult:
        """Execute an action on a target device."""
        params = params or {}
        params["device_id"] = device_id or target_ip.replace(".", "_")

        # resolve templates
        endpoint = self._resolve(action.endpoint, params)
        payload = self._resolve(action.payload, params)

        protocol = action.protocol.lower()

        if protocol == "http":
            return self._dispatch_http(target_ip, action.method, endpoint, payload)
        elif protocol == "mqtt":
            return self._dispatch_mqtt(action.method, endpoint, payload)
        elif protocol == "ssh":
            return self._dispatch_ssh(target_ip, payload)
        else:
            return DispatchResult(success=False, protocol=protocol,
                                  error=f"unsupported protocol: {protocol}")

    def _dispatch_http(self, ip: str, method: str, endpoint: str,
                       payload: str) -> DispatchResult:
        client = self._http_clients.get(ip)
        if client is None:
            # auto-create with defaults
            client = HTTPClient(base_url=f"http://{ip}")
            self._http_clients[ip] = client
        result = client.request(method, endpoint, payload)
        return DispatchResult(
            success=result.success, protocol="http",
            detail=f"{method} {endpoint} → {result.status_code}",
            error=result.error,
        )

    def _dispatch_mqtt(self, method: str, topic: str, payload: str) -> DispatchResult:
        if self._mqtt_client is None:
            return DispatchResult(success=False, protocol="mqtt", error="MQTT not connected")
        if method.upper() == "PUB":
            result = self._mqtt_client.publish(topic, payload)
            return DispatchResult(success=result.success, protocol="mqtt",
                                  detail=f"PUB {topic}", error=result.error)
        return DispatchResult(success=False, protocol="mqtt", error=f"unsupported method: {method}")

    def _dispatch_ssh(self, ip: str, command: str) -> DispatchResult:
        client = self._ssh_clients.get(ip)
        if client is None:
            return DispatchResult(success=False, protocol="ssh",
                                  error=f"no SSH client for {ip}")
        result = client.execute(command)
        return DispatchResult(
            success=result.success, protocol="ssh",
            detail=f"exit={result.exit_code}: {result.stdout[:100]}",
            error=result.error or result.stderr[:200],
        )

    @staticmethod
    def _resolve(template: str, params: dict) -> str:
        result = template
        for k, v in params.items():
            result = result.replace(f"{{{k}}}", str(v))
        return result

    def close_all(self) -> None:
        for c in self._ssh_clients.values():
            c.close()
        if self._mqtt_client:
            self._mqtt_client.close()
