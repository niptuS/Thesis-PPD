"""
Entrada: None
Salida: CommandDispatcher class
Descripción: Routes action definitions to the appropriate communication
             channel (HTTP, MQTT, SSH or Local). Resolves {placeholder}
             templates with device-specific parameters.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass

from modules.benign_profiles.profile_schema import ActionDefinition
from modules.comms.ssh_channel import SSHChannel
from modules.comms.http_channel import HTTPChannel
from modules.comms.mqtt_channel import MQTTChannel

logger = logging.getLogger(__name__)

# Backwards-compatible aliases (old names used by external callers)
SSHClient = SSHChannel
HTTPClient = HTTPChannel
MQTTClient = MQTTChannel


@dataclass
class DispatchResult:
    """
    Entrada: success (bool), protocol (str), detail (str), error (str)
    Salida: DispatchResult instance
    Descripción: Result returned by CommandDispatcher.dispatch().
    """
    success: bool
    protocol: str = ""
    detail: str = ""
    error: str = ""


class CommandDispatcher:
    """Routes action definitions to the appropriate communication channel."""

    """
    Entrada: None
    Salida: None
    Descripción: Initializes the dispatcher with empty channel registries.
    """
    def __init__(self) -> None:
        self._ssh_clients: dict[str, SSHChannel] = {}
        self._http_clients: dict[str, HTTPChannel] = {}
        self._mqtt_client: MQTTChannel | None = None

    """
    Entrada: ip (str), client (SSHChannel)
    Salida: None
    Descripción: Registers an SSH channel for the given target IP.
    """
    def register_ssh(self, ip: str, client: SSHChannel) -> None:
        self._ssh_clients[ip] = client

    """
    Entrada: ip (str), client (HTTPChannel)
    Salida: None
    Descripción: Registers an HTTP channel for the given target IP.
    """
    def register_http(self, ip: str, client: HTTPChannel) -> None:
        self._http_clients[ip] = client

    """
    Entrada: client (MQTTChannel)
    Salida: None
    Descripción: Sets the shared MQTT channel used for MQTT dispatch.
    """
    def set_mqtt(self, client: MQTTChannel) -> None:
        self._mqtt_client = client

    """
    Entrada: action (ActionDefinition), target_ip (str), params (dict | None), device_id (str)
    Salida: DispatchResult
    Descripción: Execute an action on a target device via the matching channel.
    """
    def dispatch(self, action: ActionDefinition, target_ip: str,
                 params: dict | None = None, device_id: str = "") -> DispatchResult:
        params = params or {}
        params["device_id"] = device_id or target_ip.replace(".", "_")

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

    """
    Entrada: ip (str), method (str), endpoint (str), payload (str)
    Salida: DispatchResult
    Descripción: Dispatches an HTTP request to the channel for the given IP.
    """
    def _dispatch_http(self, ip: str, method: str, endpoint: str,
                       payload: str) -> DispatchResult:
        client = self._http_clients.get(ip)
        if client is None:
            client = HTTPChannel(timeout=10)
            self._http_clients[ip] = client
        result = client.execute(
            target_ip=ip, command="",
            method=method, endpoint=endpoint, payload=payload,
        )
        return DispatchResult(
            success=result.success, protocol="http",
            detail=f"{method} {endpoint}",
            error=result.error,
        )

    """
    Entrada: method (str), topic (str), payload (str)
    Salida: DispatchResult
    Descripción: Dispatches an MQTT publish to the shared MQTT channel.
    """
    def _dispatch_mqtt(self, method: str, topic: str, payload: str) -> DispatchResult:
        if self._mqtt_client is None:
            return DispatchResult(success=False, protocol="mqtt", error="MQTT not connected")
        if method.upper() == "PUB":
            result = self._mqtt_client.execute(
                target_ip="", command="", topic=topic, payload=payload,
            )
            return DispatchResult(success=result.success, protocol="mqtt",
                                  detail=f"PUB {topic}", error=result.error)
        return DispatchResult(success=False, protocol="mqtt", error=f"unsupported method: {method}")

    """
    Entrada: ip (str), command (str)
    Salida: DispatchResult
    Descripción: Dispatches an SSH command to the channel registered for the
                 given IP. Uses execute_rich() to get exit_code granularity.
    """
    def _dispatch_ssh(self, ip: str, command: str) -> DispatchResult:
        client = self._ssh_clients.get(ip)
        if client is None:
            return DispatchResult(success=False, protocol="ssh",
                                  error=f"no SSH client for {ip}")
        result = client.execute_rich(command)
        return DispatchResult(
            success=result.success, protocol="ssh",
            detail=f"exit={result.exit_code}: {result.stdout[:100]}",
            error=result.error or result.stderr[:200],
        )

    """
    Entrada: template (str), params (dict)
    Salida: str
    Descripción: Resolves {key} placeholders in the template using params.
    """
    @staticmethod
    def _resolve(template: str, params: dict) -> str:
        result = template
        for k, v in params.items():
            result = result.replace(f"{{{k}}}", str(v))
        return result

    """
    Entrada: None
    Salida: None
    Descripción: Closes all registered SSH and MQTT channels.
    """
    def close_all(self) -> None:
        for c in self._ssh_clients.values():
            close = getattr(c, "close", None)
            if callable(close):
                close()
        if self._mqtt_client:
            self._mqtt_client.close()
