"""
Entrada: None
Salida: Unified communications layer (modules.comms)
Descripción: Single communication layer for local, HTTP, MQTT and SSH channels.
             Replaces the previous split between modules/communication (executors)
             and modules/comms (clients). Backwards-compatible re-exports are
             provided so existing callers keep working.
"""
from __future__ import annotations

from modules.comms.base import (
    BaseChannel,
    ChannelResult,
    ExecutionResult,        # legacy alias for ChannelResult
)
from modules.comms.local_channel import LocalChannel
from modules.comms.http_channel import HTTPChannel, HTTPResult
from modules.comms.mqtt_channel import MQTTChannel, MQTTResult
from modules.comms.ssh_channel import SSHChannel, SSHResult
from modules.comms.attacker_profile import AttackerProfile
from modules.comms.dispatcher import (
    CommandDispatcher,
    DispatchResult,
)

# ── Legacy aliases (modules.communication compatibility shim) ───────────────
BaseExecutor = BaseChannel
SSHExecutor = SSHChannel
HTTPExecutor = HTTPChannel
MQTTExecutor = MQTTChannel

__all__ = [
    # New API
    "BaseChannel", "ChannelResult",
    "LocalChannel", "HTTPChannel", "MQTTChannel", "SSHChannel",
    "HTTPResult", "MQTTResult", "SSHResult",
    "AttackerProfile",
    "CommandDispatcher", "DispatchResult",
    # Legacy aliases
    "BaseExecutor", "ExecutionResult",
    "SSHExecutor", "HTTPExecutor", "MQTTExecutor",
]
