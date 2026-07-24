"""
Entrada: None
Salida: Backwards-compatibility shim
Descripción: Legacy compatibility shim — modules.communication has been merged
             into modules.comms. This file re-exports the new symbols under
             the old names so existing imports keep working. New code should
             import directly from modules.comms.
"""
from __future__ import annotations

from modules.comms.base import BaseChannel, ChannelResult, ExecutionResult
from modules.comms.ssh_channel import SSHChannel as SSHExecutor
from modules.comms.http_channel import HTTPChannel as HTTPExecutor
from modules.comms.mqtt_channel import MQTTChannel as MQTTExecutor
from modules.comms.attacker_profile import AttackerProfile
from modules.comms.base import BaseChannel as BaseExecutor

__all__ = [
    "BaseExecutor", "BaseChannel", "ExecutionResult", "ChannelResult",
    "SSHExecutor", "SSHChannel",
    "HTTPExecutor", "HTTPChannel",
    "MQTTExecutor", "MQTTChannel",
    "AttackerProfile",
]
