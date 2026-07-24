"""
Entrada: None
Salida: Base channel primitives
Descripción: Defines the abstract BaseChannel and the unified ChannelResult
             dataclass used by every concrete channel (Local, HTTP, MQTT, SSH).
             ChannelResult is field-compatible with the legacy ExecutionResult
             so existing callers and tests keep working.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ChannelResult:
    """
    Entrada: success (bool), output (str), error (str), duration (float)
    Salida: ChannelResult instance
    Descripción: Unified result for every channel operation. Field-compatible
                 with the legacy ExecutionResult so existing code keeps working.
    """
    success: bool
    output: str = ""
    error: str = ""
    duration: float = 0.0


# Legacy alias (modules.communication.executor_base.ExecutionResult)
ExecutionResult = ChannelResult


class BaseChannel(ABC):
    """
    Entrada: None
    Salida: BaseChannel abstract class
    Descripción: Abstract base every concrete channel inherits from. A channel
                 is anything that can deliver a command/payload to a target:
                 local subprocess, HTTP, MQTT or SSH.
    """

    """
    Entrada: target_ip (str), command (str), **kwargs
    Salida: ChannelResult
    Descripción: Abstract method — deliver a command/payload to the target.
    """
    @abstractmethod
    def execute(self, target_ip: str, command: str, **kwargs) -> ChannelResult:
        ...

    """
    Entrada: target_ip (str)
    Salida: bool
    Descripción: Abstract method — test connectivity to the target.
    """
    @abstractmethod
    def test_connection(self, target_ip: str) -> bool:
        ...
