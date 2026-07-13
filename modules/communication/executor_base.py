"""Base class for all remote executors."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    success: bool
    output: str = ""
    error: str = ""
    duration: float = 0.0


class BaseExecutor(ABC):
    """
    Entrada: target_ip (str), command (str), **kwargs
    Salida: ExecutionResult
    Descripción: Abstract method to execute a command against a target.
    """
    @abstractmethod
    def execute(self, target_ip: str, command: str, **kwargs) -> ExecutionResult:
        ...

    """
    Entrada: target_ip (str)
    Salida: bool
    Descripción: Abstract method to test connectivity to a target.
    """
    @abstractmethod
    def test_connection(self, target_ip: str) -> bool:
        ...
