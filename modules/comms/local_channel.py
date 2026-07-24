"""
Entrada: None
Salida: LocalChannel class
Descripción: Local execution channel — runs a shell command on this machine
             via subprocess. Used for local attack execution and any local
             plugin fallback. Equivalent to running on a "localhost" channel.
"""
from __future__ import annotations
import subprocess
import time
import logging
from modules.comms.base import BaseChannel, ChannelResult

logger = logging.getLogger(__name__)


class LocalChannel(BaseChannel):
    """
    Entrada: None
    Salida: LocalChannel instance
    Descripción: Channel that runs commands on the local machine via subprocess.
    """

    """
    Entrada: target_ip (str), command (str), timeout (int), use_sudo (bool), **kwargs
    Salida: ChannelResult
    Descripción: Runs the command locally. If use_sudo is True on non-Windows,
                 prefixes the command with sudo.
    """
    def execute(self, target_ip: str, command: str, *,
                timeout: int = 120, use_sudo: bool = False,
                **kwargs) -> ChannelResult:
        import platform
        actual_cmd = command
        if use_sudo and platform.system() != "Windows":
            actual_cmd = f"sudo {command}"
        elif use_sudo:
            logger.warning("sudo not available on Windows; running without sudo")

        start = time.time()
        try:
            result = subprocess.run(
                actual_cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            elapsed = time.time() - start
            if result.returncode == 0:
                return ChannelResult(
                    success=True, output=result.stdout, duration=elapsed,
                )
            err = (result.stderr or "").strip() or f"exit code {result.returncode}"
            return ChannelResult(
                success=False, output=result.stdout, error=err, duration=elapsed,
            )
        except subprocess.TimeoutExpired:
            return ChannelResult(
                success=False, error=f"timeout ({timeout}s)",
                duration=time.time() - start,
            )
        except (OSError, ValueError) as exc:
            return ChannelResult(
                success=False, error=str(exc), duration=time.time() - start,
            )

    """
    Entrada: target_ip (str)
    Salida: bool
    Salida: Always True for the local channel (the local machine is always
            reachable from itself).
    """
    def test_connection(self, target_ip: str = "") -> bool:
        return True
