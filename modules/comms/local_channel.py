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
import os
from modules.comms.base import BaseChannel, ChannelResult

logger = logging.getLogger(__name__)

# Commands that produce massive output per second (flood attacks). For these
# we must NOT capture stdout/stderr — the pipe buffer (64 KB on Linux) fills
# up and blocks the process, which in turn blocks subprocess.run() and freezes
# the TUI. Redirect to /dev/null instead.
_HIGH_OUTPUT_PATTERNS = (
    "--flood",
    "aireplay-ng --deauth",
)


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
                 prefixes the command with sudo. For flood attacks (hping3
                 --flood, slowloris, aireplay-ng --deauth) output is redirected
                 to /dev/null to avoid pipe-buffer deadlocks that freeze the TUI.
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

        # Detect flood attacks that produce massive output — redirect to
        # /dev/null so the pipe buffer doesn't fill up and block.
        is_high_output = any(p in actual_cmd for p in _HIGH_OUTPUT_PATTERNS)
        if is_high_output:
            if platform.system() == "Windows":
                actual_cmd = f"{actual_cmd} > NUL 2>&1"
            else:
                actual_cmd = f"{actual_cmd} > /dev/null 2>&1"
            logger.info("High-output attack detected, redirecting to /dev/null")

        start = time.time()
        try:
            if is_high_output:
                # Don't capture output — let it go to /dev/null. This avoids
                # the pipe-buffer deadlock entirely.
                result = subprocess.run(
                    actual_cmd, shell=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout, check=False,
                )
                elapsed = time.time() - start
                # Exit code 124 = the `timeout` command killed the process
                # after its duration. For continuous attacks this is EXPECTED.
                # Exit code 137 = SIGKILL (from -k 2).
                if result.returncode in (0, 124, 137):
                    return ChannelResult(
                        success=True, output="", duration=elapsed,
                    )
                return ChannelResult(
                    success=False,
                    error=f"exit code {result.returncode}",
                    duration=elapsed,
                )
            else:
                # Normal capture for recon attacks (nmap, hydra, slowloris, etc.)
                result = subprocess.run(
                    actual_cmd, shell=True,
                    stdin=subprocess.DEVNULL,
                    capture_output=True, text=True,
                    timeout=timeout, check=False,
                )
                elapsed = time.time() - start
                if result.returncode in (0, 124, 137):
                    return ChannelResult(
                        success=True, output=result.stdout, duration=elapsed,
                    )
                # Show actual stderr if available — helps diagnose failures
                err = (result.stderr or "").strip()
                if not err:
                    err = (result.stdout or "").strip()
                if not err:
                    err = f"exit code {result.returncode}"
                # Truncate long errors
                if len(err) > 300:
                    err = err[:300] + "..."
                return ChannelResult(
                    success=False, output=result.stdout,
                    error=err, duration=elapsed,
                )
        except subprocess.TimeoutExpired:
            # This shouldn't happen for flood attacks (the `timeout` command
            # handles it), but just in case:
            return ChannelResult(
                success=True,  # treat as success — attack ran for its duration
                output="",
                error=f"subprocess timeout ({timeout}s) — attack likely completed",
                duration=time.time() - start,
            )
        except (OSError, ValueError) as exc:
            return ChannelResult(
                success=False, error=str(exc), duration=time.time() - start,
            )

    """
    Entrada: target_ip (str)
    Salida: bool
    Descripción: Always True for the local channel (the local machine is
                 always reachable from itself).
    """
    def test_connection(self, target_ip: str = "") -> bool:
        return True
