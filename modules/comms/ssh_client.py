"""
SSH Client — executes commands on remote machines (Kali Linux).
Uses paramiko for SSH communication.
"""
from __future__ import annotations
import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SSHResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str = ""


class SSHClient:
    """Manages SSH connections to a remote host (e.g., Kali Linux)."""

    def __init__(self, host: str, port: int = 22,
                 username: str = "kali", password: str = "",
                 key_path: str = "") -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self._client = None

    def connect(self) -> bool:
        try:
            import paramiko
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = {"hostname": self.host, "port": self.port, "username": self.username}
            if self.key_path:
                kwargs["key_filename"] = self.key_path
            elif self.password:
                kwargs["password"] = self.password
            self._client.connect(**kwargs, timeout=10)
            logger.info("SSH connected to %s@%s:%d", self.username, self.host, self.port)
            return True
        except ImportError:
            logger.warning("paramiko not installed, falling back to subprocess ssh")
            return True  # will use subprocess
        except Exception as exc:
            logger.error("SSH connection failed: %s", exc)
            self._client = None
            return False

    def execute(self, command: str, timeout: int = 30) -> SSHResult:
        """Execute a command on the remote host."""
        # try paramiko first
        if self._client is not None:
            try:
                _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
                exit_code = stdout.channel.recv_exit_status()
                return SSHResult(
                    success=(exit_code == 0),
                    stdout=stdout.read().decode(errors="replace"),
                    stderr=stderr.read().decode(errors="replace"),
                    exit_code=exit_code,
                )
            except Exception as exc:
                return SSHResult(success=False, error=str(exc))

        # fallback: subprocess ssh
        try:
            ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                       "-o", "ConnectTimeout=10"]
            if self.key_path:
                ssh_cmd.extend(["-i", self.key_path])
            ssh_cmd.append(f"{self.username}@{self.host}")
            ssh_cmd.append(command)
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout, check=False)
            return SSHResult(
                success=(result.returncode == 0),
                stdout=result.stdout, stderr=result.stderr,
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return SSHResult(success=False, error="timeout")
        except Exception as exc:
            return SSHResult(success=False, error=str(exc))

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def is_connected(self) -> bool:
        if self._client:
            try:
                transport = self._client.get_transport()
                return transport is not None and transport.is_active()
            except Exception:
                return False
        return False
