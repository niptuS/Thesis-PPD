"""
Entrada: None
Salida: SSHChannel class
Descripción: SSH channel — executes commands on a remote machine (typically
             Kali Linux) via paramiko, with sudo-via-PTY support. Merges the
             previous SSHExecutor (sudo/PTY logic) and SSHClient (paramiko
             fallback to subprocess ssh).
"""
from __future__ import annotations
import subprocess
import time
import logging
from dataclasses import dataclass
from modules.comms.base import BaseChannel, ChannelResult

logger = logging.getLogger(__name__)


@dataclass
class SSHResult:
    """
    Entrada: success (bool), stdout (str), stderr (str), exit_code (int), error (str)
    Salida: SSHResult instance
    Descripción: Rich SSH-specific result with separate stdout/stderr/exit_code,
                 kept for callers that need exit-code granularity.
    """
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str = ""


class SSHChannel(BaseChannel):
    """
    Entrada: host (str), user (str), port (int), key_file (str), password (str)
    Salida: None
    Descripción: Initializes the SSH channel with connection parameters and
                 paramiko availability.
    """

    def __init__(self, host: str, user: str = "kali", port: int = 22,
                 key_file: str = "", password: str = ""):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.password = password
        self._use_paramiko = self._check_paramiko()

    """
    Entrada: None
    Salida: bool
    Descripción: Checks whether paramiko is available for SSH execution.
    """
    @staticmethod
    def _check_paramiko() -> bool:
        try:
            import paramiko  # noqa: F401
            return True
        except ImportError:
            return False

    """
    Entrada: target_ip (str), command (str), timeout (int), use_sudo (bool), **kwargs
    Salida: ChannelResult
    Descripción: Execute command on remote host. If use_sudo=True, runs with
                 sudo via PTY. Falls back to sshpass if paramiko is unavailable.
    """
    def execute(self, target_ip: str, command: str, timeout: int = 120,
                use_sudo: bool = False, **kwargs) -> ChannelResult:
        logger.info("SSH exec: %s@%s → %s", self.user, self.host, command[:80])
        if self._use_paramiko:
            if use_sudo and self.password:
                return self._exec_paramiko_sudo(command, timeout)
            return self._exec_paramiko(command, timeout)
        return self._exec_sshpass(command, timeout)

    """
    Entrada: target_ip (str)
    Salida: tuple[bool, str]
    Descripción: Tests SSH connectivity and returns a status flag with optional
                 detail string.
    """
    def test_connection(self, target_ip: str = "") -> tuple:  # type: ignore[override]
        method = "paramiko" if self._use_paramiko else "sshpass"
        result = self.execute("", "echo __SSH_OK__", timeout=15)
        ok = result.success and "__SSH_OK__" in (result.output or "")
        detail = ""
        if not ok:
            detail = result.error or result.output or "no response"
            detail = f"[{method}] {detail}"
        return ok, detail

    """
    Entrada: command (str), timeout (int)
    Salida: ChannelResult
    Descripción: Executes a command via paramiko (non-sudo).
    """
    def _exec_paramiko(self, command: str, timeout: int) -> ChannelResult:
        start = time.time()
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": self.host, "port": self.port,
                "username": self.user, "timeout": min(timeout, 15),
                "allow_agent": False, "look_for_keys": False,
            }
            if self.key_file:
                connect_kwargs["key_filename"] = self.key_file
            if self.password:
                connect_kwargs["password"] = self.password
            client.connect(**connect_kwargs)

            # For flood attacks, redirect output to /dev/null on the remote
            # host to avoid paramiko's stdout.read() blocking on a massive
            # output stream (pipe-buffer deadlock).
            is_high_output = any(
                p in command for p in (
                    "--flood", "slowloris", "aireplay-ng --deauth",
                )
            )
            if is_high_output:
                command = f"{command} > /dev/null 2>&1"

            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            # For high-output attacks, don't read stdout/stderr — just get
            # the exit code. Reading would block on the massive output.
            if is_high_output:
                exit_code = stdout.channel.recv_exit_status()
                out = ""
                err = ""
            else:
                out = stdout.read().decode("utf-8", errors="replace").strip()
                err = stderr.read().decode("utf-8", errors="replace").strip()
                exit_code = stdout.channel.recv_exit_status()
            client.close()
            elapsed = time.time() - start
            # Exit code 124 = the `timeout` command killed the process after
            # its duration. 137 = SIGKILL (from -k 2). Both are expected for
            # continuous flood attacks.
            if exit_code in (0, 124, 137):
                return ChannelResult(success=True, output=out, duration=elapsed)
            return ChannelResult(
                success=False, output=out,
                error=err or f"exit {exit_code}", duration=elapsed,
            )
        except (OSError, IOError, TimeoutError, RuntimeError) as e:
            return ChannelResult(
                success=False, error=str(e), duration=time.time() - start,
            )

    """
    Entrada: command (str), timeout (int)
    Salida: ChannelResult
    Descripción: Run command with sudo using an interactive PTY session.
    """
    def _exec_paramiko_sudo(self, command: str, timeout: int) -> ChannelResult:
        start = time.time()
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": self.host, "port": self.port,
                "username": self.user, "timeout": min(timeout, 15),
                "allow_agent": False, "look_for_keys": False,
            }
            if self.key_file:
                connect_kwargs["key_filename"] = self.key_file
            if self.password:
                connect_kwargs["password"] = self.password
            client.connect(**connect_kwargs)

            channel = client.get_transport().open_session()
            channel.get_pty()
            channel.invoke_shell()
            channel.settimeout(timeout)

            time.sleep(0.5)
            if channel.recv_ready():
                channel.recv(4096)

            channel.send("sudo su\n")
            time.sleep(1)
            if channel.recv_ready():
                prompt = channel.recv(4096).decode("utf-8", errors="replace")
                if "password" in prompt.lower():
                    channel.send(f"{self.password}\n")
                    time.sleep(1)
                    if channel.recv_ready():
                        channel.recv(4096)

            channel.send(f"{command}\n")

            output_chunks = []
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.5)
                if channel.recv_ready():
                    chunk = channel.recv(8192).decode("utf-8", errors="replace")
                    output_chunks.append(chunk)
                if channel.exit_status_ready():
                    break

            channel.send("exit\n")
            time.sleep(0.3)
            channel.close()
            client.close()
            elapsed = time.time() - start

            raw_out = "".join(output_chunks)
            lines = raw_out.split("\n")
            clean = [ln for ln in lines
                     if not ln.startswith("[sudo]")
                     and "password" not in ln.lower()
                     and not ln.strip().startswith("root@")
                     and not ln.strip().startswith("$")
                     and not ln.strip().startswith("#")]
            clean_out = "\n".join(clean).strip()

            return ChannelResult(success=True, output=clean_out[:500], duration=elapsed)
        except (OSError, IOError, TimeoutError, RuntimeError) as e:
            return ChannelResult(
                success=False, error=str(e), duration=time.time() - start,
            )

    """
    Entrada: command (str), timeout (int)
    Salida: ChannelResult
    Descripción: Executes a command via sshpass as a paramiko fallback.
    """
    def _exec_sshpass(self, command: str, timeout: int) -> ChannelResult:
        start = time.time()
        if not self.password:
            return ChannelResult(
                success=False, error="No password and no paramiko",
            )

        # For flood attacks, redirect remote output to /dev/null to avoid
        # the local subprocess.run() blocking on massive captured output.
        is_high_output = any(
            p in command for p in (
                "--flood", "slowloris", "aireplay-ng --deauth",
            )
        )
        if is_high_output:
            command = f"{command} > /dev/null 2>&1"

        cmd = [
            "sshpass", "-p", self.password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10", "-p", str(self.port),
            f"{self.user}@{self.host}", command,
        ]
        try:
            if is_high_output:
                result = subprocess.run(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout, check=False,
                )
                elapsed = time.time() - start
                if result.returncode in (0, 124, 137):
                    return ChannelResult(
                        success=True, output="", duration=elapsed,
                    )
                return ChannelResult(
                    success=False,
                    error=f"exit code {result.returncode}",
                    duration=elapsed,
                )
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            elapsed = time.time() - start
            # Exit code 124 = the `timeout` command killed the process after
            # its duration. 137 = SIGKILL. Both expected for flood attacks.
            if result.returncode in (0, 124, 137):
                return ChannelResult(
                    success=True, output=result.stdout.strip(), duration=elapsed,
                )
            return ChannelResult(
                success=False,
                error=result.stderr.strip() or f"exit {result.returncode}",
                duration=elapsed,
            )
        except FileNotFoundError:
            return ChannelResult(
                success=False,
                error="sshpass not installed + paramiko not available",
            )
        except subprocess.TimeoutExpired:
            # For flood attacks, subprocess timeout means the `timeout`
            # command didn't kill it fast enough — the attack still ran.
            if is_high_output:
                return ChannelResult(
                    success=True, output="",
                    duration=time.time() - start,
                )
            return ChannelResult(
                success=False, error=f"timeout ({timeout}s)",
            )
        except (OSError, IOError, TimeoutError) as e:
            return ChannelResult(success=False, error=str(e))

    """
    Entrada: attack_name (str), target_ip (str), duration (int), intensity (str), **kwargs
    Salida: ChannelResult
    Descripción: Looks up an attack by name and runs it on the remote host.
    """
    def run_attack(self, attack_name: str, target_ip: str, duration: int = 30,
                   intensity: str = "medium", **kwargs) -> ChannelResult:
        from modules.attacks import get_attack_class
        attack_def = get_attack_class(attack_name)
        if attack_def is None:
            return ChannelResult(success=False, error=f"'{attack_name}' not found")
        cmd = attack_def.build_command(target_ip=target_ip, duration=duration, port=80)
        return self.execute(
            target_ip, cmd, timeout=duration + 30,
            use_sudo=attack_def.requires_root,
        )

    # ── SSHResult-returning variant (used by tests and dispatcher) ─────────

    """
    Entrada: command (str), timeout (int)
    Salida: SSHResult
    Descripción: Executes a command via paramiko (or subprocess ssh fallback)
                 and returns a rich SSHResult with separate stdout/stderr/exit_code.
    """
    def execute_rich(self, command: str, timeout: int = 30) -> SSHResult:
        if self._use_paramiko:
            try:
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                kwargs = {
                    "hostname": self.host, "port": self.port,
                    "username": self.user,
                }
                if self.key_file:
                    kwargs["key_filename"] = self.key_file
                elif self.password:
                    kwargs["password"] = self.password
                client.connect(**kwargs, timeout=10)
                _, stdout, stderr = client.exec_command(command, timeout=timeout)
                exit_code = stdout.channel.recv_exit_status()
                result = SSHResult(
                    success=(exit_code == 0),
                    stdout=stdout.read().decode(errors="replace"),
                    stderr=stderr.read().decode(errors="replace"),
                    exit_code=exit_code,
                )
                client.close()
                return result
            except Exception as exc:
                return SSHResult(success=False, error=str(exc))

        try:
            ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                       "-o", "ConnectTimeout=10"]
            if self.key_file:
                ssh_cmd.extend(["-i", self.key_file])
            ssh_cmd.append(f"{self.user}@{self.host}")
            ssh_cmd.append(command)
            result = subprocess.run(
                ssh_cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            return SSHResult(
                success=(result.returncode == 0),
                stdout=result.stdout, stderr=result.stderr,
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return SSHResult(success=False, error="timeout")
        except Exception as exc:
            return SSHResult(success=False, error=str(exc))
