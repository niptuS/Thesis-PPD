"""
SSH Executor — connects to remote machines via paramiko.
Handles sudo with PTY (pseudo-terminal) for root commands.
"""
from __future__ import annotations
import subprocess
import time
import logging
from modules.communication.executor_base import BaseExecutor, ExecutionResult

logger = logging.getLogger(__name__)


class SSHExecutor(BaseExecutor):
    def __init__(self, host: str, user: str = "kali", port: int = 22,
                 key_file: str = "", password: str = ""):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.password = password
        self._use_paramiko = self._check_paramiko()

    @staticmethod
    def _check_paramiko() -> bool:
        try:
            return True
        except ImportError:
            return False

    def execute(self, target_ip: str, command: str, timeout: int = 120,
                use_sudo: bool = False, **kwargs) -> ExecutionResult:
        """Execute command on remote host. If use_sudo=True, runs with sudo via PTY."""
        logger.info("SSH exec: %s@%s → %s", self.user, self.host, command[:80])
        if self._use_paramiko:
            if use_sudo and self.password:
                return self._exec_paramiko_sudo(command, timeout)
            return self._exec_paramiko(command, timeout)
        return self._exec_sshpass(command, timeout)

    def test_connection(self, target_ip: str = "") -> tuple[bool, str]:
        method = "paramiko" if self._use_paramiko else "sshpass"
        result = self.execute("", "echo __SSH_OK__", timeout=15)
        ok = result.success and "__SSH_OK__" in (result.output or "")
        detail = ""
        if not ok:
            detail = result.error or result.output or "sin respuesta"
            detail = f"[{method}] {detail}"
        return ok, detail

    # ── paramiko normal (no sudo) ───────────────────────────────

    def _exec_paramiko(self, command: str, timeout: int) -> ExecutionResult:
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
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()
            client.close()
            elapsed = time.time() - start
            if exit_code == 0:
                return ExecutionResult(success=True, output=out, duration=elapsed)
            return ExecutionResult(success=False, output=out, error=err or f"exit {exit_code}", duration=elapsed)
        except (OSError, IOError, TimeoutError, RuntimeError) as e:
            return ExecutionResult(success=False, error=str(e), duration=time.time() - start)

    # ── paramiko with sudo via PTY ──────────────────────────────

    def _exec_paramiko_sudo(self, command: str, timeout: int) -> ExecutionResult:
        """Run command with sudo using interactive PTY session."""
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

            # open interactive shell via PTY
            channel = client.get_transport().open_session()
            channel.get_pty()
            channel.invoke_shell()
            channel.settimeout(timeout)

            import time as _t
            _t.sleep(0.5)
            # drain any welcome message
            if channel.recv_ready():
                channel.recv(4096)

            # send sudo su with password
            channel.send("sudo su\n")
            _t.sleep(1)
            # check if sudo asks for password
            if channel.recv_ready():
                prompt = channel.recv(4096).decode("utf-8", errors="replace")
                if "password" in prompt.lower():
                    channel.send(f"{self.password}\n")
                    _t.sleep(1)
                    if channel.recv_ready():
                        channel.recv(4096)  # drain response

            # now we're root — run the command
            channel.send(f"{command}\n")

            # wait for command to finish or timeout
            output_chunks = []
            deadline = time.time() + timeout
            while time.time() < deadline:
                _t.sleep(0.5)
                if channel.recv_ready():
                    chunk = channel.recv(8192).decode("utf-8", errors="replace")
                    output_chunks.append(chunk)
                if channel.exit_status_ready():
                    break

            # exit sudo shell
            channel.send("exit\n")
            _t.sleep(0.3)
            channel.close()
            client.close()
            elapsed = time.time() - start

            raw_out = "".join(output_chunks)
            # clean control chars and prompts
            lines = raw_out.split("\n")
            clean = [ln for ln in lines
                     if not ln.startswith("[sudo]")
                     and "password" not in ln.lower()
                     and not ln.strip().startswith("root@")
                     and not ln.strip().startswith("$")
                     and not ln.strip().startswith("#")]
            clean_out = "\n".join(clean).strip()

            return ExecutionResult(success=True, output=clean_out[:500], duration=elapsed)
        except (OSError, IOError, TimeoutError, RuntimeError) as e:
            return ExecutionResult(success=False, error=str(e), duration=time.time() - start)

    # ── sshpass fallback ────────────────────────────────────────

    def _exec_sshpass(self, command: str, timeout: int) -> ExecutionResult:
        start = time.time()
        if not self.password:
            return ExecutionResult(success=False, error="Sin password y sin paramiko")
        cmd = [
            "sshpass", "-p", self.password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10", "-p", str(self.port),
            f"{self.user}@{self.host}", command,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            elapsed = time.time() - start
            if result.returncode == 0:
                return ExecutionResult(success=True, output=result.stdout.strip(), duration=elapsed)
            return ExecutionResult(success=False, error=result.stderr.strip() or f"exit {result.returncode}",
                                   duration=elapsed)
        except FileNotFoundError:
            return ExecutionResult(success=False, error="sshpass no instalado + paramiko no disponible")
        except subprocess.TimeoutExpired:
            return ExecutionResult(success=False, error=f"timeout ({timeout}s)")
        except (OSError, IOError, TimeoutError) as e:
            return ExecutionResult(success=False, error=str(e))

    def run_attack(self, attack_name: str, target_ip: str, duration: int = 30,
                   intensity: str = "medium", **kwargs) -> ExecutionResult:
        from modules.attacks import get_attack_class
        attack_def = get_attack_class(attack_name)
        if attack_def is None:
            return ExecutionResult(success=False, error=f"'{attack_name}' no encontrado")
        cmd = attack_def.build_command(target_ip=target_ip, duration=duration, port=80)
        return self.execute(target_ip, cmd, timeout=duration + 30,
                            use_sudo=attack_def.requires_root,
                            )
