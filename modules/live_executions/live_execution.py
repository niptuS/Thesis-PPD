"""
Live Execution Engine — SH-DATASET
Coordina captura PCAP, ejecución de eventos del timeline,
y generación de flujos etiquetados con NFStream al finalizar.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

# remote execution
from modules.communication.ssh_executor import SSHExecutor
from modules.communication.http_executor import HTTPExecutor


class ExecState(Enum):
    IDLE = "IDLE"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    FINISHED = "FINISHED"
    ABORTED = "ABORTED"
    ERROR = "ERROR"


@dataclass
class ExecSnapshot:
    state: str = "IDLE"
    started_at: str = "—"
    elapsed_s: float = 0.0
    remaining_s: float = 0.0
    planned_s: float = 0.0
    pcap_path: str = ""
    metadata_path: str = ""
    flows_path: str = ""
    active_benign: str = "—"
    active_attack: str = "—"
    next_event: str = "—"
    capture_ok: bool = False
    logger_ok: bool = True
    events_fired: int = 0
    events_total: int = 0
    flows_generated: int = 0
    error: str = ""


class LiveExecutionEngine:

    def __init__(self) -> None:
        self._state = ExecState.IDLE
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()

        self._start_time: float = 0.0
        self._end_time: float = 0.0       # freezes elapsed on stop
        self._planned_s: float = 0.0
        self._pcap_proc: Optional[subprocess.Popen] = None
        self._pcap_path: str = ""
        self._meta_path: str = ""
        self._flows_path: str = ""
        self._events: list[dict] = []
        self._fired: int = 0
        self._active_benign: str = "—"
        self._active_attack: str = "—"
        self._next_event: str = "—"
        self._flows_count: int = 0
        self._error: str = ""
        # PCAP rotation: split files by size (KB)
        # configurable via config.pcap_max_size_kb (default 10240 = 10 MB)
        self._pcap_max_size_kb: int = 512000  # 500 MB default
        self._capture_ok: bool = False
        self._iface: str = ""
        self._config: Any = None

        # device IP → role map for flow tagging
        self._device_map: dict[str, str] = {}

        self._log_fn: Optional[Callable[[str, str], None]] = None
        self._ssh_password: str = ""
        self._capture_benign: bool = True
        self._attack_mode: str = "local"
        self._attacker_profiles: dict = {}
        self._get_executor = None  # callback: ip → SSHExecutor

        # remote executors
        self._ssh_executor: Optional[SSHExecutor] = None
        self._http_executor: HTTPExecutor = HTTPExecutor(timeout=10)
        self._profiles: list = []  # BenignProfile list for IoT commands

    # ── public API ──────────────────────────────────────────────

    def set_logger(self, fn: Callable[[str, str], None]) -> None:
        self._log_fn = fn

    def snapshot(self) -> ExecSnapshot:
        with self._lock:
            # use frozen end_time if execution stopped, else live time
            if self._end_time > 0:
                elapsed = self._end_time - self._start_time
            elif self._start_time > 0:
                elapsed = time.time() - self._start_time
            else:
                elapsed = 0.0

            remaining = max(0.0, self._planned_s - elapsed)

            return ExecSnapshot(
                state=self._state.value,
                started_at=(
                    datetime.fromtimestamp(self._start_time).strftime("%H:%M:%S")
                    if self._start_time else "—"
                ),
                elapsed_s=elapsed,
                remaining_s=remaining,
                planned_s=self._planned_s,
                pcap_path=os.path.basename(self._pcap_path) if self._pcap_path else "",
                metadata_path=os.path.basename(self._meta_path) if self._meta_path else "",
                flows_path=os.path.basename(self._flows_path) if self._flows_path else "",
                active_benign=self._active_benign,
                active_attack=self._active_attack,
                next_event=self._next_event,
                capture_ok=self._capture_ok,
                logger_ok=True,
                events_fired=self._fired,
                events_total=len(self._events),
                flows_generated=self._flows_count,
                error=self._error,
            )

    def start(
        self,
        config,
        iface: str,
        output_dir: str,
        events: list[dict] | None = None,
        devices: list | None = None,
        capture_benign: bool = True,
        profiles: list | None = None,
    ) -> bool:
        if self._state not in (ExecState.IDLE, ExecState.FINISHED, ExecState.ABORTED, ExecState.ERROR):
            return False

        self._config = config
        self._capture_benign = capture_benign
        self._iface = iface
        exp_id = getattr(config, "experiment_id", "EXP")
        run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        os.makedirs(output_dir, exist_ok=True)
        pcap_dir = os.path.join(output_dir, "pcap")
        meta_dir = os.path.join(output_dir, "metadata")
        flows_dir = os.path.join(output_dir, "flows")
        logs_dir = os.path.join(output_dir, "logs")
        for d in (pcap_dir, meta_dir, flows_dir, logs_dir):
            os.makedirs(d, exist_ok=True)

        self._pcap_path = os.path.join(pcap_dir, f"{exp_id}_{run_ts}.pcap")
        self._meta_path = os.path.join(meta_dir, f"{exp_id}_{run_ts}_metadata.json")
        self._flows_path = os.path.join(flows_dir, f"{exp_id}_{run_ts}_flows.csv")

        duration_str = getattr(config, "planned_duration", "00:30:00")
        self._planned_s = self._parse_duration(duration_str)
        self._events = events or []
        self._fired = 0
        self._flows_count = 0
        self._error = ""
        self._end_time = 0.0
        self._active_benign = "—"
        self._active_attack = "—"
        self._next_event = self._format_next_event()

        # setup attacker execution mode
        attacker_cfg = getattr(config, "attacker", None)
        self._attack_mode = getattr(attacker_cfg, "mode", "local") if attacker_cfg else "local"

        if self._attack_mode == "ssh" and attacker_cfg and getattr(attacker_cfg, "ip", ""):
            self._ssh_executor = SSHExecutor(
                host=attacker_cfg.ip,
                user=getattr(attacker_cfg, "ssh_user", "kali"),
                port=getattr(attacker_cfg, "ssh_port", 22),
                key_file=getattr(attacker_cfg, "ssh_key", ""),
                password=self._ssh_password,
            )
            self._log(f"Modo SSH → Kali en {attacker_cfg.ip} ({attacker_cfg.ssh_user})", "INFO")
        else:
            self._ssh_executor = None
            if self._attack_mode == "local":
                self._log("Modo local — ataques se ejecutan en esta máquina", "INFO")
            else:
                self._log("Modo SSH sin IP configurada — ataques solo se registran", "WARN")

        # build IP → role map from registered devices
        self._device_map = {}
        if devices:
            for dev in devices:
                ip = getattr(dev, "ip", "")
                role = getattr(dev, "role", "unknown")
                if ip:
                    self._device_map[ip] = role
        # store benign profiles for IoT command dispatch
        self._profiles = profiles or []
        if self._profiles:
            self._log(f"Perfiles benignos: {len(self._profiles)} cargados", "INFO")

            self._log(
                f"Device map: {len(self._device_map)} dispositivos "
                f"({sum(1 for r in self._device_map.values() if r == 'target')} targets, "
                f"{sum(1 for r in self._device_map.values() if r == 'attacker')} attackers, "
                f"{sum(1 for r in self._device_map.values() if r == 'benign')} benign)",
                "INFO",
            )

        self._cancel.clear()
        self._pause.set()

        self._state = ExecState.STARTING
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        return True

    def pause(self) -> None:
        if self._state == ExecState.RUNNING:
            self._pause.clear()
            self._state = ExecState.PAUSED
            self._log("Ejecución pausada", "WARN")

    def resume(self) -> None:
        if self._state == ExecState.PAUSED:
            self._pause.set()
            self._state = ExecState.RUNNING
            self._log("Ejecución reanudada", "INFO")

    def abort(self) -> None:
        if self._state in (ExecState.RUNNING, ExecState.PAUSED, ExecState.STARTING):
            self._cancel.set()
            self._pause.set()
            self._log("Abortando ejecución…", "WARN")

    @property
    def is_active(self) -> bool:
        return self._state in (ExecState.RUNNING, ExecState.PAUSED, ExecState.STARTING)

    # ── main loop ───────────────────────────────────────────────

    def _run_loop(self) -> None:
        try:
            self._start_capture()
            self._start_time = time.time()
            self._state = ExecState.RUNNING
            self._log("Escenario iniciado", "INFO")
            self._log(f"Captura PCAP: {os.path.basename(self._pcap_path)}", "INFO")

            # filter to pending events only (skip completed/skipped)
            sorted_events = sorted(
                [e for e in self._events if e.get("status", "queued") in ("queued", "expired")],
                key=lambda e: e.get("offset_s", 0),
            )
            total_events = len(self._events)
            pending_count = len(sorted_events)
            already_done = total_events - pending_count
            event_idx = 0
            self._fired = already_done

            if pending_count < total_events:
                self._log(
                    f"Continuando: {already_done} completados, {pending_count} pendientes",
                    "INFO",
                )

            while not self._cancel.is_set():
                self._pause.wait()
                if self._cancel.is_set():
                    break

                elapsed = time.time() - self._start_time

                if self._planned_s > 0 and elapsed >= self._planned_s:
                    self._log("Duración planificada alcanzada", "INFO")
                    break

                while event_idx < len(sorted_events):
                    ev = sorted_events[event_idx]
                    if ev.get("offset_s", 0) <= elapsed:
                        self._fire_event(ev)
                        ev["status"] = "completed"
                        event_idx += 1
                        self._fired = already_done + event_idx
                        if event_idx < len(sorted_events):
                            self._next_event = self._format_event_label(sorted_events[event_idx])
                        else:
                            self._next_event = "—"
                    else:
                        break

                self._capture_ok = self._pcap_proc is not None and self._pcap_proc.poll() is None
                time.sleep(0.5)

            # ── freeze timer ────────────────────────────────────
            self._end_time = time.time()

            if self._cancel.is_set():
                self._state = ExecState.ABORTED
                self._log("Ejecución abortada por el usuario", "WARN")
            else:
                self._state = ExecState.STOPPING
                self._fired = len(sorted_events)

            self._stop_capture()
            # wait for PCAP to flush to disk
            time.sleep(2)
            self._log("Procesando capturas…", "INFO")

            # NFStream
            pcap_files = self._find_pcap_files()
            if pcap_files:
                total_size = sum(os.path.getsize(f) for f in pcap_files)
                if total_size > 0:
                    self._extract_flows(pcap_files)
                else:
                    self._log(f"PCAP vacío ({total_size} bytes)", "WARN")
            else:
                self._log("PCAP no encontrado", "WARN")

            self._generate_metadata()
            self._save_execution_log()

            if self._state != ExecState.ABORTED:
                self._state = ExecState.FINISHED
                self._log("Ejecución completada", "OK")
            else:
                self._log("Ejecución finalizada (abortada)", "WARN")

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._end_time = time.time()
            self._error = str(exc)
            self._state = ExecState.ERROR
            self._log(f"Error fatal: {exc}", "ERROR")
            self._stop_capture()

    # ── capture ─────────────────────────────────────────────────

    def _find_pcap_files(self) -> list[str]:
        """Find all PCAP files from this capture (including rotated parts)."""
        pcap_dir = os.path.dirname(self._pcap_path)
        base = os.path.basename(self._pcap_path).rsplit(".", 1)[0]
        files = []
        if os.path.exists(self._pcap_path):
            files.append(self._pcap_path)
        # rotated files: base_00001_timestamp.pcap, base_00002_timestamp.pcap
        if os.path.isdir(pcap_dir):
            for fn in sorted(os.listdir(pcap_dir)):
                full = os.path.join(pcap_dir, fn)
                if full == self._pcap_path:
                    continue
                if fn.startswith(base) and fn.endswith((".pcap", ".pcapng")):
                    files.append(full)
        return files

    def _find_capture_tool(self) -> str:
        """Find tcpdump, tshark, or dumpcap on the system."""
        import shutil
        import platform
        # Linux: tcpdump is standard
        if platform.system() != "Windows":
            for tool in ["tcpdump", "dumpcap", "tshark"]:
                if shutil.which(tool):
                    return tool
            return ""
        # Windows: check Wireshark install paths
        for tool in ["tshark", "dumpcap"]:
            if shutil.which(tool):
                return tool
        # search common Wireshark paths on Windows
        import glob
        for pattern in [
            r"C:\Program Files\Wireshark\*.exe",
            r"C:\Program Files (x86)\Wireshark\*.exe",
        ]:
            for path in glob.glob(pattern):
                name = os.path.basename(path).lower()
                if "tshark" in name:
                    return path
                if "dumpcap" in name:
                    return path
        return ""

    def _start_capture(self) -> None:
        if not self._iface:
            self._log("Sin interfaz de captura configurada", "WARN")
            self._capture_ok = False
            return

        # ensure output directories exist with write permissions
        self._pcap_path = os.path.abspath(self._pcap_path)
        self._flows_path = os.path.abspath(self._flows_path)
        self._meta_path = os.path.abspath(self._meta_path)
        for d in (os.path.dirname(self._pcap_path),
                  os.path.dirname(self._flows_path),
                  os.path.dirname(self._meta_path)):
            os.makedirs(d, exist_ok=True)
            try:
                os.chmod(d, 0o777)
            except OSError:
                pass


        tool = self._find_capture_tool()
        if not tool:
            self._log(
                "No se encontró herramienta de captura (tcpdump/tshark/dumpcap). "
                "Linux: sudo apt install tcpdump  |  Windows: instalar Wireshark",
                "ERROR",
            )
            self._capture_ok = False
            return

        tool_name = os.path.basename(tool).lower().replace(".exe", "")
        self._log(f"Herramienta de captura: {tool_name} ({tool})", "INFO")

        # on Linux, prepend sudo if not root (capture needs raw sockets)
        need_sudo = False
        if os.name != "nt" and os.geteuid() != 0:
            need_sudo = True
            self._log("Captura requiere sudo (se pedirá password)", "INFO")

        try:
            if "tcpdump" in tool_name:
                cmd = [
                    tool, "-i", self._iface,
                    "-w", self._pcap_path,
                    "-U",
                    "-B", "4096",
                    "--immediate-mode",
                ]
                if self._pcap_max_size_kb > 0:
                    size_mb = max(1, self._pcap_max_size_kb // 1024)
                    cmd.extend(["-C", str(size_mb)])
            elif "tshark" in tool_name:
                cmd = [tool, "-i", self._iface, "-w", self._pcap_path, "-q"]
                if self._pcap_max_size_kb > 0:
                    cmd.extend(["-b", f"filesize:{self._pcap_max_size_kb}"])
            elif "dumpcap" in tool_name:
                cmd = [tool, "-i", self._iface, "-w", self._pcap_path, "-q"]
                if self._pcap_max_size_kb > 0:
                    cmd.extend(["-b", f"filesize:{self._pcap_max_size_kb}"])
            else:
                cmd = [tool, "-i", self._iface, "-w", self._pcap_path]

            # prepend sudo on Linux if not root
            if need_sudo:
                cmd = ["sudo", "-n"] + cmd

            self._log(f"Comando: {' '.join(cmd)}", "INFO")
            self._pcap_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )

            # verify process started successfully (wait 1s and check)
            time.sleep(1)
            if self._pcap_proc.poll() is not None:
                _, stderr = self._pcap_proc.communicate(timeout=3)
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                self._log(f"Captura falló al iniciar: {err_msg}", "ERROR")
                self._capture_ok = False
                self._pcap_proc = None
                return

            self._capture_ok = True
            self._log(f"Captura iniciada en {self._iface}", "OK")

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error al iniciar captura: {exc}", "ERROR")
            self._capture_ok = False

    def _stop_capture(self) -> None:
        import platform
        if self._pcap_proc is not None:
            try:
                if platform.system() != "Windows":
                    self._pcap_proc.send_signal(signal.SIGINT)
                else:
                    self._pcap_proc.terminate()
                self._pcap_proc.wait(timeout=5)
            except Exception:  # pylint: disable=broad-exception-caught
                try:
                    self._pcap_proc.terminate()
                    self._pcap_proc.wait(timeout=3)
                except Exception:  # pylint: disable=broad-exception-caught
                    try:
                        self._pcap_proc.kill()
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass
            # check all pcap files (rotated or single)
            pcap_files = self._find_pcap_files()
            if pcap_files:
                total_size = sum(os.path.getsize(f) for f in pcap_files)
                size_str = f"{total_size / 1048576:.1f} MB" if total_size > 1048576 else f"{total_size / 1024:.1f} KB"
                self._log(
                    f"Captura detenida — {len(pcap_files)} archivo(s) PCAP, {size_str} total",
                    "OK",
                )
            else:
                self._log("Captura detenida — PCAP no generado", "WARN")
            self._pcap_proc = None
            self._capture_ok = False

    # ── event firing ────────────────────────────────────────────

    def _fire_event(self, ev: dict) -> None:
        ev_type = ev.get("event_type", ev.get("type", "unknown"))
        action = ev.get("action", "")
        target = ev.get("target", "")
        source = ev.get("source", "")
        label = ev.get("label", action)
        duration_s = ev.get("duration_s", 0)

        self._log(f"Evento: {label}  {source}→{target}", "INFO")

        if ev_type == "benign":
            self._active_benign = label
            self._exec_benign(action, target, duration_s)
        elif ev_type in ("attack", "malicious"):
            self._active_attack = label
            self._exec_attack(action, target, duration_s, source_ip=source)

        if duration_s > 0:
            def _clear_after():
                time.sleep(duration_s)
                if ev_type == "benign":
                    self._active_benign = "—"
                elif ev_type in ("attack", "malicious"):
                    self._active_attack = "—"
                self._log(f"Evento finalizado: {label}", "INFO")
            threading.Thread(target=_clear_after, daemon=True).start()

    # ── benign execution: HTTP/MQTT to IoT device ───────────────

    def _exec_benign(self, action_name: str, target_ip: str, duration_s: int) -> None:
        """Find the profile for the target device and execute the action."""
        profile = None
        for p in self._profiles:
            if p.device_ip == target_ip:
                profile = p
                break
        if profile is None:
            self._log(f"Sin perfil benigno para {target_ip} — evento solo registrado", "WARN")
            return

        action = profile.get_action(action_name)
        if action is None:
            self._log(f"Acción '{action_name}' no encontrada en perfil de {target_ip}", "WARN")
            return

        def _run():
            try:
                if action.protocol in ("http", "https"):
                    result = self._http_executor.execute(
                        target_ip=target_ip,
                        command=action_name,
                        port=profile.port,
                        method=action.method,
                        endpoint=action.endpoint,
                        payload=action.payload,
                    )
                    if result.success:
                        self._log(f"IoT OK: {action_name} → {target_ip} ({result.duration:.1f}s)", "OK")
                    else:
                        self._log(f"IoT error: {action_name} → {target_ip}: {result.error}", "ERROR")
                elif action.protocol == "mqtt":
                    try:
                        from modules.communication.mqtt_executor import MQTTExecutor
                        # connect to device IP (or broker) on MQTT port
                        mqtt_port = 1883
                        if profile.port in (1883, 8883):
                            mqtt_port = profile.port
                        mqtt = MQTTExecutor(
                            broker_host=target_ip,
                            broker_port=mqtt_port,
                        )
                        result = mqtt.send_action(action, action.payload)
                        if result.success:
                            self._log(f"MQTT OK: {action_name} topic={action.endpoint}", "OK")
                        else:
                            self._log(f"MQTT error: {result.error}", "ERROR")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        self._log(f"MQTT no disponible: {e}", "ERROR")
                else:
                    self._log(f"Protocolo '{action.protocol}' no soportado para {action_name}", "WARN")
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._log(f"Error ejecutando {action_name}: {e}", "ERROR")

        threading.Thread(target=_run, daemon=True).start()

    # ── attack execution: local or SSH to Kali ──────────────────

    def _find_attacker_profile(self, source_ip: str, need_ssh: bool = False):
        """Find best attacker profile for this source IP."""
        if source_ip and source_ip in self._attacker_profiles:
            return self._attacker_profiles[source_ip]
        for p in self._attacker_profiles.values():
            if need_ssh and p.mode == "ssh" and p.has_credentials:
                return p
        for p in self._attacker_profiles.values():
            if p.mode == "ssh":
                return p
        for p in self._attacker_profiles.values():
            return p
        return None

    def _exec_attack(self, attack_name: str, target_ip: str, duration_s: int, source_ip: str = "") -> None:
        """Execute attack — routes to correct attacker, sudo handled by executor."""
        from modules.attacks import get_attack_class
        attack_def = get_attack_class(attack_name)
        if attack_def is None:
            self._log(f"Ataque '{attack_name}' no encontrado", "ERROR")
            return

        gateway = ""
        for ip, role in self._device_map.items():
            if role == "benign":
                gateway = ip
                break

        cmd = attack_def.build_command(
            target_ip=target_ip, duration=duration_s or 30, port=80, gateway=gateway,
        )
        needs_root = attack_def.requires_root

        profile = self._find_attacker_profile(source_ip, need_ssh=True)
        mode = profile.mode if profile else "local"
        label = profile.tag or profile.device_ip if profile else "local"
        self._log(f"Ejecutor: {label} ({mode}) root={'sí' if needs_root else 'no'}", "INFO")
        self._log(f"[{attack_def.tool}] {cmd[:80]}", "INFO")

        if profile and mode == "ssh" and profile.has_credentials:
            self._exec_attack_ssh(attack_name, cmd, target_ip,
                                  source_ip=profile.device_ip, use_sudo=needs_root)
        else:
            if needs_root:
                import platform
                if platform.system() != "Windows":
                    cmd = f"sudo {cmd}"
                else:
                    self._log("sudo no disponible en Windows", "WARN")
            self._exec_attack_local(attack_name, cmd, target_ip, duration_s)

    def _exec_attack_ssh(self, name: str, cmd: str, target_ip: str, source_ip: str = "",
                         use_sudo: bool = False) -> None:
        """Run attack command on remote attacker via SSH."""
        executor = None
        # try getting executor from AttackersController
        if self._get_executor and source_ip:
            executor = self._get_executor(source_ip)
        # fallback: try all profiles
        if executor is None and self._get_executor:
            for p in self._attacker_profiles.values():
                if p.mode == "ssh" and p.has_credentials:
                    executor = self._get_executor(p.device_ip)
                    if executor:
                        self._log(f"Redirigido a {p.tag or p.device_ip}", "INFO")
                        break
        if executor is None:
            executor = self._ssh_executor
        if executor is None:
            self._log("Sin ejecutor SSH — configure credenciales en panel Attackers", "ERROR")
            return

        def _run():
            try:
                result = executor.execute(target_ip, cmd, timeout=120, use_sudo=use_sudo)
                if result.success:
                    self._log(f"Kali OK: {name} → {target_ip} ({result.duration:.1f}s)", "OK")
                    if result.output:
                        for line in result.output.splitlines()[:5]:
                            self._log(f"  {line}", "INFO")
                else:
                    self._log(f"Kali error: {name}: {result.error[:200]}", "ERROR")
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._log(f"SSH error: {e}", "ERROR")
        threading.Thread(target=_run, daemon=True).start()

    def _exec_attack_local(self, name: str, cmd: str, target_ip: str, duration_s: int) -> None:
        """Run attack command locally on this machine."""
        def _run():
            try:
                self._log(f"Local exec: {cmd[:60]}…", "INFO")
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    timeout=duration_s + 30 if duration_s else 120,
                    check=False,
                )
                if result.returncode == 0:
                    self._log(f"Local OK: {name} → {target_ip}", "OK")
                    if result.stdout:
                        for line in result.stdout.splitlines()[:5]:
                            self._log(f"  {line}", "INFO")
                else:
                    err = result.stderr.strip() or f"exit code {result.returncode}"
                    self._log(f"Local error: {name}: {err[:200]}", "ERROR")
            except subprocess.TimeoutExpired:
                self._log(f"Local timeout: {name}", "WARN")
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._log(f"Local exec error: {e}", "ERROR")
        threading.Thread(target=_run, daemon=True).start()

    # ── NFStream + flow tagging by device role ──────────────────

    def _extract_flows(self, pcap_files: list = None) -> None:
        """Extract flows from PCAP(s). Try NFStream first, fallback to tshark."""
        self._pcap_files = pcap_files or [self._pcap_path]
        if self._extract_flows_nfstream():
            return
        if self._extract_flows_tshark():
            return
        self._log("No se pudo extraer flujos — instalar nfstream (pip install nfstream) o tshark (Wireshark)", "ERROR")

    @staticmethod
    def _safe_flow_to_dict(flow) -> dict:
        """Extract flow attributes safely — works with any nfstream version."""
        # core attributes that exist in all nfstream versions
        SAFE_ATTRS = [
            "id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "ip_version", "vlan_id",
            "bidirectional_packets", "bidirectional_bytes",
            "bidirectional_duration_ms",
            "src2dst_packets", "src2dst_bytes",
            "dst2src_packets", "dst2src_bytes",
            "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
            "application_name", "application_category_name",
            "requested_server_name", "client_fingerprint", "server_fingerprint",
        ]
        row = {}
        for attr in SAFE_ATTRS:
            try:
                val = getattr(flow, attr, None)
                if val is not None and not callable(val):
                    row[attr] = val
            except (AttributeError, TypeError):
                pass
        # ensure we at least have src/dst IPs
        if "src_ip" not in row:
            for fallback in ["src_addr", "source_ip", "ip_src"]:
                try:
                    row["src_ip"] = getattr(flow, fallback)
                    break
                except AttributeError:
                    pass
        if "dst_ip" not in row:
            for fallback in ["dst_addr", "dest_ip", "ip_dst"]:
                try:
                    row["dst_ip"] = getattr(flow, fallback)
                    break
                except AttributeError:
                    pass
        return row

    def _collect_rotated_pcaps(self) -> list:
        """Collect all PCAP files created by rotation."""
        pcap_dir = os.path.dirname(self._pcap_path)
        base = os.path.basename(self._pcap_path).rsplit(".", 1)[0]
        files = []
        try:
            for f in sorted(os.listdir(pcap_dir)):
                full = os.path.join(pcap_dir, f)
                if not os.path.isfile(full):
                    continue
                if f.startswith(base) and any(
                    f.endswith(ext) for ext in (".pcap", ".pcapng")
                ):
                    files.append(full)
        except OSError:
            pass
        if not files and os.path.exists(self._pcap_path):
            files.append(self._pcap_path)
        return files

    def _fix_output_permissions(self) -> None:
        """On Linux, fix file ownership if created by sudo."""
        if os.name == "nt":
            return
        sudo_user = os.environ.get("SUDO_USER", "")
        if not sudo_user:
            return
        import pwd
        try:
            pw = pwd.getpwnam(sudo_user)
            uid, gid = pw.pw_uid, pw.pw_gid
            for path in [self._pcap_path, self._flows_path, self._meta_path]:
                if os.path.exists(path):
                    os.chown(path, uid, gid)
            # also fix rotated pcaps
            for f in self._collect_rotated_pcaps():
                try:
                    os.chown(f, uid, gid)
                except OSError:
                    pass
        except (KeyError, OSError):
            pass

    def _classify_flow(self, src_ip: str, dst_ip: str) -> tuple[str, str, str]:
        """Returns (src_role, dst_role, flow_label)."""
        src_role = self._device_map.get(src_ip, "external")
        dst_role = self._device_map.get(dst_ip, "external")
        if src_role == "attacker" or dst_role == "attacker":
            return src_role, dst_role, "attack"
        if src_role in ("benign", "target") or dst_role in ("benign", "target"):
            return src_role, dst_role, "benign"
        return src_role, dst_role, "unknown"

    def _extract_flows_nfstream(self) -> bool:
        """Try NFStream extraction from all PCAP files. Returns True on success."""
        self._log("Intentando NFStream…", "INFO")
        try:
            from nfstream import NFStreamer
        except ImportError:
            self._log("nfstream no instalado", "WARN")
            return False

        try:
            pcap_files = self._collect_rotated_pcaps()
            if not pcap_files:
                pcap_files = [self._pcap_path]
            self._log(f"Procesando {len(pcap_files)} archivo(s) PCAP…", "INFO")

            count = 0
            stats = {"attack": 0, "benign": 0, "unknown": 0}

            with open(self._flows_path, "w", newline="", encoding="utf-8") as f:
                writer = None

                for pcap_file in pcap_files:
                    try:
                        streamer = NFStreamer(
                            source=pcap_file,
                            statistical_analysis=False,
                        )
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        self._log(
                            f"NFStream skip {os.path.basename(pcap_file)}: {exc}",
                            "WARN",
                        )
                        continue

                    for flow in streamer:
                        row = self._safe_flow_to_dict(flow)
                        src_role, dst_role, label = self._classify_flow(
                            row.get("src_ip", ""),
                            row.get("dst_ip", ""),
                        )
                        stats[label] = stats.get(label, 0) + 1
                        if not self._capture_benign and label != "attack":
                            continue
                        row["src_role"] = src_role
                        row["dst_role"] = dst_role
                        row["flow_label"] = label
                        if writer is None:
                            writer = csv.DictWriter(f, fieldnames=row.keys())
                            writer.writeheader()
                        writer.writerow(row)
                        count += 1

            self._flows_count = count
            self._log(
                f"NFStream OK: {count} flujos ({stats}) "
                f"→ {os.path.basename(self._flows_path)}",
                "OK",
            )
            self._fix_output_permissions()
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"NFStream falló: {exc}", "WARN")
            return False

    def _extract_flows_tshark(self) -> bool:
        """Fallback: extract flows using tshark (comes with Wireshark)."""
        import shutil
        tshark = shutil.which("tshark")
        if not tshark:
            # search Windows paths
            import glob
            for p in glob.glob(r"C:\Program Files*\Wireshark\tshark.exe"):
                tshark = p
                break
        if not tshark:
            self._log("tshark no encontrado", "WARN")
            return False

        self._log("Usando tshark para extraer flujos…", "INFO")
        try:
            fields = [
                "frame.number", "frame.time", "frame.len",
                "ip.src", "ip.dst", "ip.proto",
                "tcp.srcport", "tcp.dstport",
                "udp.srcport", "udp.dstport",
            ]
            field_args = []
            for fld in fields:
                field_args.extend(["-e", fld])

            # process first PCAP (tshark processes one at a time)
            pcap_source = self._pcap_files[0] if self._pcap_files else self._pcap_path
            cmd = [
                tshark, "-r", pcap_source,
                "-T", "fields",
                *field_args,
                "-E", "header=y",
                "-E", "separator=,",
                "-E", "quote=d",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            if result.returncode != 0:
                self._log(f"tshark error: {result.stderr[:200]}", "ERROR")
                return False

            # parse tshark output and add role columns
            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                self._log("tshark: sin paquetes", "WARN")
                return False

            count = 0
            stats = {"attack": 0, "benign": 0, "unknown": 0}

            with open(self._flows_path, "w", newline="", encoding="utf-8") as f:
                header = lines[0].split(",")
                header.extend(["src_role", "dst_role", "flow_label"])
                writer = csv.writer(f)
                writer.writerow(header)

                for line in lines[1:]:
                    cols = line.split(",")
                    if len(cols) < len(fields):
                        continue
                    # ip.src is at index 3, ip.dst at index 4
                    src_ip = cols[3].strip('"') if len(cols) > 3 else ""
                    dst_ip = cols[4].strip('"') if len(cols) > 4 else ""
                    src_role, dst_role, label = self._classify_flow(src_ip, dst_ip)
                    stats[label] = stats.get(label, 0) + 1
                    if not self._capture_benign and label != "attack":
                        continue
                    cols.extend([src_role, dst_role, label])
                    writer.writerow(cols)
                    count += 1

            self._flows_count = count
            self._log(f"tshark OK: {count} paquetes ({stats}) → {os.path.basename(self._flows_path)}", "OK")
            return True

        except subprocess.TimeoutExpired:
            self._log("tshark timeout", "ERROR")
            return False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"tshark error: {exc}", "ERROR")
            return False

    # ── execution log file ───────────────────────────────────────

    def _save_execution_log(self) -> None:
        """Save the event log to a text file in the output directory."""
        try:
            log_dir = os.path.join(os.path.dirname(os.path.dirname(self._pcap_path)), "logs")
            os.makedirs(log_dir, exist_ok=True)
            base_name = os.path.basename(self._pcap_path).rsplit(".", 1)[0]
            log_path = os.path.join(log_dir, f"{base_name}_log.txt")
            from design.Menu_logs import EVENT_LOG
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("SH-DATASET Execution Log\n")
                f.write("========================\n\n")
                for entry in EVENT_LOG.entries():
                    f.write(f"{entry.timestamp} {entry.level:<5} {entry.message}\n")
            self._log(f"Log guardado: {os.path.basename(log_path)}", "OK")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error guardando log: {exc}", "WARN")

    # ── metadata ────────────────────────────────────────────────

    def _generate_metadata(self) -> None:
        config = self._config
        exp_id = getattr(config, "experiment_id", "EXP")
        now = datetime.now(timezone.utc).isoformat()

        actual_dur = (self._end_time - self._start_time) if self._end_time else 0.0

        artifacts = []
        for path in (self._pcap_path, self._flows_path, self._meta_path):
            if os.path.exists(path):
                artifacts.append({
                    "name": os.path.basename(path),
                    "type": path.rsplit(".", 1)[-1].upper(),
                    "size_bytes": os.path.getsize(path),
                    "sha256": self._sha256(path),
                    "path": path,
                })

        metadata = {
            "experiment_id": exp_id,
            "environment": getattr(config, "environment", ""),
            "orchestrator_version": getattr(config, "orchestrator_version", "1.0.0"),
            "started_at": (
                datetime.fromtimestamp(self._start_time, timezone.utc).isoformat()
                if self._start_time else ""
            ),
            "finished_at": now,
            "planned_duration_s": self._planned_s,
            "actual_duration_s": round(actual_dur, 2),
            "state": self._state.value,
            "capture_interface": self._iface,
            "devices": {ip: role for ip, role in self._device_map.items()},
            "events_total": len(self._events),
            "events_fired": self._fired,
            "flows_extracted": self._flows_count,
            "events": self._events,
            "artifacts": artifacts,
        }

        try:
            with open(self._meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, default=str)
            self._log(f"Metadatos: {os.path.basename(self._meta_path)}", "OK")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error generando metadatos: {exc}", "ERROR")

    # ── helpers ─────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "INFO") -> None:
        if self._log_fn:
            self._log_fn(msg, level)

    def _format_next_event(self) -> str:
        if not self._events:
            return "—"
        ev = sorted(self._events, key=lambda e: e.get("offset_s", 0))
        return self._format_event_label(ev[0]) if ev else "—"

    @staticmethod
    def _format_event_label(ev: dict) -> str:
        label = ev.get("label", ev.get("action", "?"))
        target = ev.get("target", "")
        offset = ev.get("offset_s", 0)
        m, s = divmod(int(offset), 60)
        h, m = divmod(m, 60)
        return f"{label} → {target} {h:02d}:{m:02d}:{s:02d}"

    @staticmethod
    def _parse_duration(val) -> float:
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, str) and ":" in val:
            parts = val.split(":")
            if len(parts) == 3:
                return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
            if len(parts) == 2:
                return int(parts[0]) * 60 + int(parts[1])
        try:
            return float(val)
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:  # pylint: disable=broad-exception-caught
            return ""
