"""
Entrada: None
Salida: LiveExecutionEngine module
Descripción: Live Execution Engine — SH-DATASET.
             Coordinates PCAP capture, timeline event execution,
             and labeled flow generation with NFStream at the end.
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

    """
    Entrada: None
    Salida: None
    Descripción: Initialize the LiveExecutionEngine with default IDLE state and empty runtime fields.
    """
    def __init__(self) -> None:
        self._state = ExecState.IDLE
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()

        self._start_time: float = 0.0
        self._end_time: float = 0.0
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
        self._pcap_max_size_kb: int = 512000
        self._capture_ok: bool = False
        self._iface: str = ""
        self._config: Any = None

        self._device_map: dict[str, str] = {}

        self._log_fn: Optional[Callable[[str, str], None]] = None
        self._ssh_password: str = ""
        self._capture_benign: bool = True
        self._attack_mode: str = "local"
        self._attacker_profiles: dict = {}
        self._get_executor = None

        self._ssh_executor: Optional[SSHExecutor] = None
        self._http_executor: HTTPExecutor = HTTPExecutor(timeout=10)
        self._profiles: list = []


    """
    Entrada: fn (Callable[[str, str], None])
    Salida: None
    Descripción: Set the external logging callback used to emit messages.
    """
    def set_logger(self, fn: Callable[[str, str], None]) -> None:
        self._log_fn = fn

    """
    Entrada: None
    Salida: ExecSnapshot
    Descripción: Build and return a thread-safe snapshot of the current execution state.
    """
    def snapshot(self) -> ExecSnapshot:
        with self._lock:
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

    """
    Entrada: config, iface (str), output_dir (str), events (list[dict] | None), devices (list | None), capture_benign (bool), profiles (list | None)
    Salida: bool
    Descripción: Start a live execution: prepare output dirs, configure attacker/SSH mode, build the device map, and launch the run loop thread.
    """
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
        self._pcap_max_size_kb = getattr(config, "pcap_max_size_kb", 512000)
        if isinstance(self._pcap_max_size_kb, str):
            try:
                self._pcap_max_size_kb = int(self._pcap_max_size_kb)
            except ValueError:
                self._pcap_max_size_kb = 512000
        self._log(f"PCAP max size: {self._pcap_max_size_kb} KB ({self._pcap_max_size_kb // 1024} MB)", "INFO")

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
            self._log(f"SSH mode → Kali at {attacker_cfg.ip} ({attacker_cfg.ssh_user})", "INFO")
        else:
            self._ssh_executor = None
            if self._attack_mode == "local":
                self._log("Local mode — attacks run on this machine", "INFO")
            else:
                self._log("SSH mode without configured IP — attacks only logged", "WARN")

        self._device_map = {}
        from modules.devices.host_detector import get_host_ip
        host_ip = get_host_ip()
        self._device_map[host_ip] = "attacker"
        if devices:
            for dev in devices:
                ip = getattr(dev, "ip", "")
                role = getattr(dev, "role", "unknown")
                if ip:
                    self._device_map[ip] = role
        self._profiles = profiles or []
        if self._profiles:
            self._log(f"Benign profiles: {len(self._profiles)} loaded", "INFO")

            self._log(
                f"Device map: {len(self._device_map)} devices "
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

    """
    Entrada: None
    Salida: None
    Descripción: Pause a running execution by clearing the pause event and switching state to PAUSED.
    """
    def pause(self) -> None:
        if self._state == ExecState.RUNNING:
            self._pause.clear()
            self._state = ExecState.PAUSED
            self._log("Execution paused", "WARN")

    """
    Entrada: None
    Salida: None
    Descripción: Resume a paused execution by setting the pause event and switching state to RUNNING.
    """
    def resume(self) -> None:
        if self._state == ExecState.PAUSED:
            self._pause.set()
            self._state = ExecState.RUNNING
            self._log("Execution resumed", "INFO")

    """
    Entrada: None
    Salida: None
    Descripción: Request execution abort by setting the cancel and pause events.
    """
    def abort(self) -> None:
        if self._state in (ExecState.RUNNING, ExecState.PAUSED, ExecState.STARTING):
            self._cancel.set()
            self._pause.set()
            self._log("Aborting execution…", "WARN")

    """
    Entrada: None
    Salida: bool
    Descripción: Return True if the engine is currently running, paused, or starting.
    """
    @property
    def is_active(self) -> bool:
        return self._state in (ExecState.RUNNING, ExecState.PAUSED, ExecState.STARTING)


    """
    Entrada: None
    Salida: None
    Descripción: Main background loop — start capture, fire timeline events at their offsets, then stop capture, extract flows, and generate metadata.
    """
    def _run_loop(self) -> None:
        try:
            self._start_capture()
            self._start_time = time.time()
            self._state = ExecState.RUNNING
            self._log("Scenario started", "INFO")
            self._log(f"PCAP capture: {os.path.basename(self._pcap_path)}", "INFO")

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
                    f"Resuming: {already_done} completed, {pending_count} pending",
                    "INFO",
                )

            while not self._cancel.is_set():
                self._pause.wait()
                if self._cancel.is_set():
                    break

                elapsed = time.time() - self._start_time

                if self._planned_s > 0 and elapsed >= self._planned_s:
                    self._log("Planned duration reached", "INFO")
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

            self._end_time = time.time()

            if self._cancel.is_set():
                self._state = ExecState.ABORTED
                self._log("Execution aborted by user", "WARN")
            else:
                self._state = ExecState.STOPPING
                self._fired = len(sorted_events)

            self._stop_capture()
            time.sleep(2)
            self._log("Processing captures…", "INFO")

            pcap_files = self._find_pcap_files()
            if pcap_files:
                total_size = sum(os.path.getsize(f) for f in pcap_files)
                if total_size > 0:
                    self._extract_flows(pcap_files)
                else:
                    self._log(f"PCAP empty ({total_size} bytes)", "WARN")
            else:
                self._log("PCAP not found", "WARN")

            self._generate_metadata()
            self._save_execution_log()

            if self._state != ExecState.ABORTED:
                self._state = ExecState.FINISHED
                self._log("Execution completed", "OK")
            else:
                self._log("Execution finished (aborted)", "WARN")

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._end_time = time.time()
            self._error = str(exc)
            self._state = ExecState.ERROR
            self._log(f"Fatal error: {exc}", "ERROR")
            self._stop_capture()


    """
    Entrada: None
    Salida: list[str]
    Descripción: Find all PCAP chunks and rename to base_partN.pcap format. Handles dumpcap/tshark -b chunks (base_00001_TIMESTAMP.pcapng) and tcpdump -C chunks (base.pcap1, base.pcap2); produces base.pcap, base_part1.pcap, base_part2.pcap, ...
    """
    def _find_pcap_files(self) -> list[str]:
        pcap_dir = os.path.dirname(self._pcap_path)
        base_name = os.path.basename(self._pcap_path)
        base = base_name.rsplit(".", 1)[0]

        if not os.path.isdir(pcap_dir):
            return [self._pcap_path] if os.path.exists(self._pcap_path) else []

        exact_match = None
        rotated = []
        for fn in sorted(os.listdir(pcap_dir)):
            full = os.path.join(pcap_dir, fn)
            if not os.path.isfile(full):
                continue
            if fn == base_name:
                exact_match = full
            elif fn.startswith(base + "_") and any(
                fn.endswith(e) for e in (".pcap", ".pcapng")
            ):
                rotated.append(full)
            elif fn.startswith(base_name) and fn[len(base_name):].isdigit():
                rotated.append(full)

        renamed = []
        if exact_match:
            renamed.append(exact_match)
        elif rotated:
            first = rotated.pop(0)
            ext = ".pcapng" if first.endswith(".pcapng") else ".pcap"
            new_base = os.path.join(pcap_dir, base + ext)
            try:
                os.rename(first, new_base)
                self._log(f"Chunk: {os.path.basename(first)} → {base}{ext}", "INFO")
                renamed.append(new_base)
                self._pcap_path = new_base
            except OSError:
                renamed.append(first)

        for i, fpath in enumerate(rotated, start=1):
            fn = os.path.basename(fpath)
            ext = ".pcapng" if fpath.endswith(".pcapng") else ".pcap"
            new_name = os.path.join(pcap_dir, f"{base}_part{i}{ext}")
            if fpath != new_name and not os.path.exists(new_name):
                try:
                    os.rename(fpath, new_name)
                    self._log(f"Chunk: {fn} → {os.path.basename(new_name)}", "INFO")
                    fpath = new_name
                except OSError:
                    pass
            renamed.append(fpath)

        if not renamed and os.path.exists(self._pcap_path):
            renamed.append(self._pcap_path)
        return renamed

    """
    Entrada: None
    Salida: str
    Descripción: Find tcpdump, tshark, or dumpcap on the system; returns the tool path or empty string.
    """
    def _find_capture_tool(self) -> str:
        import shutil
        import platform
        if platform.system() != "Windows":
            for tool in ["tcpdump", "dumpcap", "tshark"]:
                if shutil.which(tool):
                    return tool
            return ""
        for tool in ["tshark", "dumpcap"]:
            if shutil.which(tool):
                return tool
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

    """
    Entrada: None
    Salida: None
    Descripción: Resolve the capture tool and start the PCAP capture process on the configured interface.
    """
    def _start_capture(self) -> None:
        if not self._iface:
            self._log("No capture interface configured", "WARN")
            self._capture_ok = False
            return

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
                "Capture tool not found (tcpdump/tshark/dumpcap). "
                "Linux: sudo apt install tcpdump  |  Windows: install Wireshark",
                "ERROR",
            )
            self._capture_ok = False
            return

        tool_name = os.path.basename(tool).lower().replace(".exe", "")
        self._log(f"Capture tool: {tool_name} ({tool})", "INFO")

        need_sudo = False
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

            self._log(f"Command: {' '.join(cmd)}", "INFO")
            self._pcap_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )

            time.sleep(1)
            if self._pcap_proc.poll() is not None:
                _, stderr = self._pcap_proc.communicate(timeout=3)
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                self._log(f"Capture failed to start: {err_msg}", "ERROR")
                self._capture_ok = False
                self._pcap_proc = None
                return

            self._capture_ok = True
            self._log(f"Capture started on {self._iface}", "OK")

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error starting capture: {exc}", "ERROR")
            self._capture_ok = False

    """
    Entrada: None
    Salida: None
    Descripción: Stop the running PCAP capture process and log the total captured file size.
    """
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
            pcap_files = self._find_pcap_files()
            if pcap_files:
                total_size = sum(os.path.getsize(f) for f in pcap_files)
                size_str = f"{total_size / 1048576:.1f} MB" if total_size > 1048576 else f"{total_size / 1024:.1f} KB"
                self._log(
                    f"Capture stopped — {len(pcap_files)} PCAP file(s), {size_str} total",
                    "OK",
                )
            else:
                self._log("Capture stopped — PCAP not generated", "WARN")
            self._pcap_proc = None
            self._capture_ok = False


    """
    Entrada: ev (dict)
    Salida: None
    Descripción: Fire a single timeline event — route to the benign or attack executor and schedule a clearer thread for time-boxed events.
    """
    def _fire_event(self, ev: dict) -> None:
        ev_type = ev.get("event_type", ev.get("type", "unknown"))
        action = ev.get("action", "")
        target = ev.get("target", "")
        source = ev.get("source", "")
        label = ev.get("label", action)
        duration_s = ev.get("duration_s", 0)

        self._log(f"Event: {label}  {source}→{target}", "INFO")

        if ev_type == "benign":
            self._active_benign = label
            self._exec_benign(action, target, duration_s)
        elif ev_type in ("attack", "malicious"):
            self._active_attack = label
            self._exec_attack(action, target, duration_s, source_ip=source)

        if duration_s > 0:
            """
            Entrada: None
            Salida: None
            Descripción: Inner helper that waits duration_s seconds, then clears the active event label and logs completion.
            """
            def _clear_after():
                time.sleep(duration_s)
                if ev_type == "benign":
                    self._active_benign = "—"
                elif ev_type in ("attack", "malicious"):
                    self._active_attack = "—"
                self._log(f"Event completed: {label}", "INFO")
            threading.Thread(target=_clear_after, daemon=True).start()


    """
    Entrada: action_name (str), target_ip (str), duration_s (int)
    Salida: None
    Descripción: Find the benign profile for the target device and execute the action via the matching executor in a background thread.
    """
    def _exec_benign(self, action_name: str, target_ip: str, duration_s: int) -> None:
        profile = None
        for p in self._profiles:
            if p.device_ip == target_ip:
                profile = p
                break
        if profile is None:
            self._log(f"No benign profile for {target_ip} — event only logged", "WARN")
            return

        action = profile.get_action(action_name)
        if action is None:
            self._log(f"Action '{action_name}' not found in profile of {target_ip}", "WARN")
            return

        """
        Entrada: None
        Salida: None
        Descripción: Inner worker that runs the benign action over HTTP/MQTT and logs the result.
        """
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
                        self._log(f"MQTT unavailable: {e}", "ERROR")
                else:
                    self._log(f"Protocol '{action.protocol}' not supported for {action_name}", "WARN")
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._log(f"Error executing {action_name}: {e}", "ERROR")

        threading.Thread(target=_run, daemon=True).start()


    """
    Entrada: source_ip (str), need_ssh (bool)
    Salida: attacker profile or None
    Descripción: Find the best attacker profile for the given source IP, preferring SSH-capable profiles with credentials.
    """
    def _find_attacker_profile(self, source_ip: str, need_ssh: bool = False):
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

    """
    Entrada: attack_name (str), target_ip (str), duration_s (int), source_ip (str)
    Salida: None
    Descripción: Execute an attack by routing to the correct attacker (local, SSH, or plugin fallback); sudo is handled by the executor.
    """
    def _exec_attack(self, attack_name: str, target_ip: str, duration_s: int, source_ip: str = "") -> None:
        from modules.attacks import get_attack_class, get_plugin_attacks
        attack_def = get_attack_class(attack_name)
        if attack_def is None:
            plugins = get_plugin_attacks() or []
            for p in plugins:
                if p.name == attack_name:
                    attack_def = p
                    break
        if attack_def is None:
            self._log(f"Attack '{attack_name}' not found", "ERROR")
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
        self._log(f"Executor: {label} ({mode}) root={'yes' if needs_root else 'no'}", "INFO")
        self._log(f"[{attack_def.tool}] {cmd[:80]}", "INFO")

        if hasattr(attack_def, "local_fallback") and attack_def.local_fallback:
            self._exec_plugin(attack_def, target_ip, duration_s)
            return

        if profile and mode == "ssh" and profile.has_credentials:
            self._exec_attack_ssh(attack_name, cmd, target_ip,
                                  source_ip=profile.device_ip, use_sudo=needs_root)
        else:
            if needs_root:
                import platform
                if platform.system() != "Windows":
                    cmd = f"sudo {cmd}"
                else:
                    self._log("sudo not available on Windows", "WARN")
            self._exec_attack_local(attack_name, cmd, target_ip, duration_s)

    """
    Entrada: name (str), cmd (str), target_ip (str), source_ip (str), use_sudo (bool)
    Salida: None
    Descripción: Run an attack command on a remote attacker via SSH, dispatching to the matching executor in a background thread.
    """
    def _exec_attack_ssh(self, name: str, cmd: str, target_ip: str, source_ip: str = "",
                         use_sudo: bool = False) -> None:
        executor = None
        if self._get_executor and source_ip:
            executor = self._get_executor(source_ip)
        if executor is None and self._get_executor:
            for p in self._attacker_profiles.values():
                if p.mode == "ssh" and p.has_credentials:
                    executor = self._get_executor(p.device_ip)
                    if executor:
                        self._log(f"Redirected to {p.tag or p.device_ip}", "INFO")
                        break
        if executor is None:
            executor = self._ssh_executor
        if executor is None:
            self._log("No SSH executor — configure credentials in Attackers panel", "ERROR")
            return

        """
        Entrada: None
        Salida: None
        Descripción: Inner worker that runs the SSH attack command and logs the result.
        """
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

    """
    Entrada: attack_def, target_ip (str), duration_s (int)
    Salida: None
    Descripción: Execute a plugin attack by dynamically importing and calling its Python run() function in a background thread.
    """
    def _exec_plugin(self, attack_def, target_ip: str, duration_s: int) -> None:
        """
        Entrada: None
        Salida: None
        Descripción: Inner worker that imports the plugin module, calls its run function, and logs the result.
        """
        def _run():
            try:
                fallback = attack_def.local_fallback
                parts = fallback.split(":")
                mod_name = parts[0]
                func_name = parts[1] if len(parts) > 1 else "run"

                if mod_name.startswith("plugins.attacks."):
                    full_mod = mod_name
                elif mod_name.startswith("plugins."):
                    full_mod = mod_name
                else:
                    full_mod = f"plugins.attacks.{mod_name}"

                self._log(f"Plugin: {full_mod}.{func_name}()", "INFO")

                import importlib
                mod = importlib.import_module(full_mod)
                func = getattr(mod, func_name)

                result = func(
                    target_ip=target_ip,
                    port=80,
                    duration=duration_s or 30,
                )

                if isinstance(result, dict):
                    if result.get("success"):
                        self._log(f"Plugin OK: {attack_def.name} — {result.get('message', '')}", "OK")
                    else:
                        self._log(f"Plugin error: {result.get('message', 'unknown')}", "ERROR")
                else:
                    self._log(f"Plugin completed: {attack_def.name}", "OK")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self._log(f"Plugin error: {attack_def.name}: {exc}", "ERROR")
        threading.Thread(target=_run, daemon=True).start()

    """
    Entrada: name (str), cmd (str), target_ip (str), duration_s (int)
    Salida: None
    Descripción: Run an attack command locally on this machine in a background subprocess thread.
    """
    def _exec_attack_local(self, name: str, cmd: str, target_ip: str, duration_s: int) -> None:
        """
        Entrada: None
        Salida: None
        Descripción: Inner worker that runs the local attack command via subprocess and logs the result.
        """
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


    """
    Entrada: pcap_files (list | None)
    Salida: None
    Descripción: Extract flows from PCAP file(s); tries NFStream first and falls back to tshark.
    """
    def _extract_flows(self, pcap_files: list = None) -> None:
        self._pcap_files = pcap_files or [self._pcap_path]
        if self._extract_flows_nfstream():
            return
        if self._extract_flows_tshark():
            return
        self._log("Could not extract flows — install nfstream (pip install nfstream) or tshark (Wireshark)", "ERROR")

    """
    Entrada: flow
    Salida: dict
    Descripción: Extract flow attributes safely — works with any nfstream version. Uses a curated attribute list with fallbacks for src/dst IP.
    """
    @staticmethod
    def _safe_flow_to_dict(flow) -> dict:
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

    """
    Entrada: None
    Salida: list
    Descripción: Collect all PCAP chunks; delegates to _find_pcap_files which handles renaming.
    """
    def _collect_rotated_pcaps(self) -> list:
        return self._find_pcap_files()

    """
    Entrada: None
    Salida: None
    Descripción: On Linux, fix file ownership of output artifacts if they were created by sudo.
    """
    def _fix_output_permissions(self) -> None:
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
            for f in self._collect_rotated_pcaps():
                try:
                    os.chown(f, uid, gid)
                except OSError:
                    pass
        except (KeyError, OSError):
            pass

    """
    Entrada: src_ip (str), dst_ip (str)
    Salida: tuple
    Descripción: Classify a flow and return (src_role, dst_role, label, sublabel, kill_chain, subcategory) based on the device map and matching attack events.
    """
    def _classify_flow(self, src_ip: str, dst_ip: str) -> tuple:
        src_role = self._device_map.get(src_ip, "unknown")
        dst_role = self._device_map.get(dst_ip, "unknown")

        if src_role == "attacker" or dst_role == "attacker":
            label = "attack"
        else:
            label = "benign"

        sublabel = "artificial"

        kill_chain = ""
        subcategory = ""
        if label == "attack":
            for ev in self._events:
                if ev.get("event_type") == "attack":
                    ev_target = ev.get("target", "")
                    ev_source = ev.get("source", "")
                    if (dst_ip == ev_target or src_ip == ev_target) and \
                       (src_ip == ev_source or dst_ip == ev_source or not ev_source):
                        action = ev.get("action", "")
                        from modules.attacks import get_attack_class, get_plugin_attacks
                        atk = get_attack_class(action)
                        if atk is None:
                            plugins = get_plugin_attacks() or []
                            for p in plugins:
                                if p.name == action:
                                    atk = p; break
                        if atk:
                            kill_chain = getattr(atk, "kill_chain", "")
                            subcategory = getattr(atk, "subcategory", "")
                        break

        return src_role, dst_role, label, sublabel, kill_chain, subcategory
    """
    Entrada: None
    Salida: bool
    Descripción: Try NFStream extraction from all PCAP files; returns True on success.
    """
    def _extract_flows_nfstream(self) -> bool:
        self._log("Attempting NFStream…", "INFO")
        try:
            from nfstream import NFStreamer
        except ImportError:
            self._log("nfstream not installed", "WARN")
            return False

        try:
            pcap_files = self._collect_rotated_pcaps()
            if not pcap_files:
                pcap_files = [self._pcap_path]
            self._log(f"Processing {len(pcap_files)} PCAP file(s)…", "INFO")

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
                        src_role, dst_role, label, sublabel, kill_chain, subcat = self._classify_flow(
                            row.get("src_ip", ""),
                            row.get("dst_ip", ""),
                        )
                        stats[label] = stats.get(label, 0) + 1
                        if not self._capture_benign and label != "attack":
                            continue
                        row["src_role"] = src_role
                        row["dst_role"] = dst_role
                        row["label"] = label
                        row["sublabel"] = sublabel
                        row["kill_chain"] = kill_chain
                        row["subcategory"] = subcat
                        if writer is None:
                            writer = csv.DictWriter(f, fieldnames=row.keys())
                            writer.writeheader()
                        writer.writerow(row)
                        count += 1

            self._flows_count = count
            self._log(
                f"NFStream OK: {count} flows ({stats}) "
                f"→ {os.path.basename(self._flows_path)}",
                "OK",
            )
            self._fix_output_permissions()
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"NFStream failed: {exc}", "WARN")
            return False

    """
    Entrada: None
    Salida: bool
    Descripción: Fallback flow extraction using tshark (shipped with Wireshark); returns True on success.
    """
    def _extract_flows_tshark(self) -> bool:
        import shutil
        tshark = shutil.which("tshark")
        if not tshark:
            import glob
            for p in glob.glob(r"C:\Program Files*\Wireshark\tshark.exe"):
                tshark = p
                break
        if not tshark:
            self._log("tshark not found", "WARN")
            return False

        self._log("Using tshark to extract flows…", "INFO")
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

            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                self._log("tshark: no packets", "WARN")
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
            self._log(f"tshark OK: {count} packets ({stats}) → {os.path.basename(self._flows_path)}", "OK")
            return True

        except subprocess.TimeoutExpired:
            self._log("tshark timeout", "ERROR")
            return False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"tshark error: {exc}", "ERROR")
            return False


    """
    Entrada: None
    Salida: None
    Descripción: Save the event log to a text file inside the output directory.
    """
    def _save_execution_log(self) -> None:
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
            self._log(f"Log saved: {os.path.basename(log_path)}", "OK")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error saving log: {exc}", "WARN")


    """
    Entrada: None
    Salida: None
    Descripción: Generate and write the metadata JSON file summarizing the execution, artifacts, and enriched event metadata.
    """
    def _generate_metadata(self) -> None:
        config = self._config
        exp_id = getattr(config, "experiment_id", "EXP")
        now = datetime.now(timezone.utc).isoformat()

        actual_dur = (self._end_time - self._start_time) if self._end_time else 0.0

        artifacts = []
        for pf in self._find_pcap_files():
            if os.path.exists(pf):
                artifacts.append({
                    "name": os.path.basename(pf),
                    "type": "PCAP",
                    "size_bytes": os.path.getsize(pf),
                    "sha256": self._sha256(pf),
                    "path": pf,
                })
        for path in (self._flows_path, self._meta_path):
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
            "events": [self._enrich_event_metadata(ev) for ev in self._events],
            "artifacts": artifacts,
        }

        try:
            with open(self._meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, default=str)
            self._log(f"Metadata: {os.path.basename(self._meta_path)}", "OK")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error generating metadata: {exc}", "ERROR")


    """
    Entrada: msg (str), level (str)
    Salida: None
    Descripción: Forward a log message to the external logger callback if one is set.
    """
    def _log(self, msg: str, level: str = "INFO") -> None:
        if self._log_fn:
            self._log_fn(msg, level)

    """
    Entrada: None
    Salida: str
    Descripción: Return a formatted label for the next scheduled timeline event, or '—' if none.
    """
    def _format_next_event(self) -> str:
        if not self._events:
            return "—"
        ev = sorted(self._events, key=lambda e: e.get("offset_s", 0))
        return self._format_event_label(ev[0]) if ev else "—"

    """
    Entrada: ev (dict)
    Salida: str
    Descripción: Format a single event as 'label → target HH:MM:SS' using its offset in seconds.
    """
    @staticmethod
    def _format_event_label(ev: dict) -> str:
        label = ev.get("label", ev.get("action", "?"))
        target = ev.get("target", "")
        offset = ev.get("offset_s", 0)
        m, s = divmod(int(offset), 60)
        h, m = divmod(m, 60)
        return f"{label} → {target} {h:02d}:{m:02d}:{s:02d}"

    """
    Entrada: val
    Salida: float
    Descripción: Parse a duration value into seconds. Accepts HH:MM:SS, DD:HH:MM:SS, or suffixed formats (30s, 5m, 2h, 7d, 2w, 1M).
    """
    @staticmethod
    def _parse_duration(val) -> float:
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, str):
            val = val.strip()
            if val and val[-1] in "smhdwM" and val[:-1].replace(".", "").isdigit():
                num = float(val[:-1])
                unit = val[-1]
                multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "M": 2592000}
                return num * multipliers.get(unit, 1)
            if ":" in val:
                parts = val.split(":")
                try:
                    if len(parts) == 4:
                        return int(parts[0]) * 86400 + int(parts[1]) * 3600 + int(parts[2]) * 60 + int(parts[3])
                    if len(parts) == 3:
                        return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                    if len(parts) == 2:
                        return int(parts[0]) * 60 + int(parts[1])
                except ValueError:
                    pass
        try:
            return float(val)
        except (ValueError, TypeError):
            return 0.0

    """
    Entrada: ev (dict)
    Salida: dict
    Descripción: Enrich an event dict with kill-chain classification, MITRE reference, and tool metadata for attack events.
    """
    def _enrich_event_metadata(self, ev: dict) -> dict:
        from modules.devices.host_detector import get_host_ip
        source = ev.get("source", "")
        if source and source not in self._device_map:
            source = get_host_ip()
        meta = {
            "event_type": ev.get("event_type", ""),
            "action": ev.get("action", ""),
            "target": ev.get("target", ""),
            "source": source,
            "scheduled_dt": ev.get("scheduled_dt", ""),
            "duration_s": ev.get("duration_s", 0),
            "status": ev.get("status", ""),
            "label": "attack" if ev.get("event_type") == "attack" else "benign",
            "sublabel": "artificial",
        }
        if ev.get("event_type") == "attack":
            action = ev.get("action", "")
            from modules.attacks import get_attack_class, get_plugin_attacks
            atk = get_attack_class(action)
            if atk is None:
                plugins = get_plugin_attacks() or []
                for p in plugins:
                    if p.name == action:
                        atk = p
                        break
            if atk:
                meta["category"] = getattr(atk, "kill_chain", "")
                meta["subcategory"] = getattr(atk, "subcategory", "")
                meta["mitre_ref"] = getattr(atk, "mitre_ref", "")
                meta["tool"] = getattr(atk, "tool", "")
        return meta

    """
    Entrada: path (str)
    Salida: str
    Descripción: Compute the SHA-256 hex digest of a file, or return an empty string on error.
    """
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
