"""
Entrada: None
Salida: LiveExecutionEngine class
Descripción: Thin orchestrator that wires together the 5 extracted services
             (CaptureService, EventExecutor, FlowExtractor, FlowLabeler,
             ArtifactManifestWriter) into a single live execution. All
             scientific decisions (capture, dispatch, extraction, labeling,
             manifest) live in the services; this class only sequences them
             and exposes a thread-safe snapshot for the UI.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

from modules.comms import SSHChannel
from modules.services import (
    CaptureService,
    EventExecutor,
    FlowExtractor,
    FlowLabeler,
    ArtifactManifestWriter,
)


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
    """
    Entrada: state, started_at, elapsed_s, remaining_s, planned_s,
             pcap_path, metadata_path, flows_path, active_benign,
             active_attack, next_event, capture_ok, logger_ok,
             events_fired, events_total, flows_generated, error
    Salida: ExecSnapshot instance
    Descripción: Immutable snapshot of the engine state, returned
                 by snapshot().
    """
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
    Descripción: Initialize the engine with default IDLE state, empty runtime
                 fields, and the 5 services wired to the engine's logger.
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
        self._duration_warned: bool = False
        self._iface: str = ""
        self._config: Any = None
        self._capture_benign: bool = True
        self._device_map: dict[str, str] = {}

        self._log_fn: Optional[Callable[[str, str], None]] = None
        self._ssh_password: str = ""
        self._attack_mode: str = "local"
        self._attacker_profiles: dict = {}
        self._get_executor = None
        self._ssh_executor: Optional[SSHChannel] = None
        self._profiles: list = []

        # The 5 services — created lazily so __init__ never fails
        self._capture = CaptureService(log_fn=self._log)
        self._event_executor = EventExecutor(log_fn=self._log)
        self._flow_extractor = FlowExtractor(log_fn=self._log)
        self._manifest_writer = ArtifactManifestWriter(log_fn=self._log)

    """
    Entrada: fn (Callable[[str, str], None])
    Salida: None
    Descripción: Set the external logging callback used to emit messages.
                 Propagates it to all services.
    """
    def set_logger(self, fn: Callable[[str, str], None]) -> None:
        self._log_fn = fn
        self._capture = CaptureService(log_fn=fn)
        self._event_executor = EventExecutor(log_fn=fn)
        self._flow_extractor = FlowExtractor(log_fn=fn)
        self._manifest_writer = ArtifactManifestWriter(log_fn=fn)

    """
    Entrada: None
    Salida: ExecSnapshot
    Descripción: Build and return a thread-safe snapshot of the current
                 execution state.
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
                active_benign=self._event_executor.active_benign,
                active_attack=self._event_executor.active_attack,
                next_event=self._next_event,
                capture_ok=self._capture.capture_ok,
                logger_ok=True,
                events_fired=self._fired,
                events_total=len(self._events),
                flows_generated=self._flows_count,
                error=self._error,
            )

    """
    Entrada: config, iface, output_dir, events, devices,
             capture_benign, profiles
    Salida: bool
    Descripción: Start a live execution: prepare output dirs, configure
                 attacker/SSH mode, build the device map, configure the 5
                 services, and launch the run loop thread.
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
        if self._state not in (
            ExecState.IDLE, ExecState.FINISHED,
            ExecState.ABORTED, ExecState.ERROR,
        ):
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

        pcap_max_size_kb = getattr(config, "pcap_max_size_kb", 512000)
        if isinstance(pcap_max_size_kb, str):
            try:
                pcap_max_size_kb = int(pcap_max_size_kb)
            except ValueError:
                pcap_max_size_kb = 512000
        self._log(f"PCAP max size: {pcap_max_size_kb} KB ({pcap_max_size_kb // 1024} MB)", "INFO")

        duration_str = getattr(config, "planned_duration", "00:30:00")
        self._planned_s = self._parse_duration(duration_str)
        self._events = events or []
        self._fired = 0
        self._flows_count = 0
        self._error = ""
        self._duration_warned = False
        self._end_time = 0.0
        self._next_event = self._format_next_event()

        attacker_cfg = getattr(config, "attacker", None)
        self._attack_mode = getattr(attacker_cfg, "mode", "local") if attacker_cfg else "local"

        if self._attack_mode == "ssh" and attacker_cfg and getattr(attacker_cfg, "ip", ""):
            self._ssh_executor = SSHChannel(
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

        # Build device map {ip: role} for flow labeling
        # and device info {ip: {"role": ..., "mac": ...}} for metadata
        self._device_map = {}
        self._device_info = {}
        from modules.devices.host_detector import get_host_ip
        host_ip = get_host_ip()
        self._device_map[host_ip] = "attacker"
        self._device_info[host_ip] = {"role": "attacker", "mac": ""}
        if devices:
            for dev in devices:
                ip = getattr(dev, "ip", "")
                role = getattr(dev, "role", "unknown")
                mac = getattr(dev, "mac", "")
                if ip:
                    self._device_map[ip] = role
                    self._device_info[ip] = {"role": role, "mac": mac or ""}
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

        # Configure the 5 services
        self._capture.configure(iface, self._pcap_path, pcap_max_size_kb)
        self._event_executor.set_profiles(self._profiles)
        self._event_executor.set_device_map(self._device_map)
        self._event_executor.set_attacker_profiles(self._attacker_profiles)
        self._event_executor.set_executor_getter(self._get_executor)
        self._event_executor.set_ssh_executor(self._ssh_executor)
        self._event_executor.set_complete_callbacks(
            on_benign_complete=lambda label: None,
            on_attack_complete=lambda label: None,
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
    Descripción: Pause a running execution by clearing the pause event and
                 switching state to PAUSED.
    """
    def pause(self) -> None:
        if self._state == ExecState.RUNNING:
            self._pause.clear()
            self._state = ExecState.PAUSED
            self._log("Execution paused", "WARN")

    """
    Entrada: None
    Salida: None
    Descripción: Resume a paused execution by setting the pause event and
                 switching state to RUNNING.
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

    # ── Backwards-compatible properties used by LiveController ──────────────

    @property
    def _state_value(self) -> str:
        return self._state.value

    # LiveController accesses _state directly; expose it as a property-like
    # attribute so existing code keeps working.
    @property
    def state(self) -> ExecState:
        return self._state

    # ── Main run loop ──────────────────────────────────────────────────────

    """
    Entrada: None
    Salida: None
    Descripción: Main background loop — start capture, fire timeline events
                 at their offsets, then stop capture, extract flows, label
                 them, and write the manifest + execution log.
    """
    def _run_loop(self) -> None:
        try:
            self._capture.start()
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
                    if not self._duration_warned:
                        self._log(
                            f"Planned duration reached ({self._planned_s:.0f}s) "
                            f"- capture continues until all events fire or Ctrl+X",
                            "WARN",
                        )
                        self._duration_warned = True

                while event_idx < len(sorted_events):
                    ev = sorted_events[event_idx]
                    if ev.get("offset_s", 0) <= elapsed:
                        self._event_executor.fire(ev)
                        ev["status"] = "completed"
                        event_idx += 1
                        self._fired = already_done + event_idx
                        if event_idx < len(sorted_events):
                            self._next_event = self._format_event_label(sorted_events[event_idx])
                        else:
                            self._next_event = "—"
                    else:
                        break

                # The capture only stops when the user presses Ctrl+X.
                # All events firing does NOT stop the capture — the user
                # may want to keep capturing benign traffic.

                time.sleep(0.5)

            self._end_time = time.time()

            if self._cancel.is_set():
                self._state = ExecState.ABORTED
                self._log("Execution aborted by user", "WARN")
            else:
                self._state = ExecState.STOPPING
                self._fired = len(sorted_events)

            self._capture.stop()
            time.sleep(2)
            self._log("Processing captures…", "INFO")

            # Extract + label flows
            pcap_files = CaptureService.find_pcap_files(
                self._pcap_path, log_fn=self._log,
            )
            if pcap_files:
                total_size = sum(os.path.getsize(f) for f in pcap_files)
                if total_size > 0:
                    if self._flow_extractor.extract(pcap_files, self._flows_path):
                        labeler = FlowLabeler(
                            device_map=self._device_map,
                            events=self._events,
                            capture_benign=self._capture_benign,
                            log_fn=self._log,
                        )
                        labeler.label(self._flows_path)
                        self._flows_count = labeler.labeled_count
                    else:
                        self._flows_count = 0
                else:
                    self._log(f"PCAP empty ({total_size} bytes)", "WARN")
            else:
                self._log("PCAP not found", "WARN")

            # Write manifest + log
            self._manifest_writer.write_manifest(
                meta_path=self._meta_path,
                pcap_path=self._pcap_path,
                flows_path=self._flows_path,
                config=self._config,
                state=self._state.value,
                started_at=self._start_time,
                ended_at=self._end_time,
                planned_s=self._planned_s,
                iface=self._iface,
                device_map=self._device_map,
                device_info=self._device_info,
                events=self._events,
                events_fired=self._fired,
                flows_count=self._flows_count,
            )
            self._manifest_writer.save_execution_log(self._pcap_path)

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
            self._capture.stop()

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
    Descripción: Return a formatted label for the next scheduled timeline
                 event, or '—' if none.
    """
    def _format_next_event(self) -> str:
        if not self._events:
            return "—"
        ev = sorted(self._events, key=lambda e: e.get("offset_s", 0))
        return self._format_event_label(ev[0]) if ev else "—"

    """
    Entrada: ev (dict)
    Salida: str
    Descripción: Format a single event as 'label → target HH:MM:SS' using its
                 offset in seconds.
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
    Descripción: Parse a duration value into seconds. Accepts HH:MM:SS,
                 DD:HH:MM:SS, or suffixed formats (30s, 5m, 2h, 7d, 2w, 1M).
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
                multipliers = {
                    "s": 1, "m": 60, "h": 3600,
                    "d": 86400, "w": 604800, "M": 2592000,
                }
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

    # ── Backwards-compatible attributes used by LiveController ─────────────

    # LiveController sets these directly on the engine before calling start().
    # They are read by start() to configure the EventExecutor.
