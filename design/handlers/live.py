"""
Entrada: None
Salida: LiveController class
Descripción: LiveController — handles keys for the Live Execution panel
             and connects the TUI with the LiveExecutionEngine.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_live import build_live_section
from design.Menu_logs import EVENT_LOG
from modules.live_executions.live_execution import LiveExecutionEngine


class LiveController:

    """
    Entrada: app (MenuApp)
    Salida: None
    Descripción: Initializes the LiveController with the parent app and engine.
    """
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._engine = LiveExecutionEngine()
        self._engine.set_logger(self._on_log)

    """
    Entrada: None
    Salida: LiveExecutionEngine
    Descripción: Returns the underlying execution engine.
    """
    @property
    def engine(self) -> LiveExecutionEngine:
        return self._engine

    """
    Entrada: key (int)
    Salida: bool
    Descripción: Handles a key press. Returns True if the key was consumed.
    """
    def handle_key(self, key: int) -> bool:
        if key == 18:
            self._do_start_or_resume()
            return True
        if key == 16:
            self._do_pause()
            return True
        if key == 24:
            self._do_abort()
            return True
        return False


    """
    Entrada: None
    Salida: None
    Descripción: Starts a new execution or resumes a paused one.
    """
    def _do_start_or_resume(self) -> None:
        if self._engine._state.value == "PAUSED":
            self._engine.resume()
            EVENT_LOG.info("Execution resumed")
            return

        if self._engine.is_active:
            EVENT_LOG.warn("An execution is already running")
            return

        from design.Menu import CAPTURE_IFACE
        iface = CAPTURE_IFACE
        config = self._app.active_config

        if not iface or not any(c.isalnum() for c in iface):
            self._app.set_status("Configure a network interface first (Ctrl+N).", "err")
            return
        if config is None:
            self._app.set_status("No configuration loaded.", "err")
            return

        # Auto-set start_time to current date+time (DD/MM/YYYY HH:MM:SS)
        from datetime import datetime
        now = datetime.now()
        config.start_time = now.strftime("%d/%m/%Y %H:%M:%S")
        EVENT_LOG.info(f"Start time set to: {config.start_time}")
        self._app._refresh_scenario_section()
        self._app._refresh_home_section()

        events = self._gather_events(config)

        devices = self._gather_devices()

        output_cfg = getattr(config, "output", None)
        capture_benign = getattr(output_cfg, "export_benign", True) if output_cfg else True

        output_dir = getattr(config, "output_folder", "outputs")
        if not output_dir:
            output_dir = "outputs"

        profiles = self._gather_profiles()

        ctrl_atk = getattr(self._app, "_ctrl_attackers", None)
        if ctrl_atk:
            self._engine._attacker_profiles = {
                p.device_ip: p for p in ctrl_atk.profiles_list
            }
            self._engine._get_executor = ctrl_atk.get_executor

        ok = self._engine.start(
            config=config,
            iface=iface,
            output_dir=output_dir,
            events=events,
            devices=devices,
            capture_benign=capture_benign,
            profiles=profiles,
        )
        if ok:
            self._app.status = "RUNNING"
            self._app.capture = "ACTIVE"
            self._app.set_status("Scenario started", "ok")
        else:
            self._app.set_status("Could not start execution.", "err")

    """
    Entrada: None
    Salida: None
    Descripción: Pauses the running execution.
    """
    def _do_pause(self) -> None:
        self._engine.pause()
        self._app.set_status("Paused", "warn")

    """
    Entrada: None
    Salida: None
    Descripción: Aborts the running execution.
    """
    def _do_abort(self) -> None:
        self._engine.abort()
        self._app.status = "IDLE"
        self._app.capture = "READY"
        self._app.set_status("Aborting…", "warn")


    """
    Entrada: config (ScenarioConfig)
    Salida: list[dict]
    Descripción: Reads events from TimelineController. Recalculates offsets
                 if the scenario start_time is stale (uses now() as base).
    """
    def _gather_events(self, config) -> list[dict]:
        ctrl = getattr(self._app, "_ctrl_timeline", None)
        if ctrl is not None and hasattr(ctrl, "manager"):
            manager = ctrl.manager
            scenario_start = getattr(config, "start_time", "00:00:00") if config else "00:00:00"
            base = manager.get_base_time(scenario_start)

            manager.update_all_scheduled(base)

            pending = sum(1 for e in manager.events if e.status in ("queued", "expired"))
            completed = sum(1 for e in manager.events if e.status == "completed")
            EVENT_LOG.info(
                f"Timeline: {len(manager)} events "
                f"({completed} completed, {pending} pending) "
                f"base={base.strftime('%H:%M:%S')}"
            )

            return manager.to_list()

        raw = getattr(config, "timeline", None) or []
        events = []
        for ev in raw:
            if isinstance(ev, dict):
                events.append({
                    "offset_s": ev.get("offset_s", ev.get("start_offset", 0)),
                    "event_type": ev.get("event_type", ev.get("type", "benign")),
                    "action": ev.get("action", ev.get("module", "")),
                    "source": ev.get("source", ""),
                    "target": ev.get("target", ""),
                    "label": ev.get("label", ev.get("action", "event")),
                    "duration_s": ev.get("duration_s", ev.get("duration", 0)),
                    "status": ev.get("status", "queued"),
                })
        return events

    """
    Entrada: None
    Salida: list
    Descripción: Gets benign profiles for IoT command dispatch.
    """
    def _gather_profiles(self) -> list:
        ctrl = getattr(self._app, "_ctrl_benign", None)
        if ctrl is not None and hasattr(ctrl, "profiles"):
            return ctrl.profiles
        return []

    """
    Entrada: None
    Salida: list
    Descripción: Gets registered devices from DevicesController for flow tagging.
    """
    def _gather_devices(self) -> list:
        ctrl = getattr(self._app, "_ctrl_devices", None)
        if ctrl is not None and hasattr(ctrl, "devices"):
            return ctrl.devices
        return []

    """
    Entrada: message (str), level (str)
    Salida: None
    Descripción: Redirects engine logs to EventLog.
    """
    def _on_log(self, message: str, level: str) -> None:
        level_upper = level.upper()
        if level_upper in ("OK",):
            EVENT_LOG.ok(message)
            self._app.set_status(message, "ok")
        elif level_upper in ("WARN", "WARNING"):
            EVENT_LOG.warn(message)
            self._app.set_status(message, "warn")
        elif level_upper in ("ERROR", "ERR"):
            EVENT_LOG.error(message)
            self._app.set_status(message, "err")
        else:
            EVENT_LOG.info(message)

    """
    Entrada: None
    Salida: None
    Descripción: Called by Menu._render to update the live section.
    """
    def refresh_section(self) -> None:
        snap = self._engine.snapshot()
        updated = build_live_section(
            state=snap.state,
            started_at=snap.started_at,
            elapsed_s=snap.elapsed_s,
            remaining_s=snap.remaining_s,
            planned_s=snap.planned_s,
            pcap_path=snap.pcap_path,
            metadata_path=snap.metadata_path,
            flows_path=snap.flows_path,
            active_benign=snap.active_benign,
            active_attack=snap.active_attack,
            next_event=snap.next_event,
            capture_ok=snap.capture_ok,
            logger_ok=snap.logger_ok,
            events_fired=snap.events_fired,
            events_total=snap.events_total,
            flows_generated=snap.flows_generated,
            error=snap.error,
        )
        self._app.replace_section("live", updated)

        if snap.state == "FINISHED":
            self._app.status = "IDLE"
            self._app.capture = "READY"
        elif snap.state == "RUNNING":
            self._app.status = "RUNNING"
            self._app.capture = "ACTIVE"
        elif snap.state == "PAUSED":
            self._app.status = "PAUSED"
