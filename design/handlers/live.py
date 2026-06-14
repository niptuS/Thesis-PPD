"""
LiveController — Maneja teclas del panel Live Execution
y conecta la TUI con el LiveExecutionEngine.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_live import build_live_section
# attacker profiles managed by AttackersController
from design.Menu_logs import EVENT_LOG
from modules.live_executions.live_execution import LiveExecutionEngine


class LiveController:

    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._engine = LiveExecutionEngine()
        self._engine.set_logger(self._on_log)

    @property
    def engine(self) -> LiveExecutionEngine:
        return self._engine

    def handle_key(self, key: int) -> bool:
        # Ctrl+R  = 18  → start / resume
        if key == 18:
            self._do_start_or_resume()
            return True
        # Ctrl+P  = 16  → pause
        if key == 16:
            self._do_pause()
            return True
        # Ctrl+X  = 24  → abort
        if key == 24:
            self._do_abort()
            return True
        return False

    # ── actions ─────────────────────────────────────────────────

    def _do_start_or_resume(self) -> None:
        from design.Menu_logs import EVENT_LOG

        if self._engine._state.value == "PAUSED":
            self._engine.resume()
            EVENT_LOG.info("Ejecución reanudada")
            return

        if self._engine.is_active:
            EVENT_LOG.warn("Ya hay una ejecución en curso")
            return

        # validate prerequisites
        from design.Menu import CAPTURE_IFACE
        iface = CAPTURE_IFACE
        config = self._app.active_config

        if not iface or not any(c.isalnum() for c in iface):
            self._app.set_status("Configure interfaz de red primero (Ctrl+N).", "err")
            return
        if config is None:
            self._app.set_status("No hay configuración cargada.", "err")
            return

        # gather timeline events from config
        events = self._gather_events(config)

        # gather registered devices for flow tagging
        devices = self._gather_devices()

        # read capture mode from config (default: capture all including benign)
        output_cfg = getattr(config, "output", None)
        capture_benign = getattr(output_cfg, "export_benign", True) if output_cfg else True

        output_dir = getattr(config, "output_folder", "outputs")
        if not output_dir:
            output_dir = "outputs"

        # gather benign profiles for IoT command dispatch
        profiles = self._gather_profiles()

        # pass attacker profiles for SSH execution
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
            self._app.set_status("Escenario iniciado", "ok")
        else:
            self._app.set_status("No se pudo iniciar la ejecución.", "err")

    def _do_pause(self) -> None:
        self._engine.pause()
        self._app.set_status("Pausado", "warn")

    def _do_abort(self) -> None:
        self._engine.abort()
        self._app.status = "IDLE"
        self._app.capture = "READY"
        self._app.set_status("Abortando…", "warn")

    # ── helpers ─────────────────────────────────────────────────

    def _gather_events(self, config) -> list[dict]:
        """
        Lee eventos del TimelineController. Recalcula offsets si el
        escenario tiene start_time caducado (usa now() como base).
        """

        ctrl = getattr(self._app, "_ctrl_timeline", None)
        if ctrl is not None and hasattr(ctrl, "manager"):
            manager = ctrl.manager
            # recalculate scheduled datetimes from now
            scenario_start = getattr(config, "start_time", "00:00:00") if config else "00:00:00"
            base = manager.get_base_time(scenario_start)

            # if base is in the future, events run at their scheduled time
            # if base is now (scenario expired), offsets run from now
            manager.update_all_scheduled(base)

            pending = sum(1 for e in manager.events if e.status in ("queued", "expired"))
            completed = sum(1 for e in manager.events if e.status == "completed")
            from design.Menu_logs import EVENT_LOG
            EVENT_LOG.info(
                f"Timeline: {len(manager)} eventos "
                f"({completed} completados, {pending} pendientes) "
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

    def _gather_profiles(self) -> list:
        """Get benign profiles for IoT command dispatch."""
        ctrl = getattr(self._app, "_ctrl_benign", None)
        if ctrl is not None and hasattr(ctrl, "profiles"):
            return ctrl.profiles
        return []

    def _gather_devices(self) -> list:
        """Get registered devices from DevicesController for flow tagging."""
        ctrl = getattr(self._app, "_ctrl_devices", None)
        if ctrl is not None and hasattr(ctrl, "devices"):
            return ctrl.devices
        return []

    def _on_log(self, message: str, level: str) -> None:
        """Redirect engine logs to EventLog."""
        level_upper = level.upper()
        if level_upper in ("OK",):
            EVENT_LOG.ok(message)
        elif level_upper in ("WARN", "WARNING"):
            EVENT_LOG.warn(message)
        elif level_upper in ("ERROR", "ERR"):
            EVENT_LOG.error(message)
        else:
            EVENT_LOG.info(message)

    def refresh_section(self) -> None:
        """Called by Menu._render to update the live section."""
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

        # sync app status bar
        if snap.state == "FINISHED":
            self._app.status = "IDLE"
            self._app.capture = "READY"
        elif snap.state == "RUNNING":
            self._app.status = "RUNNING"
            self._app.capture = "ACTIVE"
        elif snap.state == "PAUSED":
            self._app.status = "PAUSED"
