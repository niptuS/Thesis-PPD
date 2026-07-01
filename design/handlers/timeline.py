"""
TimelineController — uses specialized overlays.
#2: Attack library with attack_select_overlay
#3: Host = default attacker (no source prompt)
#4: Context-specific modals
#8: Time wheel for offsets
"""
from __future__ import annotations
import curses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_logs import EVENT_LOG
from design.Menu_timeline import build_timeline_section, PAGE_SIZE, EVENT_TYPES
from modules.timeline.timeline_manager import TimelineManager, TimelineEvent
from design.overlays import (
    attack_select_overlay, device_select_overlay,
    time_wheel_overlay, text_input_overlay,
)


class TimelineController:
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._manager = TimelineManager()
        self._cursor: int = 0
        self._page: int = 0

    @property
    def manager(self) -> TimelineManager:
        return self._manager

    def handle_key(self, key: int) -> bool:
        action_map = {
            ord("a"): self._do_add, ord("A"): self._do_add,
            ord("e"): self._do_edit, ord("E"): self._do_edit,
            ord("x"): self._do_delete, ord("X"): self._do_delete,
            ord("m"): self._do_move, ord("M"): self._do_move,
        }
        action = action_map.get(key)
        if action is not None:
            action()
            return True
        if key == curses.KEY_DOWN:
            if self._manager.events:
                self._cursor = min(len(self._manager) - 1, self._cursor + 1)
                self._sync_page()
                self._refresh()
            return True
        if key == curses.KEY_UP:
            if self._manager.events:
                self._cursor = max(0, self._cursor - 1)
                self._sync_page()
                self._refresh()
            return True
        if key == curses.KEY_NPAGE:
            tp = max(1, (len(self._manager) + PAGE_SIZE - 1) // PAGE_SIZE)
            if self._page < tp - 1:
                self._page += 1
                self._cursor = self._page * PAGE_SIZE
                self._refresh()
            return True
        if key == curses.KEY_PPAGE:
            if self._page > 0:
                self._page -= 1
                self._cursor = self._page * PAGE_SIZE
                self._refresh()
            return True
        return False

    def _sync_page(self):
        self._page = self._cursor // PAGE_SIZE

    def _clamp_cursor(self):
        total = len(self._manager)
        if total == 0:
            self._cursor = 0
            self._page = 0
        else:
            self._cursor = min(self._cursor, total - 1)
            self._sync_page()

    def _refresh(self):
        updated = build_timeline_section(events=self._manager.events, cursor=self._cursor, page=self._page)
        self._app.replace_section("timeline", updated)

    def _get_target_devices(self):
        ctrl = getattr(self._app, "_ctrl_devices", None)
        if ctrl is None:
            return []
        return [d for d in ctrl.devices if d.role != "attacker"]

    def _get_host_ip(self) -> str:
        """Legacy: return first attacker IP."""
        ctrl = getattr(self._app, "_ctrl_devices", None)
        if ctrl is None:
            return ""
        for d in ctrl.devices:
            if d.role == "attacker":
                return d.ip
        return ""

    def _select_attacker(self, stdscr) -> str | None:
        """Smart attacker selection: auto if 1, selector if multiple."""
        ctrl_atk = getattr(self._app, "_ctrl_attackers", None)
        if ctrl_atk is None:
            return self._get_host_ip()
        profs = ctrl_atk.profiles_list
        if not profs:
            EVENT_LOG.error("No hay atacantes registrados (role=attacker en Devices)")
            return None
        if len(profs) == 1:
            return profs[0].device_ip  # auto-select
        # multiple attackers — show selector
        ctrl_d = getattr(self._app, "_ctrl_devices", None)
        if ctrl_d:
            attackers = [d for d in ctrl_d.devices if d.role == "attacker"]
            if attackers:
                return device_select_overlay(stdscr, "Atacante origen", attackers)
        return profs[0].device_ip

    def _get_profile_actions(self, device_ip: str) -> list:
        """Get benign actions from the profile linked to this device IP."""
        ctrl_bp = getattr(self._app, "_ctrl_benign", None)
        if ctrl_bp is None:
            return []
        for p in ctrl_bp.profiles:
            if p.device_ip == device_ip:
                return p.actions
        return []

    def _build_attack_info(self) -> list[dict]:
        from modules.attacks import get_attack_info_list
        return get_attack_info_list()

    # ── add ──────────────────────────────────────────────────────

    def _do_add(self):
        if self._app._stdscr is None:
            return
        stdscr = self._app._stdscr
        from design.Menu import choice_select_overlay

        # 1. type
        etype = choice_select_overlay(stdscr, "Tipo de evento", EVENT_TYPES, "attack")
        if not etype:
            return

        # 2. target — device selector overlay (#4)
        targets = self._get_target_devices()
        if not targets:
            EVENT_LOG.error("No hay dispositivos target. Escanee primero")
            return
        target_ip = device_select_overlay(stdscr, "Dispositivo destino", targets)
        if not target_ip:
            return

        # 3. action — attack library or benign profile actions
        if etype == "attack":
            attacks = self._build_attack_info()
            if not attacks:
                EVENT_LOG.error("No hay ataques en la librería")
                return
            action = attack_select_overlay(stdscr, attacks)
            if not action:
                return
        else:
            # get benign actions from profile linked to target device
            profile_actions = self._get_profile_actions(target_ip)
            if profile_actions:
                action_names = [a.name for a in profile_actions]
                action = choice_select_overlay(stdscr, "Acción benigna", action_names, action_names[0])
                if not action:
                    return
            else:
                action = text_input_overlay(stdscr, "Acción benigna (sin perfil)")
                if action is None:
                    return

        # 4. offset — time wheel with smart default (#8)
        config = self._app.active_config
        scenario_start = getattr(config, "start_time", "00:00:00") if config else "00:00:00"
        base = self._manager.get_base_time(scenario_start)
        from datetime import datetime
        now = datetime.now()
        if base <= now:
            base_label = f"desde ahora ({now.strftime('%H:%M:%S')})"
        else:
            base_label = f"desde {base.strftime('%H:%M:%S')}"

        # suggest next offset (5 min after last event)
        default_offset = self._manager.get_default_offset()
        default_hms = f"{default_offset // 3600:02d}:{(default_offset % 3600) // 60:02d}:{default_offset % 60:02d}"

        offset_str = time_wheel_overlay(stdscr, f"Offset {base_label}", default_hms)
        if offset_str is None:
            return
        offset_s = self._parse_time(offset_str)

        # 5. duration — only for continuous attacks (floods, MITM)
        duration_s = 0
        if etype == "attack":
            from modules.attacks import get_attack_class
            attack_def = get_attack_class(action)
            if attack_def and attack_def.continuous:
                # continuous attack: needs duration to stop
                rec = attack_def.recommended_dur_s
                rec_hms = f"{rec // 3600:02d}:{(rec % 3600) // 60:02d}:{rec % 60:02d}"
                dur_str = time_wheel_overlay(
                    stdscr,
                    f"Duración ({attack_def.tool}, recomendado {rec}s)",
                    rec_hms,
                )
                if dur_str is None:
                    return
                duration_s = self._parse_time(dur_str)
            else:
                # non-continuous (nmap, hydra): runs until complete
                duration_s = 0
        # benign events: instant (HTTP/MQTT request), no duration needed

        # source — benign uses local host, attack uses attacker selector
        if etype == "benign":
            from modules.devices.host_detector import get_host_ip
            source = get_host_ip()
        else:
            source = self._select_attacker(stdscr)
            if source is None:
                return

        ev = TimelineEvent(
            offset_s=offset_s, event_type=etype, action=action,
            source=source, target=target_ip,
            duration_s=duration_s, label=action,
        )
        ev.update_scheduled_dt(base)
        self._manager.add(ev)
        self._cursor = self._manager.find_index(ev.event_id)
        self._sync_page()
        EVENT_LOG.info(f"Timeline +{ev.offset_str()} {etype}: {action} → {target_ip}")
        self._refresh()

    # ── edit ─────────────────────────────────────────────────────

    def _do_edit(self):
        from design.Menu import choice_select_overlay
        ev = self._manager.get(self._cursor)
        if ev is None:
            return
        if self._app._stdscr is None:
            return
        stdscr = self._app._stdscr

        fields = ["action", "target", "source", "offset", "duration", "type", "notes", "Cancelar"]
        field = choice_select_overlay(stdscr, "Editar campo", fields, fields[0])
        if not field or field == "Cancelar":
            return

        if field == "type":
            new = choice_select_overlay(stdscr, "Tipo", EVENT_TYPES, ev.event_type)
            if new:
                ev.event_type = new
        elif field == "action":
            if ev.event_type == "attack":
                attacks = self._build_attack_info()
                new = attack_select_overlay(stdscr, attacks, ev.action) if attacks else None
            else:
                new = text_input_overlay(stdscr, "Acción", ev.action)
            if new:
                ev.action = new
                ev.label = new
        elif field == "source":
            new_src = self._select_attacker(stdscr)
            if new_src:
                ev.source = new_src
        elif field == "target":
            targets = self._get_target_devices()
            if targets:
                new = device_select_overlay(stdscr, "Destino", targets, ev.target)
                if new:
                    ev.target = new
        elif field == "offset":
            new = time_wheel_overlay(stdscr, "Offset", ev.offset_str())
            if new is not None:
                ev.offset_s = self._parse_time(new)
        elif field == "duration":
            dur_hms = f"{ev.duration_s // 3600:02d}:{(ev.duration_s % 3600) // 60:02d}:{ev.duration_s % 60:02d}"
            new = time_wheel_overlay(stdscr, "Duración", dur_hms)
            if new is not None:
                ev.duration_s = self._parse_time(new)
        elif field == "notes":
            new = text_input_overlay(stdscr, "Notas", ev.notes)
            if new is not None:
                ev.notes = new

        self._manager._sort()
        self._cursor = self._manager.find_index(ev.event_id)
        self._sync_page()
        EVENT_LOG.info(f"Evento editado: {ev.label}")
        self._refresh()

    def _do_delete(self):
        ev = self._manager.get(self._cursor)
        if ev is None:
            return
        self._manager.remove(self._cursor)
        self._clamp_cursor()
        EVENT_LOG.info(f"Evento eliminado: {ev.label}")
        self._refresh()

    def _do_move(self):
        ev = self._manager.get(self._cursor)
        if ev is None:
            return
        if self._app._stdscr is None:
            return
        new_time = time_wheel_overlay(self._app._stdscr, "Nuevo offset", ev.offset_str())
        if new_time is None:
            return
        ev.offset_s = self._parse_time(new_time)
        self._manager._sort()
        self._cursor = self._manager.find_index(ev.event_id)
        self._sync_page()
        EVENT_LOG.info(f"Evento movido a {ev.offset_str()}: {ev.label}")
        self._refresh()

    @staticmethod
    def _parse_time(val: str) -> int:
        parts = val.strip().split(":")
        try:
            if len(parts) == 3:
                return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
            if len(parts) == 2:
                return int(parts[0]) * 60 + int(parts[1])
            return int(parts[0])
        except ValueError:
            return 0
