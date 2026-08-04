"""
BenignProfilesController — manages IoT device profiles.
Auto-scans endpoints when creating profiles to discover available actions.
"""
from __future__ import annotations
import curses
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_logs import EVENT_LOG
from design.Menu_benignprofiles import build_benign_profiles_section, PAGE_SIZE
from modules.profiles.profile_schema import BenignProfile, DeviceAction
from modules.profiles.profile_library import DEVICE_TYPES, create_template_profile
from modules.profiles.endpoint_scanner import scan_endpoints, summarize_scan, scan_mqtt
from design.overlays import text_input_overlay, device_select_overlay


class BenignProfilesController:
    """
    Entrada: app
    Salida: None
    Descripción: init
    """
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._profiles: list[BenignProfile] = []
        self._cursor: int = 0
        self._page: int = 0
        self._zone: str = "table"
        self._detail_cursor: int = -1

    """
    Entrada: None
    Salida: None
    Descripción: profiles
    """
    @property
    def profiles(self) -> list[BenignProfile]:
        return list(self._profiles)

    """
    Entrada: None
    Salida: None
    Descripción: selected
    """
    def _selected(self) -> Optional[BenignProfile]:
        if self._profiles and 0 <= self._cursor < len(self._profiles):
            return self._profiles[self._cursor]
        return None

    """
    Entrada: key
    Salida: bool
    Descripción: handle key
    """
    def handle_key(self, key: int) -> bool:
        actions = {
            ord("a"): self._do_add, ord("A"): self._do_add,
            ord("e"): self._do_edit, ord("E"): self._do_edit,
            ord("r"): self._do_delete, ord("X"): self._do_delete,
            ord("t"): self._do_test, ord("T"): self._do_test,
            ord("s"): self._do_scan_endpoints, ord("S"): self._do_scan_endpoints,
        }
        action = actions.get(key)
        if action is not None:
            action()
            return True

        if self._zone == "table":
            if key == curses.KEY_DOWN and self._profiles:
                self._cursor = min(len(self._profiles) - 1, self._cursor + 1)
                self._sync_page()
                self._refresh()
                return True
            if key == curses.KEY_UP and self._profiles:
                self._cursor = max(0, self._cursor - 1)
                self._sync_page()
                self._refresh()
                return True
            if key in (curses.KEY_ENTER, 10, 13):
                if self._selected() and self._selected().actions:
                    self._zone = "detail"
                    self._detail_cursor = 0
                    self._refresh()
                return True
            if key == curses.KEY_NPAGE:
                tp = max(1, (len(self._profiles) + PAGE_SIZE - 1) // PAGE_SIZE)
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

        elif self._zone == "detail":
            profile = self._selected()
            if not profile:
                self._zone = "table"
                return True
            if key == curses.KEY_DOWN:
                self._detail_cursor = min(len(profile.actions) - 1, self._detail_cursor + 1)
                self._refresh()
                return True
            if key == curses.KEY_UP:
                if self._detail_cursor > 0:
                    self._detail_cursor -= 1
                    self._refresh()
                else:
                    self._zone = "table"
                    self._detail_cursor = -1
                    self._refresh()
                return True
            if key in (27, curses.KEY_LEFT):
                self._zone = "table"
                self._detail_cursor = -1
                self._refresh()
                return True
            if key in (curses.KEY_ENTER, 10, 13):
                self._edit_action()
                return True

        return False

    """
    Entrada: None
    Salida: None
    Descripción: sync page
    """
    def _sync_page(self):
        self._page = self._cursor // PAGE_SIZE

    """
    Entrada: None
    Salida: None
    Descripción: clamp cursor
    """
    def _clamp_cursor(self):
        if not self._profiles:
            self._cursor = 0
            self._page = 0
        else:
            self._cursor = min(self._cursor, len(self._profiles) - 1)
            self._sync_page()

    """
    Entrada: None
    Salida: None
    Descripción: refresh
    """
    def _refresh(self):
        updated = build_benign_profiles_section(
            profiles=self._profiles, cursor=self._cursor,
            page=self._page, detail_cursor=self._detail_cursor if self._zone == "detail" else -1,
        )
        self._app.replace_section("benign_profiles", updated)


    """
    Entrada: None
    Salida: None
    Descripción: do add
    """
    def _do_add(self):
        from design.Menu import choice_select_overlay
        if self._app._stdscr is None:
            return
        stdscr = self._app._stdscr

        dtype = choice_select_overlay(stdscr, "Device type", DEVICE_TYPES, DEVICE_TYPES[0])
        if not dtype:
            return

        ctrl_d = getattr(self._app, "_ctrl_devices", None)
        device_ip = ""
        device_tag = ""
        if ctrl_d and ctrl_d.devices:
            targets = [d for d in ctrl_d.devices if d.role != "attacker"]
            if targets:
                device_ip = device_select_overlay(stdscr, "Link device", targets) or ""
                if device_ip:
                    dev = next((d for d in targets if d.ip == device_ip), None)
                    device_tag = " ".join(dev.tags) if dev and dev.tags else ""

        tag = text_input_overlay(stdscr, "Profile tag/name", device_tag or dtype)
        if tag is None:
            return

        port_str = text_input_overlay(stdscr, "Device HTTP port", "80")
        port = 80
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                pass

        profile = BenignProfile(
            device_type=dtype, device_ip=device_ip,
            device_tag=tag, port=port, protocol="http",
        )

        if device_ip:
            EVENT_LOG.info(f"Scanning endpoints on {device_ip}:{port} ({dtype})…")
            self._profiles.append(profile)
            self._cursor = len(self._profiles) - 1
            self._sync_page()
            self._refresh()
            threading.Thread(
                target=self._scan_worker, args=(profile,), daemon=True
            ).start()
        else:
            template = create_template_profile(dtype, device_ip, tag)
            profile.actions = template.actions
            self._profiles.append(profile)
            self._cursor = len(self._profiles) - 1
            self._sync_page()
            EVENT_LOG.ok(f"Profile created: {tag} (template, {len(profile.actions)} actions)")
            self._refresh()


    """
    Entrada: profile
    Salida: None
    Descripción: scan worker
    """
    def _scan_worker(self, profile: BenignProfile):
        """
        Entrada: msg, lvl
        Salida: None
        Descripción: log fn
        """
        def log_fn(msg, lvl):
            return getattr(EVENT_LOG, lvl.lower(), EVENT_LOG.info)(msg)

        results = scan_endpoints(
            device_ip=profile.device_ip,
            device_type=profile.device_type,
            port=profile.port,
            timeout=1.5,
            auth_user=profile.auth_user,
            auth_pass=profile.auth_pass,
            log_fn=log_fn,
        )

        mqtt_results = {}
        for mqtt_port in [1883, 8883]:
            mqtt_results = scan_mqtt(
                device_ip=profile.device_ip,
                device_type=profile.device_type,
                port=mqtt_port,
                timeout=2.0,
                log_fn=log_fn,
            )
            if mqtt_results:
                break

        summary = summarize_scan(results)

        profile.actions = []
        available = 0
        auth_needed = 0
        unavail = 0

        for action_name, mqtt_result in mqtt_results.items():
            profile.actions.append(DeviceAction(
                name=f"mqtt_{action_name}",
                description=f"MQTT: {mqtt_result.description}",
                protocol="mqtt",
                method="PUB",
                endpoint=mqtt_result.endpoint,
                payload=mqtt_result.payload,
            ))
            available += 1
            EVENT_LOG.ok(f"    ✓ MQTT {action_name}: {mqtt_result.endpoint}")

        for action_name, info in summary.items():
            if info["status"] == "available":
                profile.actions.append(DeviceAction(
                    name=action_name,
                    description=f"{info['desc']} [{info['status_code']}]",
                    protocol="http",
                    method=info["method"],
                    endpoint=info["endpoint"],
                ))
                available += 1
                EVENT_LOG.ok(f"    ✓ {action_name}: {info['endpoint']}")
            elif info["status"] == "needs_auth":
                profile.actions.append(DeviceAction(
                    name=f"{action_name}_auth",
                    description=f"🔒 {info['desc']} (requires credentials)",
                    protocol="http",
                    method=info["method"],
                    endpoint=info["endpoint"],
                ))
                auth_needed += 1
                EVENT_LOG.warn(f"    🔒 {action_name}: {info['endpoint']} (403 — credentials)")
            else:
                unavail += 1
                EVENT_LOG.info(f"    ✗ {action_name}: no endpoint available")

        EVENT_LOG.ok(
            f"Scan completed: {available} available, "
            f"{auth_needed} require auth, {unavail} no available"
        )
        self._refresh()


    """
    Entrada: None
    Salida: None
    Descripción: do scan endpoints
    """
    def _do_scan_endpoints(self):
        profile = self._selected()
        if not profile or not profile.device_ip:
            EVENT_LOG.error("Select a profile with configured IP")
            return

        if self._app._stdscr:
            from design.Menu import choice_select_overlay
            if choice_select_overlay(self._app._stdscr, "Enter credentials for scan?",
                                     ["No", "Yes"], "No") == "Yes":
                user = text_input_overlay(self._app._stdscr, "HTTP user", profile.auth_user)
                if user is not None:
                    profile.auth_user = user
                pwd = text_input_overlay(self._app._stdscr, "HTTP password", profile.auth_pass)
                if pwd is not None:
                    profile.auth_pass = pwd

        EVENT_LOG.info(f"Re-scanning {profile.device_ip}:{profile.port}…")
        threading.Thread(target=self._scan_worker, args=(profile,), daemon=True).start()


    """
    Entrada: None
    Salida: None
    Descripción: do edit
    """
    def _do_edit(self):
        from design.Menu import choice_select_overlay
        profile = self._selected()
        if not profile or not self._app._stdscr:
            return
        stdscr = self._app._stdscr
        fields = ["tag", "device_ip", "port", "auth_user", "auth_pass", "Cancel"]
        field = choice_select_overlay(stdscr, "Edit field", fields, fields[0])
        if not field or field == "Cancel":
            return
        if field == "tag":
            new = text_input_overlay(stdscr, "Tag", profile.device_tag)
            if new is not None:
                profile.device_tag = new
        elif field == "device_ip":
            ctrl_d = getattr(self._app, "_ctrl_devices", None)
            if ctrl_d and ctrl_d.devices:
                targets = [d for d in ctrl_d.devices if d.role != "attacker"]
                if targets:
                    new = device_select_overlay(stdscr, "Device", targets, profile.device_ip)
                    if new:
                        profile.device_ip = new
            else:
                new = text_input_overlay(stdscr, "IP", profile.device_ip)
                if new:
                    profile.device_ip = new
        elif field == "port":
            new = text_input_overlay(stdscr, "Port", str(profile.port))
            if new:
                try:
                    profile.port = int(new)
                except ValueError:
                    pass
        elif field in ("auth_user", "auth_pass"):
            new = text_input_overlay(stdscr, field.replace("_", " ").title(), getattr(profile, field, ""))
            if new is not None:
                setattr(profile, field, new)
        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: edit action
    """
    def _edit_action(self):
        from design.Menu import choice_select_overlay
        profile = self._selected()
        if not profile or self._detail_cursor < 0 or self._detail_cursor >= len(profile.actions):
            return
        if not self._app._stdscr:
            return
        stdscr = self._app._stdscr
        action = profile.actions[self._detail_cursor]
        fields = ["endpoint", "payload", "method", "Cancel"]
        field = choice_select_overlay(stdscr, f"Edit {action.name}", fields, fields[0])
        if not field or field == "Cancel":
            return
        if field == "endpoint":
            new = text_input_overlay(stdscr, "Endpoint", action.endpoint)
            if new is not None:
                action.endpoint = new
        elif field == "payload":
            new = text_input_overlay(stdscr, "Payload JSON", action.payload)
            if new is not None:
                action.payload = new
        elif field == "method":
            methods = ["GET", "POST", "PUT", "DELETE"]
            new = choice_select_overlay(stdscr, "Method", methods, action.method)
            if new:
                action.method = new
        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: do delete
    """
    def _do_delete(self):
        profile = self._selected()
        if not profile:
            return
        ip = profile.device_ip
        tag = profile.device_tag
        self._profiles.pop(self._cursor)
        self._zone = "table"
        self._detail_cursor = -1
        self._clamp_cursor()
        ctrl_tl = getattr(self._app, "_ctrl_timeline", None)
        if ctrl_tl and ip:
            before = len(ctrl_tl._manager._events)
            ctrl_tl._manager._events = [
                e for e in ctrl_tl._manager._events
                if not (e.event_type == "benign" and e.target == ip)
            ]
            removed = before - len(ctrl_tl._manager._events)
            ctrl_tl._clamp_cursor()
            if removed:
                EVENT_LOG.info(f"  + {removed} benign events removed from timeline")
        EVENT_LOG.info(f"Profile removed: {tag}")
        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: do test
    """
    def _do_test(self):
        profile = self._selected()
        if not profile or not profile.device_ip:
            return
        from modules.comms.http_channel import HTTPChannel
        EVENT_LOG.info(f"Test connection → {profile.device_ip}:{profile.port}…")
        executor = HTTPChannel(timeout=5)
        ok = executor.test_connection(profile.device_ip, profile.port)
        if ok:
            EVENT_LOG.ok(f"Connection OK: {profile.device_ip}:{profile.port}")
        else:
            EVENT_LOG.error(f"No response: {profile.device_ip}:{profile.port}")

    """
    Entrada: None
    Salida: None
    Descripción: to list
    """
    def to_list(self) -> list[dict]:
        return [p.to_dict() for p in self._profiles]

    """
    Entrada: data
    Salida: None
    Descripción: load from list
    """
    def load_from_list(self, data: list[dict]) -> None:
        self._profiles = [BenignProfile.from_dict(d) for d in data]
        self._clamp_cursor()
