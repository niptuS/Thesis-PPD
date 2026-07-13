"""
AttackersController — manages attacker devices and their SSH connections.
Auto-syncs with devices that have role=attacker.
"""
from __future__ import annotations
import curses
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_logs import EVENT_LOG
from design.Menu_attackers import build_attackers_section
from modules.communication.attacker_profile import AttackerProfile
from modules.communication.ssh_executor import SSHExecutor
from design.overlays import text_input_overlay


class AttackersController:
    """
    Entrada: app
    Salida: None
    Descripción: init
    """
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._profiles: dict[str, AttackerProfile] = {}
        self._cursor: int = 0
        self._zone: str = "table"
        self._detail_cursor: int = -1

    """
    Entrada: None
    Salida: None
    Descripción: profiles list
    """
    @property
    def profiles_list(self) -> list[AttackerProfile]:
        self._sync_from_devices()
        return list(self._profiles.values())

    """
    Entrada: ip
    Salida: None
    Descripción: get profile
    """
    def get_profile(self, ip: str) -> Optional[AttackerProfile]:
        self._sync_from_devices()
        return self._profiles.get(ip)

    """
    Entrada: None
    Salida: Optional[AttackerProfile]
    Descripción: If exactly 1 attacker, return it. Otherwise None.
    """
    def get_single_attacker(self) -> Optional[AttackerProfile]:
        profs = self.profiles_list
        return profs[0] if len(profs) == 1 else None

    """
    Entrada: ip
    Salida: Optional[SSHExecutor]
    Descripción: Get SSH executor for an attacker by IP.
    """
    def get_executor(self, ip: str) -> Optional[SSHExecutor]:
        p = self.get_profile(ip)
        if p is None:
            return None
        if p.is_local:
            return None
        return SSHExecutor(
            host=p.device_ip, user=p.ssh_user, port=p.ssh_port,
            key_file=p.ssh_key, password=p.ssh_password,
        )

    """
    Entrada: None
    Salida: None
    Descripción: Sync profiles with devices that have role=attacker.
    """
    def _sync_from_devices(self):
        ctrl = getattr(self._app, "_ctrl_devices", None)
        if ctrl is None:
            return
        attacker_ips = {d.ip for d in ctrl.devices if d.role == "attacker"}
        for ip in attacker_ips:
            if ip not in self._profiles:
                dev = next((d for d in ctrl.devices if d.ip == ip), None)
                tag = " ".join(dev.tags) if dev and dev.tags else ""
                hostname = dev.hostname if dev else ""
                self._profiles[ip] = AttackerProfile(
                    device_ip=ip, tag=tag or hostname or ip,
                    mode="local" if any(t in (dev.tags if dev else []) for t in ("host", "localhost")) else "ssh",
                )
        for ip in list(self._profiles.keys()):
            if ip not in attacker_ips:
                del self._profiles[ip]

    """
    Entrada: None
    Salida: None
    Descripción: selected
    """
    def _selected(self) -> Optional[AttackerProfile]:
        profs = self.profiles_list
        if profs and 0 <= self._cursor < len(profs):
            return profs[self._cursor]
        return None

    """
    Entrada: key
    Salida: bool
    Descripción: handle key
    """
    def handle_key(self, key: int) -> bool:
        self._refresh()

        if key in (ord("t"), ord("T")):
            self._do_test()
            return True

        if self._zone == "table":
            if key == curses.KEY_DOWN:
                profs = self.profiles_list
                if profs:
                    self._cursor = min(len(profs) - 1, self._cursor + 1)
                    self._refresh()
                return True
            if key == curses.KEY_UP:
                if self.profiles_list:
                    self._cursor = max(0, self._cursor - 1)
                    self._refresh()
                return True
            if key in (curses.KEY_ENTER, 10, 13):
                if self._selected():
                    self._zone = "detail"
                    self._detail_cursor = 0
                    self._refresh()
                return True
        elif self._zone == "detail":
            if key == curses.KEY_DOWN:
                self._detail_cursor = min(4, self._detail_cursor + 1)
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
            if key in (curses.KEY_ENTER, 10, 13):
                self._edit_field()
                return True
            if key in (27, curses.KEY_LEFT):
                self._zone = "table"
                self._detail_cursor = -1
                self._refresh()
                return True
        return False

    """
    Entrada: None
    Salida: None
    Descripción: refresh
    """
    def _refresh(self):
        profs = self.profiles_list
        if profs and self._cursor >= len(profs):
            self._cursor = max(0, len(profs) - 1)
        updated = build_attackers_section(
            profiles=profs, cursor=self._cursor,
            detail_cursor=self._detail_cursor if self._zone == "detail" else -1,
        )
        self._app.replace_section("attackers", updated)

    """
    Entrada: None
    Salida: None
    Descripción: edit field
    """
    def _edit_field(self):
        p = self._selected()
        if not p or self._app._stdscr is None:
            return
        stdscr = self._app._stdscr
        field_map = ["mode", "ssh_user", "ssh_port", "ssh_password", "ssh_key"]
        attr = field_map[self._detail_cursor]

        if attr == "mode":
            from design.Menu import choice_select_overlay
            new = choice_select_overlay(stdscr, "Connection type", ["local", "ssh"], p.mode)
            if new and new != p.mode:
                p.mode = new
                EVENT_LOG.info(f"Attacker {p.label}: mode → {new}")
        elif attr == "ssh_password":
            pwd = text_input_overlay(stdscr, "SSH Password (not saved)", "")
            if pwd is not None:
                p.ssh_password = pwd
                EVENT_LOG.info(f"Attacker {p.label}: password set")
        elif attr == "ssh_user":
            new = text_input_overlay(stdscr, "SSH User", p.ssh_user)
            if new is not None:
                p.ssh_user = new
        elif attr == "ssh_port":
            new = text_input_overlay(stdscr, "SSH Port", str(p.ssh_port))
            if new is not None:
                try:
                    p.ssh_port = int(new)
                except ValueError:
                    pass
        elif attr == "ssh_key":
            new = text_input_overlay(stdscr, "SSH Key path", p.ssh_key)
            if new is not None:
                p.ssh_key = new
        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: do test
    """
    def _do_test(self):
        p = self._selected()
        if not p:
            return
        if p.is_local:
            EVENT_LOG.ok(f"Attacker {p.label}: local (no SSH test)")
            return
        if not p.ssh_password and not p.ssh_key:
            EVENT_LOG.error(f"Attacker {p.label}: no SSH credentials")
            return
        EVENT_LOG.info(f"Testing SSH → {p.device_ip}…")
        executor = self.get_executor(p.device_ip)
        if executor:
            ok, detail = executor.test_connection()
            if ok:
                EVENT_LOG.ok(f"SSH OK → {p.device_ip}")
            else:
                EVENT_LOG.error(f"SSH failed → {p.device_ip}: {detail}")

    """
    Entrada: None
    Salida: None
    Descripción: to list
    """
    def to_list(self) -> list[dict]:
        return [p.to_dict() for p in self._profiles.values()]

    """
    Entrada: data
    Salida: None
    Descripción: load from list
    """
    def load_from_list(self, data: list[dict]):
        self._profiles = {}
        for d in data:
            p = AttackerProfile.from_dict(d)
            self._profiles[p.device_ip] = p
