"""AttacksController — attack library display + tool verification via Attackers panel."""
from __future__ import annotations
import curses
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_logs import EVENT_LOG
from design.Menu_attacks import build_attacks_section, ATTACK_LIBRARY
from modules.attacks import get_plugin_attacks
from modules.attacks.base import check_tool_local, check_tool_ssh


class AttacksController:
    """
    Entrada: app
    Salida: None
    Descripción: init
    """
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._cursor: int = 0
        self._tool_status: dict[str, bool] = {}
        self._scan_mode: str = "—"
        self._scanning: bool = False

    """
    Entrada: key
    Salida: bool
    Descripción: handle key
    """
    def handle_key(self, key: int) -> bool:
        if key in (ord("v"), ord("V")):
            self._do_verify()
            return True
        if key == curses.KEY_DOWN:
            total = len(ATTACK_LIBRARY) + len(get_plugin_attacks() or [])
            if total:
                self._cursor = min(total - 1, self._cursor + 1)
                self._refresh()
            return True
        if key == curses.KEY_UP:
            total = len(ATTACK_LIBRARY) + len(get_plugin_attacks() or [])
            if total:
                self._cursor = max(0, self._cursor - 1)
                self._refresh()
            return True
        return False

    """
    Entrada: None
    Salida: None
    Descripción: refresh
    """
    def _refresh(self):
        updated = build_attacks_section(cursor=self._cursor, tool_status=self._tool_status, scan_mode=self._scan_mode)
        self._app.replace_section("attacks", updated)

    """
    Entrada: None
    Salida: None
    Descripción: do verify
    """
    def _do_verify(self):
        if self._scanning:
            EVENT_LOG.warn("Verification already in progress")
            return

        ctrl_atk = getattr(self._app, "_ctrl_attackers", None)
        if not ctrl_atk:
            EVENT_LOG.error("Attackers controller not available")
            return

        profs = ctrl_atk.profiles_list
        if not profs:
            EVENT_LOG.error("No attackers (set role=attacker in Devices)")
            return

        if len(profs) == 1:
            profile = profs[0]
        else:
            from design.Menu import choice_select_overlay
            if not self._app._stdscr:
                return
            labels = [f"{p.label} ({p.mode} - {p.device_ip})" for p in profs]
            sel = choice_select_overlay(self._app._stdscr, "Verify on machine", labels, labels[0])
            if not sel:
                return
            idx = labels.index(sel) if sel in labels else 0
            profile = profs[idx]

        self._scan_mode = f"Local ({profile.label})" if profile.is_local else f"SSH → {profile.device_ip}"
        EVENT_LOG.info(f"Verifying tools ({self._scan_mode})…")
        self._scanning = True
        self._tool_status = {}
        self._refresh()
        threading.Thread(target=self._verify_worker, args=(profile, ctrl_atk), daemon=True).start()

    """
    Entrada: profile, ctrl_atk
    Salida: None
    Descripción: verify worker
    """
    def _verify_worker(self, profile, ctrl_atk):
        tools = sorted(set(a.tool for a in ATTACK_LIBRARY))
        ssh_exec = None

        if profile.mode == "ssh":
            if not profile.has_credentials:
                EVENT_LOG.error(f"{profile.label}: no credentials (configure in Attackers panel)")
                self._scanning = False
                self._refresh()
                return

            ssh_exec = ctrl_atk.get_executor(profile.device_ip)
            if not ssh_exec:
                EVENT_LOG.error(f"Cannot create executor for {profile.label}")
                self._scanning = False
                self._refresh()
                return

            EVENT_LOG.info(f"SSH → {profile.ssh_user}@{profile.device_ip}:{profile.ssh_port}")
            EVENT_LOG.info(
                f"  password={'yes' if profile.ssh_password else 'no'}, key={'yes' if profile.ssh_key else 'no'}")
            ok, detail = ssh_exec.test_connection()
            if not ok:
                EVENT_LOG.error(f"SSH failed: {detail}")
                self._scanning = False
                self._scan_mode += " (no connection)"
                self._refresh()
                return
            EVENT_LOG.ok(f"SSH connected → {profile.device_ip}")

        for tool in tools:
            if profile.mode == "ssh" and ssh_exec:
                available = check_tool_ssh(tool, ssh_exec)
            else:
                available = check_tool_local(tool)
            self._tool_status[tool] = available
            EVENT_LOG.info(f"  {tool}: {'✓' if available else '✗'}")
            self._refresh()

        n_ok = sum(1 for v in self._tool_status.values() if v)
        EVENT_LOG.ok(f"Verification: {n_ok}/{len(tools)} available ({self._scan_mode})")
        self._scanning = False
        self._refresh()
