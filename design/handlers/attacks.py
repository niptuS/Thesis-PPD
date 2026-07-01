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
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._cursor: int = 0
        self._tool_status: dict[str, bool] = {}
        self._scan_mode: str = "—"
        self._scanning: bool = False

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

    def _refresh(self):
        updated = build_attacks_section(cursor=self._cursor, tool_status=self._tool_status, scan_mode=self._scan_mode)
        self._app.replace_section("attacks", updated)

    def _do_verify(self):
        if self._scanning:
            EVENT_LOG.warn("Verificación ya en curso")
            return

        ctrl_atk = getattr(self._app, "_ctrl_attackers", None)
        if not ctrl_atk:
            EVENT_LOG.error("Controlador de atacantes no disponible")
            return

        profs = ctrl_atk.profiles_list
        if not profs:
            EVENT_LOG.error("No hay atacantes (role=attacker en Devices)")
            return

        # smart select
        if len(profs) == 1:
            profile = profs[0]
        else:
            from design.Menu import choice_select_overlay
            if not self._app._stdscr:
                return
            labels = [f"{p.label} ({p.mode} - {p.device_ip})" for p in profs]
            sel = choice_select_overlay(self._app._stdscr, "Verificar en máquina", labels, labels[0])
            if not sel:
                return
            idx = labels.index(sel) if sel in labels else 0
            profile = profs[idx]

        self._scan_mode = f"Local ({profile.label})" if profile.is_local else f"SSH → {profile.device_ip}"
        EVENT_LOG.info(f"Verificando herramientas ({self._scan_mode})…")
        self._scanning = True
        self._tool_status = {}
        self._refresh()
        threading.Thread(target=self._verify_worker, args=(profile, ctrl_atk), daemon=True).start()

    def _verify_worker(self, profile, ctrl_atk):
        tools = sorted(set(a.tool for a in ATTACK_LIBRARY))
        ssh_exec = None

        if profile.mode == "ssh":
            if not profile.has_credentials:
                EVENT_LOG.error(f"{profile.label}: sin credenciales (configure en panel Attackers)")
                self._scanning = False
                self._refresh()
                return

            ssh_exec = ctrl_atk.get_executor(profile.device_ip)
            if not ssh_exec:
                EVENT_LOG.error(f"No se pudo crear executor para {profile.label}")
                self._scanning = False
                self._refresh()
                return

            EVENT_LOG.info(f"SSH → {profile.ssh_user}@{profile.device_ip}:{profile.ssh_port}")
            EVENT_LOG.info(
                f"  password={'sí' if profile.ssh_password else 'no'}, key={'sí' if profile.ssh_key else 'no'}")
            ok, detail = ssh_exec.test_connection()
            if not ok:
                EVENT_LOG.error(f"SSH falló: {detail}")
                self._scanning = False
                self._scan_mode += " (sin conexión)"
                self._refresh()
                return
            EVENT_LOG.ok(f"SSH conectado → {profile.device_ip}")

        for tool in tools:
            if profile.mode == "ssh" and ssh_exec:
                available = check_tool_ssh(tool, ssh_exec)
            else:
                available = check_tool_local(tool)
            self._tool_status[tool] = available
            EVENT_LOG.info(f"  {tool}: {'✓' if available else '✗'}")
            self._refresh()

        n_ok = sum(1 for v in self._tool_status.values() if v)
        EVENT_LOG.ok(f"Verificación: {n_ok}/{len(tools)} disponibles ({self._scan_mode})")
        self._scanning = False
        self._refresh()
