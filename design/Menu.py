import json
import os
import sys
import platform

try:
    import curses
except ImportError:
    if platform.system() == "Windows":
        sys.stderr.write(
            "ERROR: 'curses' not found.\n"
            "Install with: pip install windows-curses\n"
        )
    else:
        sys.stderr.write(
            "ERROR: 'curses' not found.\n"
            "Install with: sudo apt-get install libncurses5-dev\n"
        )
    sys.exit(1)

from typing import Callable, Optional

from design.handlers import (
    DevicesController,
    ArtifactsController,
    ScenarioController,
    AttacksController,
    TimelineController,
    LiveController,
    LogsController,
    BenignProfilesController,
)
from design.handlers.attackers import AttackersController
from design.Menu_scenario import SCENARIO_SECTION, build_scenario_section
from design.Menu_devices import DEVICES_SECTION, build_devices_section
from design.Menu_attacks import ATTACKS_SECTION
from design.Menu_timeline import TIMELINE_SECTION
from design.Menu_benignprofiles import BENIGN_PROFILES_SECTION
from design.Menu_attackers import ATTACKERS_SECTION
from design.Menu_live import LIVE_SECTION
from design.Menu_logs import LOGS_SECTION, build_logs_section, EVENT_LOG
from design.Menu_artifacts import ARTIFACTS_SECTION
from design.Menu_help import HELP_SECTION

from design.models import Section, FieldMeta

SAVES_DIR = "saves/scenarios"
OUTPUT_META = "outputs/metadata"
OUTPUT_PCAP = "outputs/pcap"
CAPTURE_IFACE: str = ""

HOME_SECTION = Section(
    key="home",
    label="Home",
    hint="sidebar · campos · Ctrl+O cargar · Ctrl+S guardar · Ctrl+R ejecutar",
    content_lines=[
        "Experiment ID : ",
        "Environment : ",
        "Orchestrator : 1.0.0",
        "",
        "Paths",
        f" Saves : {SAVES_DIR}",
        f" Metadata : {OUTPUT_META}",
        f" PCAP : {OUTPUT_PCAP}",
        "",
        "Capture",
        f" Interface : {CAPTURE_IFACE or '(none selected)'}",
        "",
        "Quick actions",
        " Ctrl+O Load scenario",
        " Ctrl+S Save scenario",
        " Ctrl+R Start scenario",
        " Ctrl+L Open logs",
        " Ctrl+X Abort execution",
    ],
    actions=[],
    field_map=[],
)

SECTIONS: list[Section] = [
    HOME_SECTION,
    SCENARIO_SECTION,
    DEVICES_SECTION,
    BENIGN_PROFILES_SECTION,
    ATTACKS_SECTION,
    ATTACKERS_SECTION,
    TIMELINE_SECTION,
    LIVE_SECTION,
    LOGS_SECTION,
    ARTIFACTS_SECTION,
    HELP_SECTION,
]

PAIR_HEADER_BG = 1
PAIR_MENU_NORMAL = 2
PAIR_MENU_SEL = 3
PAIR_MENU_ARROW = 4
PAIR_CONTENT = 5
PAIR_HINT_BG = 6
PAIR_BORDER = 7
PAIR_OVERLAY_BG = 8
PAIR_OVERLAY_TTL = 9
PAIR_STATUS_OK = 10
PAIR_STATUS_ERR = 11
PAIR_STATUS_WARN = 12
PAIR_LABEL_DIM = 13
PAIR_FIELD_HL = 14
PAIR_FIELD_EDIT = 15
PAIR_PANEL_HDR = 16

MENU_WIDTH = 22
HINT_HEIGHT = 2
HEADER_HEIGHT = 1

FOCUS_SIDEBAR = "sidebar"
FOCUS_PANEL = "panel"

_EDIT_SEP = " : "


def _empty_config():
    try:
        from modules.scenario_editor.config_schema import ScenarioConfig, OutputConfig, AttackerConfig
        return ScenarioConfig(
            name="",
            experiment_id="NEW",
            environment="",
            start_time="00:00:00",
            planned_duration="00:30:00",
            devices=[],
            attack_modules=[],
            timeline=[],
            output=OutputConfig(
                folder=OUTPUT_META,
                capture_enabled=True,
                export_metadata=True,
                export_pcap=True,
                export_benign=True,
            ),
            attacker=AttackerConfig(),
        )
    except Exception:
        return None


def _clean_iface_name(name: str) -> str:
    """Strip Linux NetworkManager suffixes like ' - default', ' (default)'.
    Only applied on Linux. On Windows names like 'Wi-Fi' stay intact."""
    import re
    import platform
    if platform.system() != "Linux":
        return name.strip()
    # remove " - default", " - Wired" (requires SPACE before dash)
    name = re.sub(r"\s+-\s+.*$", "", name)
    # remove "(default)", "(wired)", etc.
    name = re.sub(r"\s*\(.*?\)\s*", "", name)
    return name.strip()


def list_network_interfaces() -> list[str]:
    import socket as socket_module
    import platform

    # On Linux, read directly from /sys/class/net for clean names
    if platform.system() == "Linux":
        try:
            import os
            sysnet = "/sys/class/net"
            if os.path.isdir(sysnet):
                ifaces = []
                for name in sorted(os.listdir(sysnet)):
                    if name == "lo":
                        continue
                    ifaces.append(name)
                if ifaces:
                    return ifaces
        except Exception:
            pass

    try:
        import psutil
        import socket as psutil_socket
        seen: list[str] = []
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            if name == "Loopback Pseudo-Interface 1":
                continue
            clean = _clean_iface_name(name)
            if not clean or clean.lower() in ("lo", "loopback"):
                continue
            has_ipv4 = any(addr.family == psutil_socket.AF_INET for addr in addrs)
            is_up = stats.get(name) and stats[name].isup
            if has_ipv4 or is_up:
                seen.append(clean)
        if seen:
            return seen
    except ImportError:
        pass

    try:
        import subprocess
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="cp850",
        check=False,
        )
        ifaces: list[str] = []
        for line in result.stdout.splitlines():
            lower_line = line.lower()
            if "adaptador" in lower_line or "adapter" in lower_line:
                name = line.strip().rstrip(":")
                for prefix in (
                    "Adaptador de Ethernet ",
                    "Adaptador de LAN inalámbrica ",
                    "Adaptador desconocido ",
                    "Ethernet adapter ",
                    "Wireless LAN adapter ",
                    "Unknown adapter ",
                ):
                    if name.startswith(prefix):
                        name = name[len(prefix):]
                        break
                name = name.rstrip(":")
                if name:
                    ifaces.append(name)
        if ifaces:
            return ifaces
    except OSError:
        pass

    try:
        useful_prefixes = ("ethernet_", "wireless_")
        ifaces = [
            name
            for _, name in socket_module.if_nameindex()
            if any(name.startswith(prefix) for prefix in useful_prefixes)
            and not name.endswith((
                "_32768",
                "_32769",
                "_32770",
                "_32771",
                "_32772",
                "_32773",
                "_32774",
                "_32775",
            ))
        ]
        if ifaces:
            return ifaces
    except (AttributeError, OSError):
        pass

    return ["(eth0 - default)", "(wlan0 - default)", "any"]


def _init_colors() -> None:
    curses.use_default_colors()
    curses.init_pair(PAIR_HEADER_BG, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(PAIR_MENU_NORMAL, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_MENU_SEL, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(PAIR_MENU_ARROW, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_CONTENT, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_HINT_BG, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(PAIR_BORDER, curses.COLOR_CYAN, -1)
    curses.init_pair(PAIR_OVERLAY_BG, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(PAIR_OVERLAY_TTL, curses.COLOR_YELLOW, curses.COLOR_BLUE)
    curses.init_pair(PAIR_STATUS_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(PAIR_STATUS_ERR, curses.COLOR_RED, -1)
    curses.init_pair(PAIR_STATUS_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_LABEL_DIM, 8, -1)
    curses.init_pair(PAIR_FIELD_HL, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(PAIR_FIELD_EDIT, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(PAIR_PANEL_HDR, curses.COLOR_YELLOW, -1)


def _get_nested(obj: object, path: str) -> str:
    current = obj
    for part in path.split("."):
        current = getattr(current, part, None)
        if current is None:
            return ""
    if isinstance(current, bool):
        return "[x]" if current else "[ ]"
    return str(current)


def _set_nested(obj: object, path: str, value: str) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        obj = getattr(obj, part)
    current = getattr(obj, parts[-1], None)
    if isinstance(current, bool):
        setattr(obj, parts[-1], value.strip().lower() in ("true", "yes", "1", "on", "[x]", "x"))
        return
    setattr(obj, parts[-1], value)


def _line_label_end(line: str) -> int:
    idx = line.find(_EDIT_SEP)
    if idx == -1:
        return len(line)
    return idx + len(_EDIT_SEP)


def _draw_header(stdscr, experiment_id: str, status: str, capture: str) -> None:
    _, max_x = stdscr.getmaxyx()
    raw = f" SH-DATASET :: exp={experiment_id} :: status={status} :: capture={capture} "
    header = raw.ljust(max_x)[: max_x - 1]
    stdscr.attron(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)
    stdscr.addstr(0, 0, header)
    stdscr.attroff(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)


def _draw_borders(stdscr, top_y: int, bottom_y: int) -> None:
    _, max_x = stdscr.getmaxyx()
    content_bot = bottom_y - HINT_HEIGHT
    stdscr.attron(curses.color_pair(PAIR_BORDER))
    stdscr.addch(top_y, 0, curses.ACS_LTEE)
    for x in range(1, MENU_WIDTH):
        stdscr.addch(top_y, x, curses.ACS_HLINE)
    stdscr.addch(top_y, MENU_WIDTH, curses.ACS_TTEE)
    for x in range(MENU_WIDTH + 1, max_x - 1):
        stdscr.addch(top_y, x, curses.ACS_HLINE)
    try:
        stdscr.addch(top_y, max_x - 1, curses.ACS_RTEE)
    except curses.error:
        pass
    for y in range(top_y + 1, content_bot):
        stdscr.addch(y, 0, curses.ACS_VLINE)
        try:
            stdscr.addch(y, max_x - 1, curses.ACS_VLINE)
        except curses.error:
            pass
    stdscr.attroff(curses.color_pair(PAIR_BORDER))


def _draw_sidebar(stdscr, sections: list[Section], selected_idx: int, focus: str, top_y: int, bottom_y: int) -> None:
    menu_bottom = bottom_y - HINT_HEIGHT
    sidebar_active = focus == FOCUS_SIDEBAR
    div_pair = PAIR_BORDER if sidebar_active else PAIR_LABEL_DIM
    for y in range(top_y, menu_bottom):
        stdscr.attron(curses.color_pair(div_pair))
        stdscr.addch(y, MENU_WIDTH, curses.ACS_VLINE)
        stdscr.attroff(curses.color_pair(div_pair))
    hdr_pair = PAIR_PANEL_HDR if sidebar_active else PAIR_LABEL_DIM
    stdscr.attron(curses.color_pair(hdr_pair) | curses.A_BOLD)
    stdscr.addstr(top_y, 2, "MENU" + (" ◄" if sidebar_active else " "))
    stdscr.attroff(curses.color_pair(hdr_pair) | curses.A_BOLD)
    row = top_y + 1
    for i, sec in enumerate(sections):
        if row >= menu_bottom:
            break
        prefix = "> " if i == selected_idx else " "
        max_len = MENU_WIDTH - 4
        label = sec.label if len(sec.label) <= max_len else sec.label[: max_len - 2] + ".."
        if i == selected_idx and sidebar_active:
            stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            stdscr.addstr(row, 2, f"{prefix}{label}")
            padding = MENU_WIDTH - 2 - len(prefix) - len(label)
            if padding > 0:
                stdscr.addstr(row, 2 + len(prefix) + len(label), " " * padding)
            stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
        elif i == selected_idx:
            stdscr.attron(curses.color_pair(PAIR_MENU_ARROW) | curses.A_DIM)
            stdscr.addstr(row, 2, f"{prefix}{label}")
            stdscr.attroff(curses.color_pair(PAIR_MENU_ARROW) | curses.A_DIM)
        else:
            stdscr.attron(curses.color_pair(PAIR_MENU_ARROW))
            stdscr.addstr(row, 2, prefix)
            stdscr.attroff(curses.color_pair(PAIR_MENU_ARROW))
            stdscr.attron(curses.color_pair(PAIR_MENU_NORMAL))
            stdscr.addstr(row, 2 + len(prefix), label)
            stdscr.attroff(curses.color_pair(PAIR_MENU_NORMAL))
        row += 1


def _draw_content_with_fields(stdscr, section: Section, field_cursor: int, editing_line: int, inline_buf: str, top_y: int, bottom_y: int) -> None:
    _, max_x = stdscr.getmaxyx()
    left = MENU_WIDTH + 1
    width = max_x - 1 - left
    content_bot = bottom_y - HINT_HEIGHT
    stdscr.attron(curses.color_pair(PAIR_CONTENT) | curses.A_BOLD)
    stdscr.addstr(top_y, left + 2, section.label.upper())
    stdscr.attroff(curses.color_pair(PAIR_CONTENT) | curses.A_BOLD)
    line_to_field = {field.line_idx: field for field in section.field_map}
    selected_line = -1
    if 0 <= field_cursor < len(section.field_map):
        selected_line = section.field_map[field_cursor].line_idx
    row = top_y + 1
    for li, line in enumerate(section.content_lines):
        if row >= content_bot:
            break
        field = line_to_field.get(li)
        if field is not None and li == editing_line:
            sep_end = _line_label_end(line)
            label_part = line[:sep_end]
            display = f"{label_part}(editando) {inline_buf}"[: width - 2]
            stdscr.attron(curses.color_pair(PAIR_FIELD_EDIT) | curses.A_BOLD)
            try:
                stdscr.addstr(row, left + 2, display.ljust(width - 2))
            except curses.error:
                pass
            stdscr.attroff(curses.color_pair(PAIR_FIELD_EDIT) | curses.A_BOLD)
        elif field is not None and li == selected_line:
            display = line[: width - 2]
            stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
            try:
                stdscr.addstr(row, left + 2, display.ljust(width - 2))
            except curses.error:
                pass
            stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
        else:
            stdscr.attron(curses.color_pair(PAIR_CONTENT))
            try:
                stdscr.addstr(row, left + 2, line[: width - 2])
            except curses.error:
                pass
            stdscr.attroff(curses.color_pair(PAIR_CONTENT))
        row += 1


def _draw_hint_bar(stdscr, text: str, kind: str, bottom_y: int) -> None:
    _, max_x = stdscr.getmaxyx()
    hint_row = bottom_y - HINT_HEIGHT
    stdscr.attron(curses.color_pair(PAIR_BORDER))
    stdscr.addch(hint_row, 0, curses.ACS_LTEE)
    for x in range(1, MENU_WIDTH):
        stdscr.addch(hint_row, x, curses.ACS_HLINE)
    stdscr.addch(hint_row, MENU_WIDTH, curses.ACS_BTEE)
    for x in range(MENU_WIDTH + 1, max_x - 1):
        stdscr.addch(hint_row, x, curses.ACS_HLINE)
    try:
        stdscr.addch(hint_row, max_x - 1, curses.ACS_RTEE)
    except curses.error:
        pass
    stdscr.attroff(curses.color_pair(PAIR_BORDER))
    color_map = {
        "hint": PAIR_HINT_BG,
        "ok": PAIR_STATUS_OK,
        "err": PAIR_STATUS_ERR,
        "warn": PAIR_STATUS_WARN,
    }
    pair = color_map.get(kind, PAIR_HINT_BG)
    prefix = " Hint: " if kind == "hint" else " "
    disp = f"{prefix}{text} "[: max_x - 1].ljust(max_x - 1)
    attr = curses.color_pair(pair) | (curses.A_BOLD if kind != "hint" else 0)
    stdscr.attron(attr)
    try:
        stdscr.addstr(hint_row + 1, 0, disp)
    except curses.error:
        pass
    stdscr.attroff(attr)


def _file_prompt_overlay(stdscr, default: str, title: str = "Ruta del archivo") -> str:
    max_y, max_x = stdscr.getmaxyx()
    overlay_w = min(64, max_x - 4)
    overlay_h = 5
    oy = (max_y - overlay_h) // 2
    ox = (max_x - overlay_w) // 2
    for y in range(oy, oy + overlay_h):
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(y, ox, " " * overlay_w)
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
    stdscr.addstr(oy, ox, f" {title} "[:overlay_w].ljust(overlay_w))
    stdscr.addstr(oy + 4, ox, " [Enter] Confirmar [Esc] Cancelar "[:overlay_w])
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
    stdscr.addstr(oy + 2, ox + 2, "> ")
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
    curses.curs_set(1)
    curses.echo()
    input_x = ox + 4
    input_y = oy + 2
    input_w = overlay_w - 6
    buf: list[str] = list(default)

    def refresh_overlay() -> None:
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(input_y, input_x, "".join(buf)[:input_w].ljust(input_w))
        stdscr.move(input_y, input_x + min(len(buf), input_w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.refresh()

    refresh_overlay()
    canceled = False
    while True:
        ch = stdscr.getch()
        if ch in (curses.KEY_ENTER, 10, 13):
            break
        if ch == 27:
            canceled = True
            break
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop()
        elif 32 <= ch < 127 and len(buf) < input_w:
            buf.append(chr(ch))
        refresh_overlay()
    curses.noecho()
    curses.curs_set(0)
    return "" if canceled else "".join(buf)


def iface_select_overlay(stdscr, current: str) -> str:
    """Interface selector showing name + IP for clarity."""
    try:
        import psutil
        import socket as _sock
        import platform as _plat
        import os as _os
        iface_data = []  # list of (name, ip)

        # On Linux, use /sys/class/net for clean names + psutil for IPs
        if _plat.system() == "Linux" and _os.path.isdir("/sys/class/net"):
            all_addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name in sorted(_os.listdir("/sys/class/net")):
                if name == "lo":
                    continue
                # find IP from psutil (match by clean name or original)
                ip = ""
                for psutil_name, addrs in all_addrs.items():
                    clean = _clean_iface_name(psutil_name)
                    if clean == name or psutil_name == name:
                        for addr in addrs:
                            if addr.family == _sock.AF_INET:
                                ip = addr.address
                                break
                        break
                iface_data.append((name, ip or ""))
        else:
            # Windows / fallback
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                if name.lower().startswith(("lo", "loopback")):
                    continue
                clean = _clean_iface_name(name)
                if not clean:
                    continue
                ip = ""
                for addr in addrs:
                    if addr.family == _sock.AF_INET:
                        ip = addr.address
                        break
                is_up = stats.get(name) and stats[name].isup
                if ip or is_up:
                    iface_data.append((clean, ip or "sin IP"))
    except ImportError:
        iface_data = [(n, "") for n in list_network_interfaces()]

    if not iface_data:
        return current

    iface_names = [name for name, _ in iface_data]
    cursor = 0
    for i, (name, _) in enumerate(iface_data):
        if name == current:
            cursor = i
            break

    maxy, maxx = stdscr.getmaxyx()
    overlay_w = min(50, maxx - 4)
    overlay_h = min(len(iface_data) + 5, maxy - 4)
    oy = (maxy - overlay_h) // 2
    ox = (maxx - overlay_w) // 2
    canceled = False

    while True:
        for y in range(oy, oy + overlay_h):
            stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
            stdscr.addstr(y, ox, " " * overlay_w)
            stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
        stdscr.addstr(oy, ox, " Seleccionar interfaz de red ".center(overlay_w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(oy + overlay_h - 1, ox, " Enter=seleccionar  Esc=cancelar ".center(overlay_w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

        list_top = oy + 2
        for i, (name, ip) in enumerate(iface_data):
            row = list_top + i
            if row >= oy + overlay_h - 1:
                break
            sel = "●" if name == current else " "
            label = f" {sel} {name}"[:overlay_w - 4]
            if i == cursor:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(row, ox + 1, f"►{label}".ljust(overlay_w - 2))
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(row, ox + 1, f" {label}".ljust(overlay_w - 2))
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(iface_data) - 1, cursor + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            break
        elif key == 27:
            canceled = True
            break
    return current if canceled else iface_names[cursor]


SCAN_METHODS = ["nmap", "arp", "all"]


def choice_select_overlay(
    stdscr,
    title: str,
    options: list[str],
    current: str,
) -> str:
    """Generic single-choice overlay. Returns selected value or *current* on cancel."""
    cursor = 0
    for i, name in enumerate(options):
        if name == current:
            cursor = i
            break
    maxy, maxx = stdscr.getmaxyx()
    overlay_w = min(40, maxx - 4)
    overlay_h = min(len(options) + 5, maxy - 4)
    oy = (maxy - overlay_h) // 2
    ox = (maxx - overlay_w) // 2
    canceled = False
    while True:
        for y in range(oy, oy + overlay_h):
            stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
            stdscr.addstr(y, ox, " " * overlay_w)
            stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
        stdscr.addstr(oy, ox, f" {title} ".center(overlay_w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(oy + overlay_h - 1, ox,
                       " Enter=seleccionar  Esc=cancelar ".center(overlay_w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        list_top = oy + 2
        for i, name in enumerate(options):
            row = list_top + i
            if row >= oy + overlay_h - 2:
                break
            check = "●" if name == current else "○"
            marker = "> " if i == cursor else "  "
            label = f"{marker}{check} {name}"[: overlay_w - 2]
            if i == cursor:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
            stdscr.addstr(row, ox + 1, label.ljust(overlay_w - 2))
            if i == cursor:
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(options) - 1, cursor + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            break
        elif key == 27:
            canceled = True
            break
    return current if canceled else options[cursor]


class MenuApp:
    def __init__(self) -> None:
        self._ctrl_devices = DevicesController(self)
        self._ctrl_artifacts = ArtifactsController(self)
        self._ctrl_scenario = ScenarioController(self)
        self._ctrl_attacks = AttacksController(self)
        self._ctrl_timeline = TimelineController(self)
        self._ctrl_benign = BenignProfilesController(self)
        self._ctrl_attackers = AttackersController(self)
        self._ctrl_live = LiveController(self)
        self._ctrl_logs = LogsController(self)
        self.selected_idx: int = 0
        self.focus: str = FOCUS_SIDEBAR
        self.field_cursor: int = 0
        self.status: str = "IDLE"
        self.capture: str = "READY"
        self.experiment_id: str = "NEW"
        self.running: bool = True
        self.active_config = _empty_config()
        self._ssh_password: str = ""  # runtime only, never saved
        if self.active_config is not None:
            if not hasattr(self.active_config, "scan_cidr"):
                self.active_config.scan_cidr = "192.168.1.0/24"
            if not hasattr(self.active_config, "scan_method"):
                self.active_config.scan_method = "nmap"
        self._status_msg: str = ""
        self._status_kind: str = "hint"
        self._editing_line: int = -1
        self._inline_buf: list[str] = []
        self._stdscr = None
        self._action_cb: Optional[Callable[[str, str], None]] = None
        self._manager: object = None
        self._scenario_start: object = None
        self._planned_duration_s: int = 0
        self._next_event_label: str = "—"
        self._active_benign: str = "—"
        self._active_attack: str = "—"
        self._selected_artifact: str = ""
        self._artifact_cursor: int = 0

    def _do_iface_select(self) -> None:
        if self._stdscr is None:
            return
        global CAPTURE_IFACE
        selected = iface_select_overlay(self._stdscr, CAPTURE_IFACE)
        if selected != CAPTURE_IFACE:
            CAPTURE_IFACE = selected
            if self.active_config is not None:
                self.active_config.capture_iface = selected
            self._refresh_home_section()
            self._refresh_devices_section()
            EVENT_LOG.info(f"Interfaz seleccionada: {selected}")
            return
        pass  # cancelled

    def _do_method_select(self) -> None:
        if self._stdscr is None:
            return
        current = getattr(self.active_config, "scan_method", "nmap")
        selected = choice_select_overlay(
            self._stdscr,
            "Método de escaneo",
            SCAN_METHODS,
            current,
        )
        if selected != current:
            if self.active_config is not None:
                self.active_config.scan_method = selected
            self._refresh_devices_section()
            EVENT_LOG.info(f"Método de escaneo: {selected}")
            return
        self.set_status("Selección cancelada.", "warn")

    def set_action_callback(self, cb: Callable[[str, str], None]) -> None:
        self._action_cb = cb

    def load_config(self, config) -> None:
        self.active_config = config
        if not hasattr(config, "scan_cidr"):
            config.scan_cidr = "192.168.1.0/24"
        if not hasattr(config, "scan_method"):
            config.scan_method = "nmap"
        self.experiment_id = config.experiment_id
        self._refresh_scenario_section()
        self._refresh_home_section()

    def set_status(self, message: str, kind: str = "ok") -> None:
        self._status_msg = message
        self._status_kind = kind
        # auto-clear feedback after 5 seconds
        import threading as _thr
        if hasattr(self, "_status_timer") and self._status_timer is not None:
            self._status_timer.cancel()

        def _clear():
            self._status_msg = ""
            self._status_kind = ""
        self._status_timer = _thr.Timer(5.0, _clear)
        self._status_timer.daemon = True
        self._status_timer.start()

    def _section(self) -> Section:
        return SECTIONS[self.selected_idx]

    def _section_key(self) -> str:
        return self._section().key

    def _section_controller(self):
        section_key = self._section_key()
        ctrl_map = {
            "devices": self._ctrl_devices,
            "artifacts": self._ctrl_artifacts,
            "scenario": self._ctrl_scenario,
            "attacks": self._ctrl_attacks,
            "timeline": self._ctrl_timeline,
            "benign_profiles": self._ctrl_benign,
            "attackers": self._ctrl_attackers,
            "live": self._ctrl_live,
            "logs": self._ctrl_logs,
        }
        return ctrl_map.get(section_key)

    def replace_section(self, key: str, section: Section) -> None:
        for idx, current in enumerate(SECTIONS):
            if current.key == key:
                SECTIONS[idx] = section
                return

    def update_runtime_sections(
        self,
        manager=None,
        scenario_start=None,
        planned_duration_s: int = 0,
        next_event_label: str = "—",
        active_benign: str = "—",
        active_attack: str = "—",
        selected_artifact: str = "",
    ) -> None:
        # artifacts now self-managed by ArtifactsController
        pass

    def _refresh_scenario_section(self) -> None:
        if self.active_config is None:
            return
        self.replace_section("scenario", build_scenario_section(
            self.active_config, has_password=bool(self._ssh_password)))

    def _refresh_home_section(self) -> None:
        if self.active_config is None:
            return
        cfg = self.active_config
        updated = Section(
            key="home",
            label="Home",
            hint="← sidebar · → campos · Ctrl+O cargar · Ctrl+S guardar · Ctrl+R ejecutar",
            content_lines=[
                f"Experiment ID : {cfg.experiment_id}",
                f"Environment : {cfg.environment}",
                "Orchestrator : 1.0.0",
                "",
                "Loaded scenario",
                f" Name : {cfg.name}",
                f" Start : {cfg.start_time}",
                f" Duration : {cfg.planned_duration}",
                "",
                "Paths",
                f" Saves : {SAVES_DIR}/",
                f" Metadata : {OUTPUT_META}/",
                f" PCAP : {OUTPUT_PCAP}/",
            ],
            actions=[],
            field_map=[],
        )
        self.replace_section("home", updated)

    def _refresh_devices_section(self) -> None:
        ctrl = self._ctrl_devices
        detail_cursor = getattr(ctrl, "detail_cursor", -1)
        updated = build_devices_section(
            devices=ctrl.devices,
            device_cursor=ctrl.device_cursor,
            page=ctrl.page,
            scan_iface=CAPTURE_IFACE,
            scan_cidr=getattr(self.active_config, "scan_cidr", "192.168.1.0/24"),
            scan_method=getattr(self.active_config, "scan_method", "nmap"),
            last_scan=getattr(self, "_last_scan_time", "never"),
            detail_cursor=detail_cursor,
        )
        self.replace_section("devices", updated)

    def _refresh_logs_section(self) -> None:
        ctrl = self._ctrl_logs
        updated = build_logs_section(
            log=EVENT_LOG,
            level_filter=getattr(ctrl, "_level_filter", "All"),
            scroll_offset=getattr(ctrl, "_scroll_offset", 0),
        )
        self.replace_section("logs", updated)

    def run(self, stdscr) -> None:
        self._stdscr = stdscr
        _init_colors()
        stdscr.keypad(True)
        stdscr.timeout(300)       # poll every 300ms for background updates
        curses.curs_set(0)
        curses.noecho()
        # auto-add host machine as attacker (#13)
        self._ctrl_devices.ensure_host_attacker()
        while self.running:
            self._render(stdscr)
            key = stdscr.getch()
            if key == -1:         # timeout — no key pressed, just refresh
                continue
            if self._editing_line >= 0:
                self._handle_inline_key(key)
            else:
                self._handle_key(key)

    def _render(self, stdscr) -> None:
        stdscr.clear()
        self._refresh_logs_section()
        self._ctrl_live.refresh_section()
        if hasattr(self, "_manager"):
            self.update_runtime_sections(
                manager=self._manager,
                scenario_start=self._scenario_start,
                planned_duration_s=self._planned_duration_s,
                next_event_label=self._next_event_label,
                active_benign=self._active_benign,
                active_attack=self._active_attack,
                selected_artifact=self._selected_artifact,
            )
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 10 or max_x < 40:
            stdscr.addstr(0, 0, "Terminal too small. Min 40x10.")
            stdscr.refresh()
            return
        top_y = HEADER_HEIGHT
        bottom_y = max_y
        section = self._section()
        _draw_header(stdscr, self.experiment_id, self.status, self.capture)
        _draw_borders(stdscr, top_y, bottom_y)
        _draw_sidebar(stdscr, SECTIONS, self.selected_idx, self.focus, top_y, bottom_y)
        field_cursor = self.field_cursor if self.focus == FOCUS_PANEL else -1
        _draw_content_with_fields(
            stdscr,
            section,
            field_cursor,
            self._editing_line,
            "".join(self._inline_buf),
            top_y,
            bottom_y,
        )
        if self._editing_line >= 0:
            hint_text = "Escribe el valor · Enter confirmar · Esc cancelar"
            hint_kind = "hint"
        elif self._status_msg:
            hint_text = self._status_msg
            hint_kind = self._status_kind
        else:
            hint_text = section.hint
            hint_kind = "hint"
        _draw_hint_bar(stdscr, hint_text, hint_kind, bottom_y)
        stdscr.refresh()

    def _handle_key(self, key: int) -> None:
        section = self._section()
        global_map: dict[int, Callable[[], None]] = {
            14: self._do_iface_select,
            19: self._do_save_all,
            18: self._do_run,
            16: self._do_pause,
            24: self._do_abort,
            12: lambda: self._jump_to("logs"),
            15: self._do_load_prompt,
        }
        action = global_map.get(key)
        if action is not None:
            action()
            return
        if self.focus == FOCUS_SIDEBAR:
            self._key_sidebar(key)
            return
        if self.focus == FOCUS_PANEL:
            controller = self._section_controller()
            if controller is not None:
                if controller.handle_key(key):
                    return
            self._key_panel(key)

    def _handle_generic_key(self, key: int, section: Section) -> None:
        char_actions: dict[str, str] = {
            "a": "add",
            "d": "delete",
            "e": "edit",
            "r": "remove",
            "t": "tag",
            "c": "clone",
            "n": "new",
            "m": "move",
            "x": "delete_event",
            "v": "validate",
            "": "filter",
            "s": "scan",
        }
        ch = chr(key).lower() if 0 < key < 128 else ""
        if ch in char_actions:
            self._dispatch(section.key, char_actions[ch])
        elif key == ord(" "):
            self._dispatch(section.key, "toggle")

    def _handle_inline_key(self, key: int) -> None:
        if key in (curses.KEY_ENTER, 10, 13):
            self._commit_inline()
        elif key == 27:
            self._cancel_inline()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if self._inline_buf:
                self._inline_buf.pop()
        elif 32 <= key < 127:
            self._inline_buf.append(chr(key))

    def _key_sidebar(self, key: int) -> None:
        if key == curses.KEY_UP:
            self.selected_idx = max(0, self.selected_idx - 1)
            self.field_cursor = 0
            return
        if key == curses.KEY_DOWN:
            self.selected_idx = min(len(SECTIONS) - 1, self.selected_idx + 1)
            self.field_cursor = 0
            return
        if key == ord("\t"):
            self.selected_idx = (self.selected_idx + 1) % len(SECTIONS)
            self.field_cursor = 0
            return
        if key in (curses.KEY_RIGHT, curses.KEY_ENTER, 10, 13):
            self.focus = FOCUS_PANEL
            self.field_cursor = 0
            return
        if key in (27, ord("q")):
            self.selected_idx = 0
            self.field_cursor = 0

    def _key_panel(self, key: int) -> None:
        # auto-refresh dynamic sections
        section = self._section()
        if section.key == "attackers" and hasattr(self, "_ctrl_attackers"):
            self._ctrl_attackers._refresh()
        section = self._section()
        field_map = section.field_map
        if key in (curses.KEY_LEFT, 27):
            self.focus = FOCUS_SIDEBAR
            return
        if not field_map:
            self._handle_generic_key(key, section)
            return
        if key == curses.KEY_UP:
            self.field_cursor = max(0, self.field_cursor - 1)
            return
        if key == curses.KEY_DOWN:
            self.field_cursor = min(len(field_map) - 1, self.field_cursor + 1)
            return
        if key in (curses.KEY_ENTER, 10, 13):
            field = field_map[self.field_cursor]
            if field.editable:
                self._start_inline(field)
            else:
                self._do_action(field.attr_path)
            return
        self._handle_generic_key(key, section)

    def _start_inline(self, field: FieldMeta) -> None:
        if self.active_config is None:
            self.active_config = _empty_config()
            if self.active_config is not None:
                if not hasattr(self.active_config, "scan_cidr"):
                    self.active_config.scan_cidr = "192.168.1.0/24"
                if not hasattr(self.active_config, "scan_method"):
                    self.active_config.scan_method = "nmap"
        if self.active_config is None:
            self.set_status("! No se pudo inicializar config.", "err")
            return
        current = _get_nested(self.active_config, field.attr_path)
        if current in ("[x]", "[ ]"):
            self._toggle_bool_field(field, current)
            return
        # attacker fields now managed in Attackers panel
        # time fields use the wheel selector (#8)
        if field.attr_path in ("start_time", "planned_duration") and self._stdscr:
            from design.overlays import time_wheel_overlay
            new_val = time_wheel_overlay(self._stdscr, field.label, current)
            if new_val is not None:
                _set_nested(self.active_config, field.attr_path, new_val)
                self._refresh_scenario_section()
                EVENT_LOG.info(f"'{field.label}' → {new_val}")
            return
        self._editing_line = field.line_idx
        self._inline_buf = list(current)

    def _toggle_bool_field(self, field: FieldMeta, current: str) -> None:
        new_bool = current != "[x]"
        _set_nested(self.active_config, field.attr_path, "[x]" if new_bool else "[ ]")
        self._refresh_scenario_section()
        self._refresh_home_section()
        status = "activado" if new_bool else "desactivado"
        EVENT_LOG.info(f"'{field.label}' {status}")

    def _commit_inline(self) -> None:
        section = self._section()
        field = next((f for f in section.field_map if f.line_idx == self._editing_line), None)
        new_val = "".join(self._inline_buf)
        self._editing_line = -1
        self._inline_buf = []
        if field is None or self.active_config is None:
            return
        old_val = _get_nested(self.active_config, field.attr_path)
        if new_val == old_val:
            pass  # no change
            return
        _set_nested(self.active_config, field.attr_path, new_val)
        if field.attr_path == "experiment_id":
            self.experiment_id = new_val
        self._refresh_scenario_section()
        self._refresh_home_section()
        if field.attr_path in ("scan_cidr", "capture_iface", "scan_method"):
            self._refresh_devices_section()
        EVENT_LOG.info(f"'{field.label}' actualizado")
        self.focus = FOCUS_SIDEBAR

    def _cancel_inline(self) -> None:
        self._editing_line = -1
        self._inline_buf = []
        pass  # edit cancelled
        self.focus = FOCUS_SIDEBAR

    def _do_action(self, attr_path: str) -> None:
        action_map = {
            "capture_iface": self._do_iface_select,
            "scan_method": self._do_method_select,
        }
        action = action_map.get(attr_path)
        if action is not None:
            action()
            return
        self.focus = FOCUS_SIDEBAR

    def _do_save_all(self) -> None:
        """Ctrl+S — unified save: config + devices + timeline."""
        if self._stdscr is None:
            return
        from design.Menu_logs import EVENT_LOG
        path = _file_prompt_overlay(self._stdscr, f"{SAVES_DIR}/scenario.json", "Guardar escenario")
        if not path.strip():
            return
        path = path.strip()
        try:
            data = {}
            # scenario config
            if self.active_config is not None:
                cfg = self.active_config
                data["scenario"] = {
                    "name": getattr(cfg, "name", ""),
                    "experiment_id": getattr(cfg, "experiment_id", ""),
                    "environment": getattr(cfg, "environment", ""),
                    "start_time": getattr(cfg, "start_time", "00:00:00"),
                    "planned_duration": getattr(cfg, "planned_duration", "00:30:00"),
                    "scan_cidr": getattr(cfg, "scan_cidr", "192.168.1.0/24"),
                    "scan_method": getattr(cfg, "scan_method", "nmap"),
                }
                out = getattr(cfg, "output", None)
                if out:
                    data["scenario"]["output"] = {
                        "folder": getattr(out, "folder", ""),
                        "capture_enabled": getattr(out, "capture_enabled", True),
                        "export_pcap": getattr(out, "export_pcap", True),
                        "export_metadata": getattr(out, "export_metadata", True),
                        "export_benign": getattr(out, "export_benign", True),
                    }
                atk = getattr(cfg, "attacker", None)
                if atk:
                    data["scenario"]["attacker"] = {
                        "mode": getattr(atk, "mode", "local"),
                        "ip": getattr(atk, "ip", ""),
                        "ssh_user": getattr(atk, "ssh_user", "kali"),
                        "ssh_port": getattr(atk, "ssh_port", 22),
                        "ssh_key": getattr(atk, "ssh_key", ""),
                        "password": getattr(atk, "password", ""),
                    }
            # devices
            ctrl_d = self._ctrl_devices
            data["devices"] = [d.to_dict() for d in ctrl_d.devices]
            # timeline
            ctrl_t = self._ctrl_timeline
            data["timeline"] = ctrl_t.manager.to_list()
            # benign profiles
            ctrl_bp = self._ctrl_benign
            data["benign_profiles"] = ctrl_bp.to_list()
            # attackers
            ctrl_atk = self._ctrl_attackers
            data["attackers"] = ctrl_atk.to_list()

            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            EVENT_LOG.ok(f"Guardado: {path} ({len(data['devices'])} devices, {len(data['timeline'])} events)")
        except Exception as exc:
            EVENT_LOG.error(f"Error al guardar: {exc}")

    def _do_load_prompt(self) -> None:
        """Ctrl+O — unified load: config + devices + timeline."""
        if self._stdscr is None:
            return
        from design.Menu_logs import EVENT_LOG
        path = _file_prompt_overlay(self._stdscr, f"{SAVES_DIR}/scenario.json", "Cargar escenario")
        if not path.strip():
            return
        path = path.strip()
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # restore scenario config
            if "scenario" in data and self.active_config is not None:
                sc = data["scenario"]
                cfg = self.active_config
                for k in ("name", "experiment_id", "environment", "start_time", "planned_duration", "scan_cidr", "scan_method"):
                    if k in sc:
                        setattr(cfg, k, sc[k])
                if "output" in sc:
                    out = getattr(cfg, "output", None)
                    if out:
                        for k, v in sc["output"].items():
                            setattr(out, k, v)
                if "attacker" in sc:
                    atk = getattr(cfg, "attacker", None)
                    if atk:
                        for k, v in sc["attacker"].items():
                            setattr(atk, k, v)
                self._refresh_scenario_section()
            # restore devices
            if "devices" in data:
                from modules.devices.device_schema import DeviceEntry
                ctrl_d = self._ctrl_devices
                ctrl_d._registry.clear()
                for dd in data["devices"]:
                    dev = DeviceEntry.from_dict(dd)
                    ctrl_d._registry.upsert(dev)
                ctrl_d._clamp_cursor()
                self._refresh_devices_section()
            # restore timeline
            if "timeline" in data:
                ctrl_t = self._ctrl_timeline
                ctrl_t.manager.load_from_list(data["timeline"])
                ctrl_t._clamp_cursor()
                ctrl_t._refresh()
            # restore attackers
            if "attackers" in data:
                ctrl_atk = self._ctrl_attackers
                ctrl_atk.load_from_list(data["attackers"])
                ctrl_atk._refresh()
            # restore benign profiles
            if "benign_profiles" in data:
                ctrl_bp = self._ctrl_benign
                ctrl_bp.load_from_list(data["benign_profiles"])
                ctrl_bp._refresh()
            EVENT_LOG.ok(f"Cargado: {path}")
        except FileNotFoundError:
            EVENT_LOG.error(f"Archivo no encontrado: {path}")
        except Exception as exc:
            EVENT_LOG.error(f"Error al cargar: {exc}")

    def _do_run(self) -> None:
        if self.active_config is None:
            self.set_status("! No hay escenario. Edita los campos o usa Ctrl+O.", "err")
            return
        self._ctrl_live.handle_key(18)  # delegate to LiveController (Ctrl+R)

    def _do_pause(self) -> None:
        self._ctrl_live.handle_key(16)  # delegate to LiveController (Ctrl+P)

    def _do_abort(self) -> None:
        self._ctrl_live.handle_key(24)  # delegate to LiveController (Ctrl+X)

    def _jump_to(self, key: str) -> None:
        for idx, section in enumerate(SECTIONS):
            if section.key == key:
                self.selected_idx = idx
                self.focus = FOCUS_SIDEBAR
                self.field_cursor = 0
                break

    def _dispatch(self, section_key: str, action: str) -> None:
        if self._action_cb is not None:
            self._action_cb(section_key, action)

    def _refresh_artifact_section(self) -> None:
        if hasattr(self, "_ctrl_artifacts"):
            self._ctrl_artifacts._refresh()

    def _get_section(self, key: str) -> Section:
        return next((section for section in SECTIONS if section.key == key), SECTIONS[0])

    def stop(self) -> None:
        self.running = False


def run_menu(action_callback: Optional[Callable[[str, str], None]] = None) -> MenuApp:
    app = MenuApp()
    if action_callback is not None:
        app.set_action_callback(action_callback)
    try:
        curses.wrapper(app.run)
    except KeyboardInterrupt:
        app.stop()
    return app
