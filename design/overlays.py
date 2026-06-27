"""
Overlay widgets — specialized modals and inline selectors.
#4: Context-specific selectors (role, method, attack, device)
#8: Date/time wheel selector (HH:MM:SS / DD/MM/YYYY HH:MM:SS)
"""
from __future__ import annotations
import curses
from typing import Optional


# ── color pair IDs (must match Menu.py) ─────────────────────────
PAIR_OVERLAY_BG = 8
PAIR_OVERLAY_TTL = 9
PAIR_MENU_SEL = 3
PAIR_STATUS_OK = 10
PAIR_STATUS_ERR = 11
PAIR_STATUS_WARN = 12
PAIR_FIELD_HL = 14


# ═══════════════════════════════════════════════════════════════
# #4: CONTEXT-SPECIFIC SELECTORS
# ═══════════════════════════════════════════════════════════════

def _draw_box(stdscr, oy, ox, h, w, title="", footer="Enter=ok  Esc=cancelar"):
    for y in range(oy, oy + h):
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(y, ox, " " * w)
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
    if title:
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
        stdscr.addstr(oy, ox, f" {title} ".center(w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
    if footer:
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(oy + h - 1, ox, f" {footer} ".center(w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

_ROLE_COLORS = {
    "target": PAIR_STATUS_WARN,
    "benign": PAIR_STATUS_OK,
    "attacker": PAIR_STATUS_ERR,
    "unknown": PAIR_OVERLAY_BG,
}
_ROLE_ICONS = {
    "target": "◎",
    "benign": "✓",
    "attacker": "⚔",
    "unknown": "?",
}


def role_select_overlay(stdscr, current: str, roles: list[str]) -> str:
    cursor = 0
    for i, r in enumerate(roles):
        if r == current:
            cursor = i
            break
    maxy, maxx = stdscr.getmaxyx()
    w = 30
    h = len(roles) + 4
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2
    while True:
        _draw_box(stdscr, oy, ox, h, w, "Seleccionar Rol")
        for i, role in enumerate(roles):
            row = oy + 2 + i
            icon = _ROLE_ICONS.get(role, " ")
            cpair = _ROLE_COLORS.get(role, PAIR_OVERLAY_BG)
            if i == cursor:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(row, ox + 2, f"► {icon} {role}".ljust(w - 4))
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(cpair))
                stdscr.addstr(row, ox + 2, f"  {icon} {role}".ljust(w - 4))
                stdscr.attroff(curses.color_pair(cpair))
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(roles) - 1, cursor + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            return roles[cursor]
        elif key == 27:
            return current


# ── Method selector (with descriptions) ────────────────────────

_METHOD_DESC = {
    "nmap": "Host discovery + port scan",
    "arp": "ARP broadcast (rápido, solo LAN)",
    "all": "nmap + ARP combinado",
}


def method_select_overlay(stdscr, current: str, methods: list[str]) -> str:
    cursor = 0
    for i, m in enumerate(methods):
        if m == current:
            cursor = i
            break
    maxy, maxx = stdscr.getmaxyx()
    w = 44
    h = len(methods) + 4
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2
    while True:
        _draw_box(stdscr, oy, ox, h, w, "Método de Escaneo")
        for i, method in enumerate(methods):
            row = oy + 2 + i
            desc = _METHOD_DESC.get(method, "")
            check = "●" if method == current else "○"
            label = f"  {check} {method:<6} {desc}"[:w - 4]
            if i == cursor:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(row, ox + 2, f"► {check} {method:<6} {desc}"[:w - 4].ljust(w - 4))
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(row, ox + 2, label.ljust(w - 4))
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(methods) - 1, cursor + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            return methods[cursor]
        elif key == 27:
            return current


# ── Attack selector (wide, with description + MITRE) ───────────

def attack_select_overlay(stdscr, attacks: list[dict], current: str = "") -> Optional[str]:
    """
    attacks: list of {"name": ..., "description": ..., "mitre_ref": ...}
    Returns selected attack name or None on cancel.
    """
    if not attacks:
        return None
    cursor = 0
    for i, a in enumerate(attacks):
        if a["name"] == current:
            cursor = i
            break
    maxy, maxx = stdscr.getmaxyx()
    w = min(60, maxx - 4)
    h = min(len(attacks) + 6, maxy - 4)
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2
    while True:
        _draw_box(stdscr, oy, ox, h, w, "Seleccionar Ataque", "↑↓=navegar  Enter=ok  Esc=cancelar")
        # header
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_UNDERLINE)
        stdscr.addstr(oy + 2, ox + 2, f"{'Ataque':<14} {'Tool':<10} {'MITRE':<12} {'Desc':<18}"[:w - 4])
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_UNDERLINE)
        list_top = oy + 3
        visible = h - 5
        scroll = max(0, cursor - visible + 1)
        for i in range(scroll, min(scroll + visible, len(attacks))):
            a = attacks[i]
            row = list_top + (i - scroll)
            if row >= oy + h - 1:
                break
            name  = a["name"][:13]
            tool  = a.get("tool", "")[:9]
            mitre = a.get("mitre_re", "")[:11]
            desc  = a.get("description", "")[:17]
            # detectar si es plugin por el prefijo en category
            is_plugin = str(a.get("category", "")).startswith("plugin:")
            prefix = "P " if is_plugin else "  "
            line_text = f"{name:<14}{tool:<10}{mitre:<12}{desc}"[:w - 6]

            if i == cursor:
                pair = PAIR_STATUS_WARN if is_plugin else PAIR_STATUS_ERR
                stdscr.attron(curses.color_pair(pair) | curses.A_BOLD)
                stdscr.addstr(row, ox + 2, f"►{prefix}{line_text}".ljust(w - 4))
                stdscr.attroff(curses.color_pair(pair) | curses.A_BOLD)
            else:
                pair = PAIR_STATUS_OK if is_plugin else PAIR_OVERLAY_BG
                stdscr.attron(curses.color_pair(pair))
                stdscr.addstr(row, ox + 2, f" {prefix}{line_text}".ljust(w - 4))
                stdscr.attroff(curses.color_pair(pair))
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(attacks) - 1, cursor + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            return attacks[cursor]["name"]
        elif key == 27:
            return None


# ── Device/target selector (table with IP + tags + type) ───────

def device_select_overlay(stdscr, title: str, devices: list, current_ip: str = "") -> Optional[str]:
    """
    devices: list of DeviceEntry objects.
    Returns selected device IP or None on cancel.
    """
    if not devices:
        return None
    cursor = 0
    for i, d in enumerate(devices):
        if d.ip == current_ip:
            cursor = i
            break
    maxy, maxx = stdscr.getmaxyx()
    w = min(62, maxx - 4)
    h = min(len(devices) + 5, maxy - 4)
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2
    while True:
        _draw_box(stdscr, oy, ox, h, w, title, "↑↓=navegar  Enter=ok  Esc=cancelar")
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_UNDERLINE)
        stdscr.addstr(oy + 2, ox + 2, f"{'IP':<16} {'Type':<10} {'Tags':<20} {'Role':<8}"[:w - 4])
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_UNDERLINE)
        list_top = oy + 3
        visible = h - 5
        scroll = max(0, cursor - visible + 1)
        for i in range(scroll, min(scroll + visible, len(devices))):
            d = devices[i]
            row = list_top + (i - scroll)
            if row >= oy + h - 1:
                break
            tags = " ".join(d.tags)[:19] if d.tags else ""
            dtype = (d.device_type or "?")[:9]
            if i == cursor:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(row, ox + 2, f"► {d.ip:<15} {dtype:<10} {tags:<20} {d.role:<8}"[:w - 4].ljust(w - 4))
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(row, ox + 2, f"  {d.ip:<15} {dtype:<10} {tags:<20} {d.role:<8}"[:w - 4].ljust(w - 4))
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            cursor = max(0, cursor - 1)
        elif key == curses.KEY_DOWN:
            cursor = min(len(devices) - 1, cursor + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            return devices[cursor].ip
        elif key == 27:
            return None


# ── Generic text input overlay ──────────────────────────────────

def text_input_overlay(stdscr, title: str, current: str = "") -> Optional[str]:
    curses.curs_set(1)
    curses.echo()
    maxy, maxx = stdscr.getmaxyx()
    w = min(50, maxx - 4)
    h = 5
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2
    _draw_box(stdscr, oy, ox, h, w, title, "Enter=ok  Esc=cancelar")
    iy, ix, iw = oy + 2, ox + 2, w - 4
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
    stdscr.addstr(iy, ix, current[:iw].ljust(iw))
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
    stdscr.move(iy, ix + len(current[:iw]))
    stdscr.refresh()
    buf = list(current)
    while True:
        ch = stdscr.getch()
        if ch == 27:
            curses.noecho()
            curses.curs_set(0)
            return None
        if ch in (curses.KEY_ENTER, 10, 13):
            curses.noecho()
            curses.curs_set(0)
            return "".join(buf)
        if ch in (curses.KEY_BACKSPACE, 127, 8) and buf:
            buf.pop()
        elif 32 <= ch <= 126 and len(buf) < iw:
            buf.append(chr(ch))
        elif ch == -1:
            continue
        text = "".join(buf)
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(iy, ix, text[:iw].ljust(iw))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.move(iy, ix + min(len(text), iw))
        stdscr.refresh()


# ═══════════════════════════════════════════════════════════════
# #8: DATE/TIME WHEEL SELECTOR
# ═══════════════════════════════════════════════════════════════

def time_wheel_overlay(stdscr, title: str = "Tiempo", current: str = "00:00:00") -> Optional[str]:
    """
    HH:MM:SS wheel selector.
    ←→ = move between slots, ↑↓ = increment/decrement.
    Returns "HH:MM:SS" or None on cancel.
    """
    parts = current.split(":")
    vals = [0, 0, 0]
    for i, p in enumerate(parts[:3]):
        try:
            vals[i] = int(p)
        except ValueError:
            pass
    maxes = [23, 59, 59]
    slot = 0  # 0=H, 1=M, 2=S
    labels = ["HH", "MM", "SS"]

    maxy, maxx = stdscr.getmaxyx()
    w = 36
    h = 7
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2

    while True:
        _draw_box(stdscr, oy, ox, h, w, title, "←→=slot  ↑↓=valor  Enter=ok  Esc=×")

        # draw arrows and values
        for i in range(3):
            cx = ox + 6 + i * 10
            val_str = f"{vals[i]:02d}"
            lbl = labels[i]

            # up arrow
            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
                stdscr.addstr(oy + 2, cx, " ▲ ")
                stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 2, cx, " ▲ ")
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            # value
            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(oy + 3, cx - 1, f"[{val_str}]")
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 3, cx - 1, f" {val_str} ")
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            # down arrow
            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
                stdscr.addstr(oy + 4, cx, " ▼ ")
                stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 4, cx, " ▼ ")
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            # label
            stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
            stdscr.addstr(oy + 5, cx, f" {lbl}")
            stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

        # separators
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)
        stdscr.addstr(oy + 3, ox + 14, ":")
        stdscr.addstr(oy + 3, ox + 24, ":")
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)

        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_LEFT:
            slot = max(0, slot - 1)
        elif key == curses.KEY_RIGHT:
            slot = min(2, slot + 1)
        elif key == curses.KEY_UP:
            vals[slot] = (vals[slot] + 1) % (maxes[slot] + 1)
        elif key == curses.KEY_DOWN:
            vals[slot] = (vals[slot] - 1) % (maxes[slot] + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            return f"{vals[0]:02d}:{vals[1]:02d}:{vals[2]:02d}"
        elif key == 27:
            return None


def datetime_wheel_overlay(stdscr, title: str = "Fecha y Hora",
                           current: str = "01/01/2025 00:00:00") -> Optional[str]:
    """
    DD/MM/YYYY HH:MM:SS wheel selector (6 slots).
    ←→ = move between slots, ↑↓ = increment/decrement.
    Returns "DD/MM/YYYY HH:MM:SS" or None on cancel.
    """
    # parse current
    parts = current.replace("/", " ").replace(":", " ").split()
    vals = [1, 1, 2025, 0, 0, 0]
    for i, p in enumerate(parts[:6]):
        try:
            vals[i] = int(p)
        except ValueError:
            pass
    maxes = [31, 12, 2099, 23, 59, 59]
    mins = [1, 1, 2024, 0, 0, 0]
    labels = ["DD", "MM", "YYYY", "HH", "MM", "SS"]
    slot = 0

    maxy, maxx = stdscr.getmaxyx()
    w = 54
    h = 7
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2

    while True:
        _draw_box(stdscr, oy, ox, h, w, title, "←→=slot  ↑↓=valor  Enter=ok  Esc=×")

        for i in range(6):
            cx = ox + 3 + i * 8
            if i >= 3:
                cx += 2  # extra space between date and time
            vw = 4 if i == 2 else 2  # YYYY needs 4 chars
            val_str = f"{vals[i]:0{vw}d}"

            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
                stdscr.addstr(oy + 2, cx, " ▲ ".center(vw + 2))
                stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(oy + 3, cx, f"[{val_str}]")
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
                stdscr.addstr(oy + 4, cx, " ▼ ".center(vw + 2))
                stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 2, cx, " ▲ ".center(vw + 2))
                stdscr.addstr(oy + 3, cx, f" {val_str} ")
                stdscr.addstr(oy + 4, cx, " ▼ ".center(vw + 2))
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
            stdscr.addstr(oy + 5, cx, f" {labels[i]}".center(vw + 2))
            stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

        # separators
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)
        stdscr.addstr(oy + 3, ox + 3 + 1 * 8 - 1, "/")
        stdscr.addstr(oy + 3, ox + 3 + 2 * 8 - 1, "/")
        stdscr.addstr(oy + 3, ox + 3 + 3 * 8 + 2 + 1 * 8 - 1, ":")
        stdscr.addstr(oy + 3, ox + 3 + 3 * 8 + 2 + 2 * 8 - 1, ":")
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)

        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_LEFT:
            slot = max(0, slot - 1)
        elif key == curses.KEY_RIGHT:
            slot = min(5, slot + 1)
        elif key == curses.KEY_UP:
            vals[slot] += 1
            if vals[slot] > maxes[slot]:
                vals[slot] = mins[slot]
        elif key == curses.KEY_DOWN:
            vals[slot] -= 1
            if vals[slot] < mins[slot]:
                vals[slot] = maxes[slot]
        elif key in (curses.KEY_ENTER, 10, 13):
            return f"{vals[0]:02d}/{vals[1]:02d}/{vals[2]:04d} {vals[3]:02d}:{vals[4]:02d}:{vals[5]:02d}"
        elif key == 27:
            return None
