"""
Entrada: None
Salida: Module with overlay widget functions
Descripción: Overlay widgets — specialized modals and inline selectors.
"""
from __future__ import annotations
import curses
from typing import Optional


PAIR_OVERLAY_BG = 8
PAIR_OVERLAY_TTL = 9
PAIR_MENU_SEL = 3
PAIR_STATUS_OK = 10
PAIR_STATUS_ERR = 11
PAIR_STATUS_WARN = 12
PAIR_FIELD_HL = 14



"""
Entrada: stdscr, oy, ox, h, w, title, footer
Salida: None
Descripción: Draws a bordered overlay box with title and footer.
"""
def _draw_box(stdscr, oy, ox, h, w, title="", footer="Enter=ok  Esc=cancel"):
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


"""
Entrada: stdscr, current (str), roles (list[str])
Salida: str
Descripción: Shows a role selector overlay and returns the chosen role.
"""
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
        _draw_box(stdscr, oy, ox, h, w, "Select Role")
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



_METHOD_DESC = {
    "nmap": "Host discovery + port scan",
    "arp": "ARP broadcast (fast, LAN only)",
    "all": "nmap + ARP combined",
}


"""
Entrada: stdscr, current (str), methods (list[str])
Salida: str
Descripción: Shows a scan method selector overlay and returns the chosen method.
"""
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
        _draw_box(stdscr, oy, ox, h, w, "Scan Method")
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



"""
Entrada: stdscr, attacks (list[dict]), current (str)
Salida: Optional[str]
Descripción: Shows an attack selector overlay. attacks is a list of dicts with
             name/description/mitre_ref. Returns the selected attack name or None.
"""
def attack_select_overlay(stdscr, attacks: list[dict], current: str = "") -> Optional[str]:
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
        _draw_box(stdscr, oy, ox, h, w, "Select Attack", "↑↓=navigate  Enter=ok  Esc=cancel")
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_UNDERLINE)
        stdscr.addstr(oy + 2, ox + 2, f"{'Attack':<14} {'Tool':<10} {'MITRE':<12} {'Desc':<18}"[:w - 4])
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



"""
Entrada: stdscr, title (str), devices (list), current_ip (str)
Salida: Optional[str]
Descripción: Shows a device selector overlay. devices is a list of DeviceEntry
             objects. Returns the selected device IP or None.
"""
def device_select_overlay(stdscr, title: str, devices: list, current_ip: str = "") -> Optional[str]:
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
        _draw_box(stdscr, oy, ox, h, w, title, "↑↓=navigate  Enter=ok  Esc=cancel")
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



"""
Entrada: stdscr, title (str), current (str)
Salida: Optional[str]
Descripción: Shows a text input overlay and returns the entered text or None.
"""
def text_input_overlay(stdscr, title: str, current: str = "") -> Optional[str]:
    curses.curs_set(1)
    curses.echo()
    maxy, maxx = stdscr.getmaxyx()
    w = min(50, maxx - 4)
    h = 5
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2
    _draw_box(stdscr, oy, ox, h, w, title, "Enter=ok  Esc=cancel")
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



"""
Entrada: stdscr, title (str), current (str)
Salida: Optional[str]
Descripción: HH:MM:SS wheel selector. ←→ moves between slots, ↑↓ increments.
             Returns "HH:MM:SS" or None on cancel.
"""
def time_wheel_overlay(stdscr, title: str = "Time", current: str = "00:00:00") -> Optional[str]:
    parts = current.split(":")
    vals = [0, 0, 0]
    for i, p in enumerate(parts[:3]):
        try:
            vals[i] = int(p)
        except ValueError:
            pass
    maxes = [23, 59, 59]
    slot = 0
    labels = ["HH", "MM", "SS"]

    maxy, maxx = stdscr.getmaxyx()
    w = 36
    h = 7
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2

    while True:
        _draw_box(stdscr, oy, ox, h, w, title, "←→=slot  ↑↓=value  Enter=ok  Esc=×")

        for i in range(3):
            cx = ox + 6 + i * 10
            val_str = f"{vals[i]:02d}"
            lbl = labels[i]

            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
                stdscr.addstr(oy + 2, cx, " ▲ ")
                stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 2, cx, " ▲ ")
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(oy + 3, cx - 1, f"[{val_str}]")
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 3, cx - 1, f" {val_str} ")
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
                stdscr.addstr(oy + 4, cx, " ▼ ")
                stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 4, cx, " ▼ ")
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
            stdscr.addstr(oy + 5, cx, f" {lbl}")
            stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

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



"""
Entrada: stdscr, title (str), current (str)
Salida: Optional[str]
Descripción: Duration wheel: Mo:DD:HH:MM:SS. ←→ moves between slots, ↑↓ increments.
             Returns formatted duration string.
"""
def duration_wheel_overlay(stdscr, title: str = "Duration",
                           current: str = "00:00:30") -> Optional[str]:
    vals = [0, 0, 0, 0, 0]
    if isinstance(current, str):
        current = current.strip()
        if current.endswith("M"):
            try: vals[0] = int(current[:-1])
            except ValueError: pass
        elif current.endswith("w"):
            try: vals[1] = int(current[:-1]) * 7
            except ValueError: pass
        elif current.endswith("d"):
            try: vals[1] = int(current[:-1])
            except ValueError: pass
        elif current.endswith("h"):
            try: vals[2] = int(current[:-1])
            except ValueError: pass
        elif current.endswith("m") and not current.endswith("mm"):
            try: vals[3] = int(current[:-1])
            except ValueError: pass
        elif ":" in current:
            parts = current.split(":")
            try:
                if len(parts) == 3:
                    vals[2], vals[3], vals[4] = int(parts[0]), int(parts[1]), int(parts[2])
                elif len(parts) == 4:
                    vals[1], vals[2], vals[3], vals[4] = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
            except ValueError:
                pass

    maxes = [12, 365, 23, 59, 59]
    labels = ["Mo", "DD", "HH", "MM", "SS"]
    slot = 2

    maxy, maxx = stdscr.getmaxyx()
    w = 52
    h = 7
    oy = (maxy - h) // 2
    ox = (maxx - w) // 2

    while True:
        _draw_box(stdscr, oy, ox, h, w, title, "←→=slot  ↑↓=value  Enter=ok  Esc=×")

        for i in range(5):
            cx = ox + 4 + i * 9
            vw = 3 if i == 1 else 2
            val_str = f"{vals[i]:0{vw}d}"
            lbl = labels[i]

            stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
            stdscr.addstr(oy + 1, cx, f" {lbl} ")
            stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            pair = PAIR_FIELD_HL if i == slot else PAIR_OVERLAY_BG
            stdscr.attron(curses.color_pair(pair) | (curses.A_BOLD if i == slot else 0))
            stdscr.addstr(oy + 2, cx, " ▲  ")
            stdscr.attroff(curses.color_pair(pair) | (curses.A_BOLD if i == slot else 0))

            if i == slot:
                stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
                stdscr.addstr(oy + 3, cx - 1, f"[{val_str}] ")
                stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                stdscr.addstr(oy + 3, cx - 1, f" {val_str}  ")
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            if i < 4:
                stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
                sep = ":" if i >= 1 else ":"
                stdscr.addstr(oy + 3, cx + vw + 1, sep)
                stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

            stdscr.attron(curses.color_pair(pair) | (curses.A_BOLD if i == slot else 0))
            stdscr.addstr(oy + 4, cx, " ▼  ")
            stdscr.attroff(curses.color_pair(pair) | (curses.A_BOLD if i == slot else 0))

        stdscr.refresh()
        key = stdscr.getch()
        if key == 27:
            return None
        if key in (curses.KEY_ENTER, 10, 13):
            mo, dd, hh, mm, ss = vals
            if mo > 0:
                total_days = mo * 30 + dd
                return f"{total_days}d" if hh == 0 and mm == 0 and ss == 0 else f"{total_days}:{hh:02d}:{mm:02d}:{ss:02d}"
            if dd > 0:
                return f"{dd}:{hh:02d}:{mm:02d}:{ss:02d}"
            return f"{hh:02d}:{mm:02d}:{ss:02d}"
        if key == curses.KEY_LEFT:
            slot = (slot - 1) % 5
        elif key == curses.KEY_RIGHT:
            slot = (slot + 1) % 5
        elif key == curses.KEY_UP:
            vals[slot] = (vals[slot] + 1) % (maxes[slot] + 1)
        elif key == curses.KEY_DOWN:
            vals[slot] = (vals[slot] - 1) % (maxes[slot] + 1)


"""
Entrada: stdscr, title (str), current (str)
Salida: Optional[str]
Descripción: DD/MM/YYYY HH:MM:SS wheel selector (6 slots). ←→ moves between
             slots, ↑↓ increments. Returns "DD/MM/YYYY HH:MM:SS" or None.
"""
def datetime_wheel_overlay(stdscr, title: str = "Date and Time",
                           current: str = "01/01/2025 00:00:00") -> Optional[str]:
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
        _draw_box(stdscr, oy, ox, h, w, title, "←→=slot  ↑↓=value  Enter=ok  Esc=×")

        for i in range(6):
            cx = ox + 3 + i * 8
            if i >= 3:
                cx += 2
            vw = 4 if i == 2 else 2
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
