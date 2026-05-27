import sys
import platform
from design.Menu_types import Section

try:
    import curses
except ImportError:
    if platform.system() == "Windows":
        sys.stderr.write(
            "ERROR: 'curses' not found.\n"
            "Install with:  pip install windows-curses\n"
        )
    else:
        sys.stderr.write(
            "ERROR: 'curses' not found.\n"
            "Install with:  sudo apt-get install libncurses5-dev\n"
        )
    sys.exit(1)

from dataclasses import dataclass, field
from typing import Callable, Optional

from design.Menu_scenario  import SCENARIO_SECTION
from design.Menu_devices   import DEVICES_SECTION
from design.Menu_benign    import BENIGN_SECTION
from design.Menu_attacks   import ATTACKS_SECTION
from design.Menu_timeline  import TIMELINE_SECTION
from design.Menu_live      import LIVE_SECTION
from design.Menu_logs      import LOGS_SECTION
from design.Menu_artifacts import ARTIFACTS_SECTION
from design.Menu_help      import HELP_SECTION

HOME_SECTION = Section(
    key="home",
    label="Home",
    hint="Vista general. ↑↓ navegar · Enter abrir · ? ayuda · Ctrl+R ejecutar · Ctrl+L logs",
    content_lines=[
        "Experiment ID : EXP-2026-05-011",
        "Environment   : SmartHomeLab-v1",
        "Orchestrator  : 1.0.0",
        "Last run      : 2026-05-11 18:32",
        "",
        "Quick summary",
        "  Devices ready      : 8",
        "  Benign profiles    : 4",
        "  Attack modules     : 5",
        "  Scheduled events   : 12",
        "  Last PCAP          : exp-011-run02.pcap",
        "  Last metadata      : exp-011-run02.json",
        "",
        "Quick actions",
        "  [Enter]   Open selected section",
        "  [Ctrl+R]  Start scenario",
        "  [Ctrl+S]  Save current scenario",
        "  [/]       Search section",
    ],
    actions=["Enter Open selected", "Ctrl+R Start scenario", "Ctrl+S Save", "/ Search"],
)

SECTIONS: list[Section] = [
    HOME_SECTION,
    SCENARIO_SECTION,
    DEVICES_SECTION,
    BENIGN_SECTION,
    ATTACKS_SECTION,
    TIMELINE_SECTION,
    LIVE_SECTION,
    LOGS_SECTION,
    ARTIFACTS_SECTION,
    HELP_SECTION,
]

PAIR_HEADER_BG    = 1
PAIR_MENU_NORMAL  = 2
PAIR_MENU_SEL     = 3
PAIR_MENU_ARROW   = 4
PAIR_CONTENT      = 5
PAIR_HINT_BG      = 6
PAIR_BORDER       = 7
PAIR_OVERLAY_BG   = 8
PAIR_OVERLAY_TTL  = 9
PAIR_STATUS_IDLE  = 10
PAIR_STATUS_RUN   = 11
PAIR_STATUS_EDIT  = 12
PAIR_LABEL_DIM    = 13

MENU_WIDTH    = 22
HINT_HEIGHT   = 2
HEADER_HEIGHT = 1


def _init_colors() -> None:
    curses.use_default_colors()
    curses.init_pair(PAIR_HEADER_BG,   curses.COLOR_WHITE,  curses.COLOR_CYAN)
    curses.init_pair(PAIR_MENU_NORMAL, curses.COLOR_WHITE,  -1)
    curses.init_pair(PAIR_MENU_SEL,    curses.COLOR_WHITE,  curses.COLOR_CYAN)
    curses.init_pair(PAIR_MENU_ARROW,  curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_CONTENT,     curses.COLOR_WHITE,  -1)
    curses.init_pair(PAIR_HINT_BG,     curses.COLOR_WHITE,  curses.COLOR_CYAN)
    curses.init_pair(PAIR_BORDER,      curses.COLOR_CYAN,   -1)
    curses.init_pair(PAIR_OVERLAY_BG,  curses.COLOR_WHITE,  curses.COLOR_BLUE)
    curses.init_pair(PAIR_OVERLAY_TTL, curses.COLOR_YELLOW, curses.COLOR_BLUE)
    curses.init_pair(PAIR_STATUS_IDLE, curses.COLOR_GREEN,  -1)
    curses.init_pair(PAIR_STATUS_RUN,  curses.COLOR_RED,    -1)
    curses.init_pair(PAIR_STATUS_EDIT, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_LABEL_DIM,   8,                   -1)


def _draw_header(
    stdscr,
    experiment_id: str,
    status: str,
    capture: str,
) -> None:
    _, max_x = stdscr.getmaxyx()
    raw = f" SH-DATASET :: exp={experiment_id} :: status={status} :: capture={capture} "
    header = raw.ljust(max_x)[:max_x - 1]
    stdscr.attron(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)
    stdscr.addstr(0, 0, header)
    stdscr.attroff(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)


def _draw_sidebar(
    stdscr,
    sections: list[Section],
    selected_idx: int,
    top_y: int,
    bottom_y: int,
) -> None:
    menu_bottom = bottom_y - HINT_HEIGHT

    for y in range(top_y, menu_bottom):
        stdscr.attron(curses.color_pair(PAIR_BORDER))
        stdscr.addch(y, MENU_WIDTH, curses.ACS_VLINE)
        stdscr.attroff(curses.color_pair(PAIR_BORDER))

    stdscr.attron(curses.color_pair(PAIR_LABEL_DIM) | curses.A_BOLD)
    stdscr.addstr(top_y, 2, "MENU")
    stdscr.attroff(curses.color_pair(PAIR_LABEL_DIM) | curses.A_BOLD)

    row = top_y + 1
    for i, sec in enumerate(sections):
        if row >= menu_bottom:
            break
        prefix    = "> " if i == selected_idx else "  "
        max_len   = MENU_WIDTH - 4
        label     = sec.label if len(sec.label) <= max_len else sec.label[:max_len - 2] + ".."

        if i == selected_idx:
            stdscr.attron(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
            stdscr.addstr(row, 2, f"{prefix}{label}")
            padding = MENU_WIDTH - 2 - len(prefix) - len(label)
            if padding > 0:
                stdscr.addstr(row, 2 + len(prefix) + len(label), " " * padding)
            stdscr.attroff(curses.color_pair(PAIR_MENU_SEL) | curses.A_BOLD)
        else:
            stdscr.attron(curses.color_pair(PAIR_MENU_ARROW))
            stdscr.addstr(row, 2, prefix)
            stdscr.attroff(curses.color_pair(PAIR_MENU_ARROW))
            stdscr.attron(curses.color_pair(PAIR_MENU_NORMAL))
            stdscr.addstr(row, 2 + len(prefix), label)
            stdscr.attroff(curses.color_pair(PAIR_MENU_NORMAL))
        row += 1


def _draw_content(
    stdscr,
    section: Section,
    top_y: int,
    bottom_y: int,
) -> None:
    _, max_x    = stdscr.getmaxyx()
    left        = MENU_WIDTH + 1
    width       = max_x - 1 - left
    content_bot = bottom_y - HINT_HEIGHT

    stdscr.attron(curses.color_pair(PAIR_CONTENT) | curses.A_BOLD)
    stdscr.addstr(top_y, left + 2, section.label.upper())
    stdscr.attroff(curses.color_pair(PAIR_CONTENT) | curses.A_BOLD)

    row = top_y + 1
    for line in section.content_lines:
        if row >= content_bot:
            break
        display = line[:width - 2]
        stdscr.attron(curses.color_pair(PAIR_CONTENT))
        try:
            stdscr.addstr(row, left + 2, display)
        except curses.error:
            pass
        stdscr.attroff(curses.color_pair(PAIR_CONTENT))
        row += 1


def _draw_hint(stdscr, hint_text: str, bottom_y: int) -> None:
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

    display = f" Hint: {hint_text} "[:max_x - 1].ljust(max_x - 1)
    stdscr.attron(curses.color_pair(PAIR_HINT_BG))
    try:
        stdscr.addstr(hint_row + 1, 0, display)
    except curses.error:
        pass
    stdscr.attroff(curses.color_pair(PAIR_HINT_BG))


def _draw_borders(stdscr, top_y: int, bottom_y: int) -> None:
    _, max_x    = stdscr.getmaxyx()
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
        stdscr.addch(y, 0,        curses.ACS_VLINE)
        try:
            stdscr.addch(y, max_x - 1, curses.ACS_VLINE)
        except curses.error:
            pass
    stdscr.attroff(curses.color_pair(PAIR_BORDER))


class MenuApp:

    def __init__(self) -> None:
        self.selected_idx:      int  = 0
        self.show_context_help: bool = False
        self.status:            str  = "IDLE"
        self.capture:           str  = "READY"
        self.experiment_id:     str  = "EXP-2026-05-011"
        self.running:           bool = True
        self._action_cb: Optional[Callable[[str, str], None]] = None

    def set_action_callback(self, callback: Callable[[str, str], None]) -> None:
        self._action_cb = callback

    def run(self, stdscr) -> None:
        _init_colors()
        stdscr.keypad(True)
        stdscr.nodelay(False)
        curses.curs_set(0)
        curses.noecho()
        while self.running:
            self._render(stdscr)
            self._handle_key(stdscr.getch())

    def _render(self, stdscr) -> None:
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 10 or max_x < 40:
            stdscr.addstr(0, 0, "Terminal too small. Min 40x10.")
            stdscr.refresh()
            return

        top_y    = HEADER_HEIGHT
        bottom_y = max_y
        section  = SECTIONS[self.selected_idx]

        _draw_header(stdscr, self.experiment_id, self.status, self.capture)
        _draw_borders(stdscr, top_y, bottom_y)
        _draw_sidebar(stdscr, SECTIONS, self.selected_idx, top_y, bottom_y)
        _draw_content(stdscr, section, top_y, bottom_y)
        _draw_hint(stdscr, section.hint, bottom_y)
        stdscr.refresh()

    def _handle_key(self, key: int) -> None:
        section = SECTIONS[self.selected_idx]

        nav_map: dict[int, Callable[[], None]] = {
            curses.KEY_UP:    lambda: setattr(self, "selected_idx", max(0, self.selected_idx - 1)),
            curses.KEY_DOWN:  lambda: setattr(self, "selected_idx", min(len(SECTIONS) - 1, self.selected_idx + 1)),
            ord("\t"):        lambda: setattr(self, "selected_idx", (self.selected_idx + 1) % len(SECTIONS)),
        }
        if key in nav_map:
            nav_map[key]()
            return

        if key in (curses.KEY_ENTER, 10, 13):
            self._dispatch(section.key, "enter")
        elif key == curses.KEY_ESCAPE:
            self.selected_idx = 0
        elif key == ord("q"):
            self.selected_idx = 0
        elif key == 19:   # Ctrl+S
            self._dispatch(section.key, "ctrl_s")
        elif key == 18:   # Ctrl+R
            self.status  = "RUNNING"
            self.capture = "ACTIVE"
            self._dispatch(section.key, "ctrl_r")
        elif key == 16:   # Ctrl+P
            self.status  = "PAUSED"
            self.capture = "PAUSED"
            self._dispatch(section.key, "ctrl_p")
        elif key == 12:   # Ctrl+L
            for i, s in enumerate(SECTIONS):
                if s.key == "logs":
                    self.selected_idx = i
                    break
        elif key == 24:   # Ctrl+X
            self.status  = "IDLE"
            self.capture = "READY"
            self._dispatch(section.key, "ctrl_x")
        else:
            char_actions: dict[str, str] = {
                "a": "add",    "d": "delete", "e": "edit",
                "r": "remove", "t": "tag",    "c": "clone",
                "n": "new",    "m": "move",   "x": "delete_event",
                "v": "validate", "f": "filter", "/": "search",
            }
            ch = chr(key).lower() if 0 < key < 128 else ""
            if ch in char_actions:
                self._dispatch(section.key, char_actions[ch])
            elif key == ord(" "):
                self._dispatch(section.key, "toggle")

    def _dispatch(self, section_key: str, action: str) -> None:
        if self._action_cb is not None:
            self._action_cb(section_key, action)

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