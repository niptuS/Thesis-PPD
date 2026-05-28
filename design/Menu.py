import sys
import platform

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

from typing import Callable, Optional
from design.Menu_types import Section, FieldMeta

from design.Menu_scenario  import build_scenario_section, SCENARIO_SECTION
from design.Menu_devices   import DEVICES_SECTION
from design.Menu_benign    import BENIGN_SECTION
from design.Menu_attacks   import ATTACKS_SECTION
from design.Menu_timeline  import TIMELINE_SECTION
from design.Menu_logs      import LOGS_SECTION
from design.Menu_live      import build_live_section,      LIVE_SECTION
from design.Menu_artifacts import build_artifacts_section, ARTIFACTS_SECTION
from design.Menu_help      import HELP_SECTION

SAVES_DIR   = "saves/scenarios"
OUTPUT_META = "outputs/metadata"
OUTPUT_PCAP = "outputs/pcap"

HOME_SECTION = Section(
    key="home",
    label="Home",
    hint="← sidebar · → campos · Ctrl+O cargar · Ctrl+S guardar · Ctrl+R ejecutar",
    content_lines=[
        "Experiment ID : —",
        "Environment   : —",
        "Orchestrator  : 1.0.0",
        "",
        "Paths",
        f"  Saves    : {SAVES_DIR}/",
        f"  Metadata : {OUTPUT_META}/",
        f"  PCAP     : {OUTPUT_PCAP}/",
        "",
        "Quick actions",
        "  [Ctrl+O]  Load scenario",
        "  [Ctrl+S]  Save scenario",
        "  [Ctrl+R]  Start scenario",
        "  [Ctrl+L]  Open logs",
        "  [Ctrl+X]  Abort execution",
    ],
    actions=[],
    field_map=[],
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

PAIR_HEADER_BG   = 1
PAIR_MENU_NORMAL = 2
PAIR_MENU_SEL    = 3
PAIR_MENU_ARROW  = 4
PAIR_CONTENT     = 5
PAIR_HINT_BG     = 6
PAIR_BORDER      = 7
PAIR_OVERLAY_BG  = 8
PAIR_OVERLAY_TTL = 9
PAIR_STATUS_OK   = 10
PAIR_STATUS_ERR  = 11
PAIR_STATUS_WARN = 12
PAIR_LABEL_DIM   = 13
PAIR_FIELD_HL    = 14
PAIR_FIELD_EDIT  = 15
PAIR_PANEL_HDR   = 16

MENU_WIDTH    = 22
HINT_HEIGHT   = 2
HEADER_HEIGHT = 1

FOCUS_SIDEBAR = "sidebar"
FOCUS_PANEL   = "panel"

_EDIT_SEP = " : "

def _empty_config():
    try:
        from modules.scenario_editor.config_schema import ScenarioConfig, OutputConfig
        return ScenarioConfig(
            name="", experiment_id="NEW", environment="",
            start_time="00:00:00", planned_duration="00:00:00",
            devices=[], benign_profiles=[], attack_modules=[], timeline=[],
            output=OutputConfig(
                folder=OUTPUT_META,
                capture_enabled=True,
                export_metadata=True,
                export_pcap=True,
            ),
        )
    except Exception:
        return None

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
    curses.init_pair(PAIR_STATUS_OK,   curses.COLOR_GREEN,  -1)
    curses.init_pair(PAIR_STATUS_ERR,  curses.COLOR_RED,    -1)
    curses.init_pair(PAIR_STATUS_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_LABEL_DIM,   8,                   -1)
    curses.init_pair(PAIR_FIELD_HL,    curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(PAIR_FIELD_EDIT,  curses.COLOR_BLACK,  curses.COLOR_YELLOW)
    curses.init_pair(PAIR_PANEL_HDR,   curses.COLOR_YELLOW, -1)

def _get_nested(obj: object, path: str) -> str:
    cur = obj
    for part in path.split("."):
        cur = getattr(cur, part, None)
        if cur is None:
            return ""
    if isinstance(cur, bool):
        return "[x]" if cur else "[ ]"
    return str(cur)

def _set_nested(obj: object, path: str, value: str) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        obj = getattr(obj, part)
    current = getattr(obj, parts[-1])
    if isinstance(current, bool):
        setattr(obj, parts[-1], value.strip().lower() in ("true", "yes", "1", "on", "[x]", "x"))
    else:
        setattr(obj, parts[-1], value)

def _line_label_end(line: str) -> int:
    """Devuelve el índice donde termina el ' : ' en la línea de contenido."""
    idx = line.find(_EDIT_SEP)
    if idx == -1:
        return len(line)
    return idx + len(_EDIT_SEP)

def _draw_header(stdscr, experiment_id: str, status: str, capture: str) -> None:
    _, max_x = stdscr.getmaxyx()
    raw    = f" SH-DATASET :: exp={experiment_id} :: status={status} :: capture={capture} "
    header = raw.ljust(max_x)[:max_x - 1]
    stdscr.attron(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)
    stdscr.addstr(0, 0, header)
    stdscr.attroff(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)

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
        stdscr.addch(y, 0, curses.ACS_VLINE)
        try:
            stdscr.addch(y, max_x - 1, curses.ACS_VLINE)
        except curses.error:
            pass
    stdscr.attroff(curses.color_pair(PAIR_BORDER))

def _draw_sidebar(
    stdscr,
    sections: list[Section],
    selected_idx: int,
    focus: str,
    top_y: int,
    bottom_y: int,
) -> None:
    menu_bottom    = bottom_y - HINT_HEIGHT
    sidebar_active = focus == FOCUS_SIDEBAR

    div_pair = PAIR_BORDER if sidebar_active else PAIR_LABEL_DIM
    for y in range(top_y, menu_bottom):
        stdscr.attron(curses.color_pair(div_pair))
        stdscr.addch(y, MENU_WIDTH, curses.ACS_VLINE)
        stdscr.attroff(curses.color_pair(div_pair))

    hdr_pair = PAIR_PANEL_HDR if sidebar_active else PAIR_LABEL_DIM
    stdscr.attron(curses.color_pair(hdr_pair) | curses.A_BOLD)
    stdscr.addstr(top_y, 2, "MENU" + (" ◀" if sidebar_active else "  "))
    stdscr.attroff(curses.color_pair(hdr_pair) | curses.A_BOLD)

    row = top_y + 1
    for i, sec in enumerate(sections):
        if row >= menu_bottom:
            break
        prefix  = "> " if i == selected_idx else "  "
        max_len = MENU_WIDTH - 4
        label   = sec.label if len(sec.label) <= max_len else sec.label[:max_len - 2] + ".."

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

def _draw_content_with_fields(
    stdscr,
    section: Section,
    field_cursor: int,
    editing_line: int,
    inline_buf: str,
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

    line_to_field: dict[int, FieldMeta] = {fm.line_idx: fm for fm in section.field_map}

    selected_line = -1
    if 0 <= field_cursor < len(section.field_map):
        selected_line = section.field_map[field_cursor].line_idx

    row = top_y + 1
    for li, line in enumerate(section.content_lines):
        if row >= content_bot:
            break

        fm = line_to_field.get(li)

        if fm is not None and li == editing_line:
            sep_end = _line_label_end(line)
            label_part = line[:sep_end]
            display    = f"{label_part}(editando) {inline_buf}"[:width - 2]
            stdscr.attron(curses.color_pair(PAIR_FIELD_EDIT) | curses.A_BOLD)
            try:
                stdscr.addstr(row, left + 2, display.ljust(width - 2))
            except curses.error:
                pass
            stdscr.attroff(curses.color_pair(PAIR_FIELD_EDIT) | curses.A_BOLD)

        elif fm is not None and li == selected_line:
            display = line[:width - 2]
            stdscr.attron(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)
            try:
                stdscr.addstr(row, left + 2, display.ljust(width - 2))
            except curses.error:
                pass
            stdscr.attroff(curses.color_pair(PAIR_FIELD_HL) | curses.A_BOLD)

        else:
            stdscr.attron(curses.color_pair(PAIR_CONTENT))
            try:
                stdscr.addstr(row, left + 2, line[:width - 2])
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
        "ok":   PAIR_STATUS_OK,
        "err":  PAIR_STATUS_ERR,
        "warn": PAIR_STATUS_WARN,
    }
    pair   = color_map.get(kind, PAIR_HINT_BG)
    prefix = " Hint: " if kind == "hint" else " "
    disp   = f"{prefix}{text} "[:max_x - 1].ljust(max_x - 1)
    attr   = curses.color_pair(pair) | (curses.A_BOLD if kind != "hint" else 0)
    stdscr.attron(attr)
    try:
        stdscr.addstr(hint_row + 1, 0, disp)
    except curses.error:
        pass
    stdscr.attroff(attr)

def _file_prompt_overlay(stdscr, default: str) -> str:
    """Overlay mínimo solo para pedir ruta de archivo."""
    max_y, max_x = stdscr.getmaxyx()
    overlay_w    = min(64, max_x - 4)
    overlay_h    = 5
    oy           = (max_y - overlay_h) // 2
    ox           = (max_x - overlay_w) // 2

    for y in range(oy, oy + overlay_h):
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(y, ox, " " * overlay_w)
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

    stdscr.attron(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)
    stdscr.addstr(oy,     ox, " Cargar escenario — ruta del archivo "[:overlay_w])
    stdscr.addstr(oy + 4, ox, " [Enter] Confirmar   [Esc] Cancelar "[:overlay_w])
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TTL) | curses.A_BOLD)

    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
    stdscr.addstr(oy + 2, ox + 2, "> ")
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

    curses.curs_set(1)
    curses.echo()
    input_x = ox + 4
    input_y = oy + 2
    input_w = overlay_w - 6
    buf     = list(default)

    def _refresh() -> None:
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(input_y, input_x, "".join(buf)[:input_w].ljust(input_w))
        stdscr.move(input_y, input_x + min(len(buf), input_w))
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.refresh()

    _refresh()
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
        _refresh()

    curses.noecho()
    curses.curs_set(0)
    return "" if canceled else "".join(buf)

class MenuApp:

    def __init__(self) -> None:
        self.selected_idx: int  = 0
        self.focus: str  = FOCUS_SIDEBAR
        self.field_cursor: int  = 0
        self.status: str  = "IDLE"
        self.capture: str  = "READY"
        self.experiment_id: str  = "NEW"
        self.running: bool = True
        self.active_config = _empty_config()
        self._status_msg: str  = ""
        self._status_kind: str  = "hint"
        self._editing_line: int  = -1
        self._inline_buf: list = []
        self._stdscr = None
        self._action_cb: Optional[Callable[[str, str], None]] = None
        self._manager: object   = None
        self._scenario_start: object   = None
        self._planned_duration_s: int      = 0
        self._next_event_label: str      = "—"
        self._active_benign: str      = "—"
        self._active_attack: str      = "—"
        self._selected_artifact: str      = ""
        self._artifact_cursor: int = 0

    def set_action_callback(self, cb: Callable[[str, str], None]) -> None:
        self._action_cb = cb

    def load_config(self, config) -> None:
        self.active_config = config
        self.experiment_id = config.experiment_id
        self._refresh_scenario_section()
        self._refresh_home_section()

    def set_status(self, message: str, kind: str = "ok") -> None:
        self._status_msg  = message
        self._status_kind = kind

    def _section(self) -> Section:
        return SECTIONS[self.selected_idx]

    def _section_key(self) -> str:
        return self._section().key

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
        live_sec = build_live_section(
            manager            = manager,
            scenario_start     = scenario_start,
            planned_duration_s = planned_duration_s,
            next_event_label   = next_event_label,
            active_benign      = active_benign,
            active_attack      = active_attack,
        )
        art_sec = build_artifacts_section(
            manager            = manager,
            selected_artifact  = selected_artifact,
            cursor_idx         = self.field_cursor if self._section_key() == "artifacts" else 0,
        )
        for i, sec in enumerate(SECTIONS):
            if sec.key == "live":
                SECTIONS[i] = live_sec
            elif sec.key == "artifacts":
                SECTIONS[i] = art_sec

    def _refresh_scenario_section(self) -> None:
        if self.active_config is None:
            return
        updated = build_scenario_section(self.active_config)
        for i, sec in enumerate(SECTIONS):
            if sec.key == "scenario":
                SECTIONS[i] = updated
                break

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
                f"Environment   : {cfg.environment}",
                "Orchestrator  : 1.0.0",
                "",
                "Loaded scenario",
                f"  Name          : {cfg.name}",
                f"  Start time    : {cfg.start_time}",
                f"  Duration      : {cfg.planned_duration}",
                "",
                "Paths",
                f"  Saves    : {SAVES_DIR}/",
                f"  Metadata : {OUTPUT_META}/",
                f"  PCAP     : {OUTPUT_PCAP}/",
            ],
            actions=[],
            field_map=[],
        )
        for i, sec in enumerate(SECTIONS):
            if sec.key == "home":
                SECTIONS[i] = updated
                break

    def run(self, stdscr) -> None:
        self._stdscr = stdscr
        _init_colors()
        stdscr.keypad(True)
        stdscr.nodelay(False)
        curses.curs_set(0)
        curses.noecho()
        while self.running:
            self._render(stdscr)
            if self._editing_line >= 0:
                self._handle_inline_key(stdscr.getch())
            else:
                self._handle_key(stdscr.getch())

    def _render(self, stdscr) -> None:
        stdscr.clear()
        if hasattr(self, "_manager"):
            self.update_runtime_sections(
                manager            = self._manager,
                scenario_start     = self._scenario_start,
                planned_duration_s = self._planned_duration_s,
                next_event_label   = self._next_event_label,
                active_benign      = self._active_benign,
                active_attack      = self._active_attack,
                selected_artifact  = self._selected_artifact,
            )
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 10 or max_x < 40:
            stdscr.addstr(0, 0, "Terminal too small. Min 40x10.")
            stdscr.refresh()
            return

        top_y    = HEADER_HEIGHT
        bottom_y = max_y
        section  = self._section()

        _draw_header(stdscr, self.experiment_id, self.status, self.capture)
        _draw_borders(stdscr, top_y, bottom_y)
        _draw_sidebar(stdscr, SECTIONS, self.selected_idx, self.focus, top_y, bottom_y)

        fc = self.field_cursor if self.focus == FOCUS_PANEL else -1
        _draw_content_with_fields(
            stdscr, section, fc,
            self._editing_line, "".join(self._inline_buf),
            top_y, bottom_y,
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
        section = SECTIONS[self.selected_idx]

        if key == 19:    self._dispatch(section.key, "ctrl_s")
        elif key == 18:  self._do_run()
        elif key == 16:  self._do_pause()
        elif key == 24:  self._do_abort()
        elif key == 12:  self._jump_to("logs")
        elif key == 15:  self._do_load_prompt()
        elif self.focus == FOCUS_SIDEBAR:
            self._key_sidebar(key)
        elif self.focus == FOCUS_PANEL:
            if section.key == "artifacts":
                self._handle_artifacts_key(key)
            else:
                self._key_panel(key)

    def _handle_enter(self, section) -> None:
        if section.key == "artifacts":
            self._artifacts_show_info()
        else:
            self._dispatch(section.key, "enter")

    def _handle_artifacts_key(self, key: int) -> None:
        artifact_keys: dict[int, Callable[[], None]] = {
            curses.KEY_UP:   lambda: self._artifacts_move(-1),
            curses.KEY_DOWN: lambda: self._artifacts_move(1),
            ord("e"):        self._artifacts_export,
            ord("E"):        self._artifacts_export,
            ord("c"):        self._artifacts_checksum,
            ord("C"):        self._artifacts_checksum,
        }
        action = artifact_keys.get(key)
        if action:
            action()

    def _handle_generic_key(self, key: int, section) -> None:
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
        elif key == curses.KEY_DOWN:
            self.selected_idx = min(len(SECTIONS) - 1, self.selected_idx + 1)
            self.field_cursor = 0
        elif key == ord("\t"):
            self.selected_idx = (self.selected_idx + 1) % len(SECTIONS)
            self.field_cursor = 0
        elif key in (curses.KEY_RIGHT, curses.KEY_ENTER, 10, 13):
            if self._section().field_map:
                self.focus        = FOCUS_PANEL
                self.field_cursor = 0
        elif key in (27, ord("q")):
            self.selected_idx = 0
            self.field_cursor = 0

    def _key_panel(self, key: int) -> None:
        section = self._section()
        fm_list = section.field_map

        if not fm_list:
            self.focus = FOCUS_SIDEBAR
            return

        if key == curses.KEY_UP:
            self.field_cursor = max(0, self.field_cursor - 1)

        elif key == curses.KEY_DOWN:
            self.field_cursor = min(len(fm_list) - 1, self.field_cursor + 1)

        elif key in (curses.KEY_LEFT, 27):
            self.focus = FOCUS_SIDEBAR

        elif key in (curses.KEY_ENTER, 10, 13):
            fm = fm_list[self.field_cursor]
            if fm.editable:
                self._start_inline(fm)
            else:
                self._do_action(fm.attr_path)

    def _start_inline(self, fm: FieldMeta) -> None:
        if self.active_config is None:
            self.active_config = _empty_config()
        if self.active_config is None:
            self.set_status("! No se pudo inicializar config.", "err")
            return

        current = _get_nested(self.active_config, fm.attr_path)

        if current in ("[x]", "[ ]"):
            self._toggle_bool_field(fm, current)
        else:
            self._editing_line = fm.line_idx
            self._inline_buf   = list(current)

    def _toggle_bool_field(self, fm: FieldMeta, current: str) -> None:
        new_bool = current != "[x]"
        _set_nested(self.active_config, fm.attr_path, "[x]" if new_bool else "[ ]")
        self._refresh_scenario_section()
        self._refresh_home_section()
        estado = "activado" if new_bool else "desactivado"
        self.set_status(f"'{fm.label}' {estado}.", "ok")

    def _commit_inline(self) -> None:
        section    = self._section()
        fm_list    = section.field_map
        fm         = next((f for f in fm_list if f.line_idx == self._editing_line), None)
        new_value  = "".join(self._inline_buf)
        self._editing_line = -1
        self._inline_buf   = []

        if fm is None or self.active_config is None:
            return

        old_value = _get_nested(self.active_config, fm.attr_path)
        if new_value == old_value:
            self.set_status("Sin cambios.", "warn")
            return

        _set_nested(self.active_config, fm.attr_path, new_value)
        if fm.attr_path == "experiment_id":
            self.experiment_id = new_value

        self._refresh_scenario_section()
        self._refresh_home_section()
        self.set_status(f"'{fm.label}' actualizado.", "ok")
        self.focus = FOCUS_SIDEBAR

    def _cancel_inline(self) -> None:
        self._editing_line = -1
        self._inline_buf   = []
        self.set_status("Edición cancelada.", "warn")
        self.focus = FOCUS_SIDEBAR

    def _do_action(self, attr_path: str) -> None:
        self.focus = FOCUS_SIDEBAR

    def _do_load_prompt(self) -> None:
        if self._stdscr is None:
            return
        path = _file_prompt_overlay(
            self._stdscr, f"{SAVES_DIR}/example_scenario.json"
        )
        if path.strip():
            self._dispatch("global", f"ctrl_o:{path.strip()}")

    def _do_run(self) -> None:
        if self.active_config is None:
            self.set_status("! No hay escenario. Edita los campos o usa Ctrl+O.", "err")
            return
        self.status  = "RUNNING"
        self.capture = "ACTIVE"
        self.set_status(f"Running: {self.active_config.experiment_id}", "ok")
        self._dispatch(self._section_key(), "ctrl_r")

    def _jump_to(self, key: str) -> None:
        for i, sec in enumerate(SECTIONS):
            if sec.key == key:
                self.selected_idx = i
                self.focus        = FOCUS_SIDEBAR
                self.field_cursor = 0
                break

    def _dispatch(self, section_key: str, action: str) -> None:
        if self._action_cb is not None:
            self._action_cb(section_key, action)

    def _artifacts_move(self, delta: int) -> None:
        section  = self._get_section("artifacts")
        max_idx  = max(0, len(section.field_map) - 1)
        new_idx  = max(0, min(max_idx, self._artifact_cursor + delta))
        if new_idx != self._artifact_cursor:
            self._artifact_cursor = new_idx
            if section.field_map:
                self._selected_artifact = section.field_map[new_idx].label
            self._refresh_artifact_section()

    def _artifacts_show_info(self) -> None:
        section = self._get_section("artifacts")
        if not section.field_map:
            self._set_status("Sin archivos disponibles.", "warn")
            return
        idx  = min(self._artifact_cursor, len(section.field_map) - 1)
        name = section.field_map[idx].label
        self._selected_artifact = name
        self._refresh_artifact_section()
        self._set_status(f"Mostrando info: {name}", "ok")

    def _artifacts_export(self) -> None:
        if not self._selected_artifact:
            self._set_status("Selecciona un archivo primero (↑↓ + Enter).", "warn")
            return
        src = self._resolve_artifact_path(self._selected_artifact)
        if src is None or not src.exists():
            self._set_status(f"Archivo no encontrado: {self._selected_artifact}", "err")
            return
        from pathlib import Path
        dst = Path("exports") / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copy2(src, dst)
        self._set_status(f"Exportado → {dst}", "ok")

    def _artifacts_checksum(self) -> None:
        if not self._selected_artifact:
            self._set_status("Selecciona un archivo primero (↑↓ + Enter).", "warn")
            return
        src = self._resolve_artifact_path(self._selected_artifact)
        if src is None or not src.exists():
            self._set_status(f"Archivo no encontrado: {self._selected_artifact}", "err")
            return
        try:
            from modules.artifacts.metadata.checksum import compute_file_checksum
            checksum = compute_file_checksum(src)
            self._set_status(f"SHA-256: {checksum[:32]}…", "ok")
        except Exception as exc:
            self._set_status(f"Error checksum: {exc}", "err")

    def _resolve_artifact_path(self, name: str):
        from pathlib import Path
        for base in ("outputs/metadata", "outputs/pcap", "outputs"):
            p = Path(base) / name
            if p.exists():
                return p
        return None

    def _refresh_artifact_section(self) -> None:
        from design.Menu_artifacts import build_artifacts_section
        art_sec = build_artifacts_section(
            manager           = getattr(self, "_manager", None),
            selected_artifact = self._selected_artifact,
            cursor_idx        = self._artifact_cursor,
        )
        for i, sec in enumerate(SECTIONS):
            if sec.key == "artifacts":
                SECTIONS[i] = art_sec
                break

    def _get_section(self, key: str) -> Section:
        return next((s for s in SECTIONS if s.key == key), SECTIONS[0])

    def _set_status(self, message: str, kind: str = "ok") -> None:
        self._status_msg  = message
        self._status_kind = kind

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