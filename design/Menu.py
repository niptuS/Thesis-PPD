import sys
import platform

try:
    import curses
except ImportError:
    _is_windows = platform.system() == "Windows"
    if _is_windows:
        sys.stderr.write(
            "ERROR: 'curses' module not found on Windows.\n"
            "Install it with:  pip install windows-curses\n"
        )
    else:
        sys.stderr.write(
            "ERROR: 'curses' module not found.\n"
            "On Linux/macOS it should be part of the standard library.\n"
            "Install it with:  sudo apt-get install libncurses5-dev  (Debian/Kali)\n"
        )
    sys.exit(1)

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

@dataclass
class Section:
    key: str
    label: str
    hint: str
    content_lines: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


SECTIONS: list[Section] = [
    Section(
        key="home",
        label="Home",
        hint="vista general del sistema. Usa ↑↓ para navegar, Enter para abrir, ? para ayuda contextual, Ctrl+R para ejecutar y Ctrl+L para abrir logs.",
        content_lines=[
            "Experiment ID : EXP-2026-05-011",
            "Environment   : SmartHomeLab-v1",
            "Orchestrator  : 1.0.0",
            "Last run      : 2026-05-11 18:32",
            "",
            "Quick summary",
            "- Devices ready      : 8",
            "- Benign profiles    : 4",
            "- Attack modules     : 5",
            "- Scheduled events   : 12",
            "- Last PCAP          : exp-011-run02.pcap",
            "- Last metadata      : exp-011-run02.json",
            "",
            "Quick actions",
            "[Enter] Open selected section",
            "[Ctrl+R] Start scenario",
            "[Ctrl+S] Save current scenario",
            "[/] Search section",
        ],
        actions=["Enter Open selected", "Ctrl+R Start scenario", "Ctrl+S Save", "/ Search"],
    ),
    Section(
        key="scenario",
        label="Scenario Editor",
        hint="aquí defines el escenario base. Configura identidad, duración y salidas.",
        content_lines=[
            "Name              : SmartHome Mixed Traffic Morning",
            "Experiment ID     : EXP-2026-05-011",
            "Environment       : SmartHomeLab-v1",
            "Start time        : 2026-05-11 10:00:00",
            "Planned duration  : 00:45:00",
            "Output folder     : /data/experiments/exp-011",
            "Capture enabled   : [x]",
            "Metadata export   : [x] JSON",
            "PCAP export       : [x]",
            "",
            "",
            "",
            "",
            "",
            "Actions",
            "[Enter] Edit field   [A] Add field   [D] Delete field",
            "[Ctrl+S] Save        [Esc] Back",
        ],
        actions=["Enter Edit field", "A Add field", "D Delete field", "Ctrl+S Save", "Esc Back"],
    ),
    Section(
        key="devices",
        label="Devices",
        hint="revisa dispositivos, roles y direcciones antes de planificar eventos.",
        content_lines=[
            "Registered nodes",
            "",
            "ID            Role         IP             Status",
            "smartbulb01   target       192.168.1.10   online",
            "smartbulb02   target       192.168.1.11   online",
            "smartplug01   target       192.168.1.20   online",
            "camera01      target       192.168.1.30   online",
            "echo01        benign       192.168.1.40   online",
            "kalivm        attacker     192.168.1.50   ready",
            "",
            "Selected node",
            "smartbulb01",
            "- MAC      : AA:BB:CC:DD:EE:01",
            "- Protocols: HTTP, MQTT",
            "- Tags     : bulb, kitchen, wifi",
            "",
            "Actions: [A] Add  [E] Edit  [R] Remove  [T] Tag",
        ],
        actions=["A Add", "E Edit", "R Remove", "T Tag"],
    ),
    Section(
        key="benign",
        label="Benign Profiles",
        hint="activa patrones benignos base para dar contexto realista a la captura.",
        content_lines=[
            "Available profiles",
            "",
            "[x] camera_stream_low      1 camera / periodic upload",
            "[x] smartplug_telemetry    2 plugs / 30s heartbeat",
            "[x] bulb_state_updates     3 bulbs / event driven",
            "[ ] alexa_interactions     user commands / sporadic",
            "",
            "Selected profile: camera_stream_low",
            "- Device class : camera",
            "- Protocol     : RTSP / HTTP",
            "- Rate         : 1 stream",
            "- Duration     : 00:45:00",
            "- Start offset : 00:00:00",
            "",
            "Actions",
            "[Space] Toggle  [Enter] Edit  [C] Clone  [N] New",
        ],
        actions=["Space Toggle", "Enter Edit", "C Clone", "N New"],
    ),
    Section(
        key="attacks",
        label="Attack Library",
        hint="define origen, objetivo, duración y taxonomía del ataque seleccionado.",
        content_lines=[
            "Modules",
            "",
            "> DoS HTTP Flood",
            "  Port Scan",
            "  ARP Spoof / MitM",
            "  SYN Flood",
            "  Brute Force HTTP",
            "",
            "Selected module: DoS HTTP Flood",
            "- Source node   : kalivm",
            "- Target node   : camera01",
            "- Duration      : 00:03:00",
            "- Intensity     : medium",
            "- Label         : DoS",
            "- MITRE ref     : T1498.001",
            "",
            "Actions",
            "[Enter] Configure  [A] Add module  [D] Delete",
            "[V] Validate params",
        ],
        actions=["Enter Configure", "A Add module", "D Delete", "V Validate params"],
    ),
    Section(
        key="timeline",
        label="Timeline",
        hint="organiza qué ocurre, cuándo ocurre y sobre qué actor se ejecuta.",
        content_lines=[
            "Scheduled events",
            "",
            "Time       Type      Source      Target       Status",
            "10:00:00   benign    echo01      smartbulb01   queued",
            "10:00:00   benign    camera01    network       queued",
            "10:05:00   attack    kalivm      camera01      queued",
            "10:12:00   benign    echo01      smartplug01   queued",
            "10:15:00   attack    kalivm      smartplug01   queued",
            "",
            "Selected event",
            "- Timestamp   : 10:05:00",
            "- Event type  : attack",
            "- Action      : DoS HTTP Flood",
            "- Notes       : attack after baseline warmup",
            "",
            "Actions: [A] Add  [E] Edit  [M] Move  [X] Delete",
        ],
        actions=["A Add", "E Edit", "M Move", "X Delete"],
    ),
    Section(
        key="live",
        label="Live Execution",
        hint="monitorea la corrida actual sin abandonar el sistema ni perder contexto.",
        content_lines=[
            "Runtime",
            "- Started at     : 10:00:00",
            "- Elapsed        : 00:17:23",
            "- Remaining      : 00:27:37",
            "- PCAP file      : exp-011-run03.pcap",
            "- Metadata file  : exp-011-run03.json",
            "",
            "",
            "Current activity",
            "- Active benign : camera_stream_low",
            "- Active attack : none",
            "- Next event    : SYN Flood -> smartplug01 @10:20:00",
            "",
            "Health",
            "[capture: OK] [logger: OK] [clock sync: OK]",
            "",
            "Actions",
            "[Ctrl+P] Pause  [Ctrl+R] Resume  [Ctrl+X] Abort",
        ],
        actions=["Ctrl+P Pause", "Ctrl+R Resume", "Ctrl+X Abort"],
    ),
    Section(
        key="logs",
        label="Logs",
        hint="aquí ves los eventos en orden temporal para revisar trazabilidad.",
        content_lines=[
            "Live event stream",
            "",
            "10:00:00 INFO  scenario started",
            "10:00:01 INFO  capture started on capturenode",
            "10:00:03 INFO  benign profile camera_stream_low on",
            "           camera01 executed",
            "10:05:00 INFO  attack module DoS HTTP Flood started",
            "10:05:01 INFO  source=kalivm target=camera01",
            "10:08:00 INFO  attack module DoS HTTP Flood ended",
            "10:12:00 INFO  benign interaction smartplug01",
            "10:16:20 WARN  transient packet drop observed",
            "10:16:21 INFO  capture stabilized",
            "",
            "Filters: [All] [Info] [Warn] [Error] [Attack]",
            "Actions: [/] Search  [F] Filter  [E] Export slice",
        ],
        actions=["/ Search", "F Filter", "E Export slice"],
    ),
    Section(
        key="artifacts",
        label="Artifacts",
        hint="revisa y exporta PCAP, metadatos y registros de cada ejecución.",
        content_lines=[
            "Generated files",
            "",
            "Name                    Type      Size      Status",
            "exp-011-run03.pcap      PCAP      428 MB    complete",
            "exp-011-run03.json      metadata  18 KB     complete",
            "exp-011-run03.log       log       74 KB     complete",
            "exp-011-run03.flows.csv flow      2.3 MB    optional",
            "",
            "Selected artifact: exp-011-run03.json",
            "- Schema version : 1.0",
            "- Start time     : 2026-05-12T10:00:00Z",
            "- Events         : 12",
            "- Exportable     : yes",
            "",
            "Actions: [Enter] Open info  [E] Export  [C] Checksum",
        ],
        actions=["Enter Open info", "E Export", "C Checksum"],
    ),
    Section(
        key="help",
        label="Help",
        hint="usa esta vista como referencia rápida del flujo completo del sistema.",
        content_lines=[
            "Navigation",
            "- ↑↓ move in menu or lists",
            "- Enter open / edit",
            "- Esc back",
            "- Tab change focus",
            "- ? contextual help",
            "- q close current panel",
            "",
            "Global shortcuts",
            "- Ctrl+S save scenario",
            "- Ctrl+R start/resume",
            "- Ctrl+P pause",
            "- Ctrl+L open logs",
            "- Ctrl+X abort scenario",
            "",
            "Recommended flow",
            "1. Scenario Editor",
            "2. Devices",
            "3. Benign Profiles",
            "4. Attack Library",
            "5. Timeline",
            "6. Live Execution",
            "7. Artifacts",
        ],
        actions=["Esc Back"],
    ),
]

CONTEXT_HELP: dict[str, dict] = {
    "home": {
        "title": "Home",
        "description": "This is the main dashboard. View experiment status, quick stats and access any section from here.",
        "tips": ["Use ↑↓ to navigate the menu.", "Press Enter to open a section.", "Ctrl+R starts the scenario."],
        "shortcuts": ["Enter Open", "Ctrl+R Start", "Ctrl+S Save", "/ Search"],
    },
    "scenario": {
        "title": "Scenario Editor",
        "description": "This section lets you define the base scenario. Configure identity, duration and output settings.",
        "tips": ["Set experiment ID before editing devices.", "Verify output folder path.", "Enable PCAP + metadata for complete captures."],
        "shortcuts": ["Enter Edit field", "A Add field", "D Delete field", "Ctrl+S Save", "Esc Back"],
    },
    "devices": {
        "title": "Devices",
        "description": "Register and configure IoT nodes. Assign roles (target, benign, attacker), IPs and tags.",
        "tips": ["At least one attacker node is required.", "Tag devices for easy filtering.", "Verify IPs match your lab network."],
        "shortcuts": ["A Add", "E Edit", "R Remove", "T Tag"],
    },
    "benign": {
        "title": "Benign Profiles",
        "description": "Activate baseline traffic patterns to give realistic context to network captures.",
        "tips": ["Start with a short warmup profile.", "Toggle profiles with Space.", "Clone existing profiles for variations."],
        "shortcuts": ["Space Toggle", "Enter Edit", "C Clone", "N New"],
    },
    "attacks": {
        "title": "Attack Library",
        "description": "Define attack modules with source, target, duration and MITRE taxonomy reference.",
        "tips": ["Always validate params before adding to timeline.", "Use MITRE refs for consistent labeling.", "Set intensity appropriately."],
        "shortcuts": ["Enter Configure", "A Add module", "D Delete", "V Validate params"],
    },
    "timeline": {
        "title": "Timeline",
        "description": "This section lets you define the temporal order of the experiment. Add benign and attack events, assign timestamps, and verify that every event has a valid source, target and action.",
        "tips": ["Start with a short benign warmup.", "Avoid overlapping attacks unless intentional.", "Validate timestamps before execution."],
        "shortcuts": ["A Add event", "E Edit", "M Move", "X Delete", "Esc Close"],
    },
    "live": {
        "title": "Live Execution",
        "description": "Monitor the running experiment in real time. View elapsed time, active profiles and health status.",
        "tips": ["Do not abort unless necessary — data may be incomplete.", "Check health indicators regularly.", "Pause to inspect intermediate state."],
        "shortcuts": ["Ctrl+P Pause", "Ctrl+R Resume", "Ctrl+X Abort"],
    },
    "logs": {
        "title": "Logs",
        "description": "View the live event stream in temporal order. Filter by severity or event type.",
        "tips": ["Use / to search specific events.", "Filter by Attack to review attack timeline.", "Export slices for offline analysis."],
        "shortcuts": ["/ Search", "F Filter", "E Export slice"],
    },
    "artifacts": {
        "title": "Artifacts",
        "description": "Review and export generated PCAP, metadata and log files from each experiment run.",
        "tips": ["Verify checksums before sharing datasets.", "Export metadata JSON for ML pipelines.", "Check file completeness status."],
        "shortcuts": ["Enter Open info", "E Export", "C Checksum"],
    },
    "help": {
        "title": "Help",
        "description": "Quick reference for navigation, shortcuts and recommended workflow.",
        "tips": ["Follow the recommended flow for first-time setups.", "Use ? anywhere for section-specific help.", "Ctrl+L jumps directly to logs."],
        "shortcuts": ["Esc Back"],
    },
}


PAIR_HEADER_BG   = 1
PAIR_MENU_NORMAL  = 2
PAIR_MENU_SELECTED = 3
PAIR_MENU_ARROW   = 4
PAIR_CONTENT      = 5
PAIR_HINT_BG      = 6
PAIR_BORDER       = 7
PAIR_OVERLAY_BG   = 8
PAIR_OVERLAY_TITLE = 9
PAIR_STATUS_IDLE  = 10
PAIR_STATUS_RUN   = 11
PAIR_STATUS_EDIT  = 12
PAIR_LABEL_DIM    = 13


def _init_colors():
    curses.use_default_colors()
    curses.init_pair(PAIR_HEADER_BG, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(PAIR_MENU_NORMAL, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_MENU_SELECTED, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(PAIR_MENU_ARROW, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_CONTENT, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_HINT_BG, curses.COLOR_WHITE, curses.COLOR_CYAN)
    curses.init_pair(PAIR_BORDER, curses.COLOR_CYAN, -1)
    curses.init_pair(PAIR_OVERLAY_BG, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(PAIR_OVERLAY_TITLE, curses.COLOR_YELLOW, curses.COLOR_BLUE)
    curses.init_pair(PAIR_STATUS_IDLE, curses.COLOR_GREEN, -1)
    curses.init_pair(PAIR_STATUS_RUN, curses.COLOR_RED, -1)
    curses.init_pair(PAIR_STATUS_EDIT, curses.COLOR_YELLOW, -1)
    curses.init_pair(PAIR_LABEL_DIM, 8, -1)  # dark gray


# ── Drawing helpers ─────────────────────────────────────────────────────────

MENU_WIDTH = 22
HINT_HEIGHT = 2
HEADER_HEIGHT = 1


def _draw_header(stdscr, experiment_id: str, status: str, capture: str):
    max_y, max_x = stdscr.getmaxyx()
    header_text = f" SH-DATASET :: experiment={experiment_id} :: status={status} :: capture={capture} "
    # Pad or truncate to fill the full width
    if len(header_text) < max_x:
        header_text = header_text + " " * (max_x - len(header_text))
    else:
        header_text = header_text[:max_x - 1]

    stdscr.attron(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)
    stdscr.addstr(0, 0, header_text)
    stdscr.attroff(curses.color_pair(PAIR_HEADER_BG) | curses.A_BOLD)


def _draw_menu(stdscr, sections: list[Section], selected_idx: int, top_y: int, bottom_y: int):
    max_y, max_x = stdscr.getmaxyx()
    menu_top = top_y
    menu_bottom = bottom_y - HINT_HEIGHT

    for y in range(menu_top, menu_bottom):
        stdscr.attron(curses.color_pair(PAIR_BORDER))
        stdscr.addch(y, MENU_WIDTH, curses.ACS_VLINE)
        stdscr.attroff(curses.color_pair(PAIR_BORDER))

    stdscr.attron(curses.color_pair(PAIR_LABEL_DIM) | curses.A_BOLD)
    stdscr.addstr(menu_top, 2, "MENU")
    stdscr.attroff(curses.color_pair(PAIR_LABEL_DIM) | curses.A_BOLD)

    row = menu_top + 1
    for i, sec in enumerate(sections):
        if row >= menu_bottom:
            break
        prefix = "> " if i == selected_idx else "  "
        label = sec.label
        # Truncate label if it exceeds menu width minus prefix
        max_label_len = MENU_WIDTH - 4
        if len(label) > max_label_len:
            label = label[:max_label_len - 2] + ".."

        if i == selected_idx:
            stdscr.attron(curses.color_pair(PAIR_MENU_SELECTED) | curses.A_BOLD)
            stdscr.addstr(row, 2, f"{prefix}{label}")
            remaining = MENU_WIDTH - 2 - len(prefix) - len(label)
            if remaining > 0:
                stdscr.addstr(row, 2 + len(prefix) + len(label), " " * remaining)
            stdscr.attroff(curses.color_pair(PAIR_MENU_SELECTED) | curses.A_BOLD)
        else:
            stdscr.attron(curses.color_pair(PAIR_MENU_ARROW))
            stdscr.addstr(row, 2, prefix)
            stdscr.attroff(curses.color_pair(PAIR_MENU_ARROW))
            stdscr.attron(curses.color_pair(PAIR_MENU_NORMAL))
            stdscr.addstr(row, 2 + len(prefix), label)
            stdscr.attroff(curses.color_pair(PAIR_MENU_NORMAL))

        row += 1


def _draw_content(stdscr, section: Section, top_y: int, bottom_y: int):
    max_y, max_x = stdscr.getmaxyx()
    content_left = MENU_WIDTH + 1
    content_right = max_x - 1
    content_top = top_y
    content_bottom = bottom_y - HINT_HEIGHT
    content_width = content_right - content_left

    # Section title
    stdscr.attron(curses.color_pair(PAIR_CONTENT) | curses.A_BOLD)
    title = section.label.upper()
    stdscr.addstr(content_top, content_left + 2, title)
    stdscr.attroff(curses.color_pair(PAIR_CONTENT) | curses.A_BOLD)

    row = content_top + 1
    for line in section.content_lines:
        if row >= content_bottom:
            break
        display_line = line[:content_width - 2] if len(line) > content_width - 2 else line
        stdscr.attron(curses.color_pair(PAIR_CONTENT))
        try:
            stdscr.addstr(row, content_left + 2, display_line)
        except curses.error:
            pass
        stdscr.attroff(curses.color_pair(PAIR_CONTENT))
        row += 1


def _draw_hint(stdscr, hint_text: str, bottom_y: int):
    max_y, max_x = stdscr.getmaxyx()
    hint_row = bottom_y - HINT_HEIGHT

    stdscr.attron(curses.color_pair(PAIR_BORDER))
    stdscr.addch(hint_row, 0, curses.ACS_LTEE)
    for x in range(1, MENU_WIDTH):
        stdscr.addch(hint_row, x, curses.ACS_HLINE)
    stdscr.addch(hint_row, MENU_WIDTH, curses.ACS_BTEE)
    for x in range(MENU_WIDTH + 1, max_x - 1):
        stdscr.addch(hint_row, x, curses.ACS_HLINE)
    stdscr.addch(hint_row, max_x - 1, curses.ACS_RTEE)
    stdscr.attroff(curses.color_pair(PAIR_BORDER))

    hint_display = f" Hint: {hint_text} "
    if len(hint_display) > max_x - 1:
        hint_display = hint_display[:max_x - 1]
    stdscr.attron(curses.color_pair(PAIR_HINT_BG))
    try:
        stdscr.addstr(hint_row + 1, 0, hint_display)
    except curses.error:
        pass
    remaining = max_x - 1 - len(hint_display)
    if remaining > 0:
        stdscr.addstr(hint_row + 1, len(hint_display), " " * remaining)
    stdscr.attroff(curses.color_pair(PAIR_HINT_BG))


def _draw_borders(stdscr, top_y: int, bottom_y: int):
    max_y, max_x = stdscr.getmaxyx()
    content_top = top_y
    content_bottom = bottom_y - HINT_HEIGHT

    stdscr.attron(curses.color_pair(PAIR_BORDER))
    stdscr.addch(content_top, 0, curses.ACS_LTEE)
    for x in range(1, MENU_WIDTH):
        stdscr.addch(content_top, x, curses.ACS_HLINE)
    stdscr.addch(content_top, MENU_WIDTH, curses.ACS_TTEE)
    for x in range(MENU_WIDTH + 1, max_x - 1):
        stdscr.addch(content_top, x, curses.ACS_HLINE)
    stdscr.addch(content_top, max_x - 1, curses.ACS_RTEE)
    stdscr.attroff(curses.color_pair(PAIR_BORDER))

    for y in range(content_top + 1, content_bottom):
        stdscr.attron(curses.color_pair(PAIR_BORDER))
        stdscr.addch(y, 0, curses.ACS_VLINE)
        stdscr.addch(y, max_x - 1, curses.ACS_VLINE)
        stdscr.attroff(curses.color_pair(PAIR_BORDER))

    hint_top = bottom_y - HINT_HEIGHT


def _draw_context_help(stdscr, section_key: str):
    max_y, max_x = stdscr.getmaxyx()
    help_data = CONTEXT_HELP.get(section_key, CONTEXT_HELP["home"])

    # Overlay dimensions — centered, ~60% width, auto height
    overlay_w = min(60, max_x - 4)
    overlay_h = min(16, max_y - 4)
    overlay_x = (max_x - overlay_w) // 2
    overlay_y = (max_y - overlay_h) // 2

    # Clear overlay area with blue background
    for y in range(overlay_y, overlay_y + overlay_h):
        stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
        stdscr.addstr(y, overlay_x, " " * overlay_w)
        stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

    # Draw border around overlay
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_TITLE) | curses.A_BOLD)
    # Top border with title
    title_text = f" CONTEXT HELP ─ {help_data['title']} "
    top_line = "┌" + "─" * (overlay_w - 2) + "┐"
    stdscr.addstr(overlay_y, overlay_x, top_line[:overlay_w])
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TITLE) | curses.A_BOLD)

    # Title row
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_TITLE) | curses.A_BOLD)
    padded_title = f" {title_text} "
    if len(padded_title) < overlay_w:
        padded_title = padded_title + " " * (overlay_w - len(padded_title))
    stdscr.addstr(overlay_y + 1, overlay_x, padded_title[:overlay_w])
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TITLE) | curses.A_BOLD)

    # Section label
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)
    stdscr.addstr(overlay_y + 3, overlay_x + 2, f"Section : {help_data['title']}")
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)

    # Description
    row = overlay_y + 5
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
    desc = help_data["description"]
    # Word-wrap description
    words = desc.split()
    current_line = ""
    for word in words:
        if len(current_line) + len(word) + 1 > overlay_w - 4:
            stdscr.addstr(row, overlay_x + 2, current_line)
            row += 1
            current_line = word
        else:
            current_line = (current_line + " " + word).strip()
    if current_line:
        stdscr.addstr(row, overlay_x + 2, current_line)
        row += 1
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

    row += 1

    # Tips
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)
    stdscr.addstr(row, overlay_x + 2, "Tips")
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)
    row += 1
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
    for tip in help_data["tips"]:
        if row >= overlay_y + overlay_h - 3:
            break
        stdscr.addstr(row, overlay_x + 2, f"- {tip}")
        row += 1
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

    row += 1

    # Shortcuts
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)
    stdscr.addstr(row, overlay_x + 2, "Shortcuts")
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG) | curses.A_BOLD)
    row += 1
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
    shortcuts_text = " ".join(f"[{s}]" for s in help_data["shortcuts"])
    stdscr.addstr(row, overlay_x + 2, shortcuts_text[:overlay_w - 4])
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))

    # Bottom border
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_TITLE) | curses.A_BOLD)
    bottom_line = "└" + "─" * (overlay_w - 2) + "┘"
    stdscr.addstr(overlay_y + overlay_h - 1, overlay_x, bottom_line[:overlay_w])
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_TITLE) | curses.A_BOLD)

    # Esc hint at bottom
    stdscr.attron(curses.color_pair(PAIR_OVERLAY_BG))
    esc_text = "[Esc] Close"
    stdscr.addstr(overlay_y + overlay_h - 2, overlay_x + overlay_w - len(esc_text) - 2, esc_text)
    stdscr.attroff(curses.color_pair(PAIR_OVERLAY_BG))


# ── Main application class ──────────────────────────────────────────────────

class MenuApp:

    def __init__(self):
        self.selected_idx: int = 0
        self.show_context_help: bool = False
        self.status: str = "IDLE"
        self.capture: str = "READY"
        self.experiment_id: str = "EXP-2026-05-011"
        self.running: bool = True
        self._action_callback: Optional[Callable[[str, str], None]] = None

    def set_action_callback(self, callback: Callable[[str, str], None]):
        self._action_callback = callback

    def run(self, stdscr):
        _init_colors()
        stdscr.keypad(True)
        stdscr.nodelay(False)
        curses.curs_set(0)  # hide cursor
        curses.noecho()

        while self.running:
            self._render(stdscr)
            key = stdscr.getch()
            self._handle_key(key)

    def _render(self, stdscr):
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()

        # Minimum size check
        if max_y < 10 or max_x < 40:
            stdscr.addstr(0, 0, "Terminal too small. Min 40x10.")
            stdscr.refresh()
            return

        top_y = HEADER_HEIGHT
        bottom_y = max_y

        # 1. Header
        _draw_header(stdscr, self.experiment_id, self.status, self.capture)

        # 2. Borders
        _draw_borders(stdscr, top_y, bottom_y)

        # 3. Menu sidebar
        _draw_menu(stdscr, SECTIONS, self.selected_idx, top_y, bottom_y)

        # 4. Content panel
        active_section = SECTIONS[self.selected_idx]
        _draw_content(stdscr, active_section, top_y, bottom_y)

        # 5. Hint bar
        _draw_hint(stdscr, active_section.hint, bottom_y)

        # 6. Context help overlay (if active)
        if self.show_context_help:
            _draw_context_help(stdscr, active_section.key)

        stdscr.refresh()

    def _handle_key(self, key):
        # If context help overlay is showing, only Esc/q close it
        if self.show_context_help:
            if key == curses.KEY_ESCAPE or key == ord('q'):
                self.show_context_help = False
            return

        active_section = SECTIONS[self.selected_idx]

        # ── Navigation keys ────────────────────────────────────────────
        if key == curses.KEY_UP:
            self.selected_idx = max(0, self.selected_idx - 1)

        elif key == curses.KEY_DOWN:
            self.selected_idx = min(len(SECTIONS) - 1, self.selected_idx + 1)

        elif key == curses.KEY_ENTER or key == 10 or key == 13:
            # Enter — open selected section / trigger action
            self._dispatch_action(active_section.key, "enter")

        elif key == curses.KEY_ESCAPE:
            # Esc — back (go to home if not already there)
            if self.selected_idx != 0:
                self.selected_idx = 0

        elif key == ord('?'):
            # ? — toggle context help overlay
            self.show_context_help = True

        elif key == ord('q'):
            # q — close current panel (go back to home)
            if self.selected_idx != 0:
                self.selected_idx = 0

        elif key == ord('\t') or key == 9:
            # Tab — switch focus (placeholder: cycles to next section)
            self.selected_idx = (self.selected_idx + 1) % len(SECTIONS)

        # ── Global Ctrl shortcuts ──────────────────────────────────────
        elif key == 19:  # Ctrl+S
            self._dispatch_action(active_section.key, "ctrl_s")

        elif key == 18:  # Ctrl+R
            self.status = "RUNNING"
            self.capture = "ACTIVE"
            self._dispatch_action(active_section.key, "ctrl_r")

        elif key == 16:  # Ctrl+P
            self.status = "PAUSED"
            self.capture = "PAUSED"
            self._dispatch_action(active_section.key, "ctrl_p")

        elif key == 12:  # Ctrl+L
            # Jump to Logs section
            for i, sec in enumerate(SECTIONS):
                if sec.key == "logs":
                    self.selected_idx = i
                    break

        elif key == 24:  # Ctrl+X
            self.status = "IDLE"
            self.capture = "READY"
            self._dispatch_action(active_section.key, "ctrl_x")

        # ── Section-specific action keys ────────────────────────────────
        elif key == ord('a') or key == ord('A'):
            self._dispatch_action(active_section.key, "add")

        elif key == ord('d') or key == ord('D'):
            self._dispatch_action(active_section.key, "delete")

        elif key == ord('e') or key == ord('E'):
            self._dispatch_action(active_section.key, "edit")

        elif key == ord('r') or key == ord('R'):
            self._dispatch_action(active_section.key, "remove")

        elif key == ord('t') or key == ord('T'):
            self._dispatch_action(active_section.key, "tag")

        elif key == ord('c') or key == ord('C'):
            self._dispatch_action(active_section.key, "clone")

        elif key == ord('n') or key == ord('N'):
            self._dispatch_action(active_section.key, "new")

        elif key == ord('m') or key == ord('M'):
            self._dispatch_action(active_section.key, "move")

        elif key == ord('x') or key == ord('X'):
            self._dispatch_action(active_section.key, "delete_event")

        elif key == ord('v') or key == ord('V'):
            self._dispatch_action(active_section.key, "validate")

        elif key == ord('f') or key == ord('F'):
            self._dispatch_action(active_section.key, "filter")

        elif key == ord('/'):
            self._dispatch_action(active_section.key, "search")

        elif key == ord(' '):
            self._dispatch_action(active_section.key, "toggle")

    def _dispatch_action(self, section_key: str, action: str):
        if self._action_callback is not None:
            self._action_callback(section_key, action)

    def stop(self):
        self.running = False

def run_menu(action_callback: Optional[Callable[[str, str], None]] = None):
    app = MenuApp()
    if action_callback is not None:
        app.set_action_callback(action_callback)

    try:
        curses.wrapper(app.run)
    except KeyboardInterrupt:
        app.stop()

    return app