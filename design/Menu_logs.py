from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime

from design.models import Section


# ── Log levels ──────────────────────────────────────────────────────
LEVEL_INFO = "INFO"
LEVEL_WARN = "WARN"
LEVEL_ERROR = "ERROR"
LEVEL_OK = "OK"

ALL_LEVELS = [LEVEL_INFO, LEVEL_WARN, LEVEL_ERROR, LEVEL_OK]
FILTER_LABELS = ["All", "Info", "Warn", "Error"]


@dataclass
class LogEntry:
    timestamp: str
    level: str
    message: str


class EventLog:
    """Thread-safe ring-buffer of log events."""

    MAX_ENTRIES = 200

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[LogEntry] = []

    # ── write ────────────────────────────────────────────────────
    def add(self, message: str, level: str = LEVEL_INFO) -> None:
        entry = LogEntry(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            level=level,
            message=message,
        )
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self.MAX_ENTRIES:
                self._entries = self._entries[-self.MAX_ENTRIES:]

    def info(self, msg: str) -> None: self.add(msg, LEVEL_INFO)
    def warn(self, msg: str) -> None: self.add(msg, LEVEL_WARN)
    def error(self, msg: str) -> None: self.add(msg, LEVEL_ERROR)
    def ok(self, msg: str) -> None: self.add(msg, LEVEL_OK)

    # ── read ─────────────────────────────────────────────────────
    def entries(self, level_filter: str = "All") -> list[LogEntry]:
        with self._lock:
            if level_filter == "All":
                return list(self._entries)
            return [e for e in self._entries if e.level == level_filter.upper()]

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# ── singleton ───────────────────────────────────────────────────────
EVENT_LOG = EventLog()


# ── section builder ─────────────────────────────────────────────────

def build_logs_section(
    log: EventLog | None = None,
    level_filter: str = "All",
    scroll_offset: int = 0,
    max_visible: int = 40,
) -> Section:
    elog = log if log is not None else EVENT_LOG
    entries = elog.entries(level_filter)

    # ── header
    content: list[str] = [
        "─── Live Event Stream ────────────────────────────────",
    ]

    if not entries:
        content.append("")
        content.append("  (sin eventos — ejecute un escaneo o inicie un escenario)")
        content.append("")
    else:
        content.append("")
        # apply scroll — show from offset up to max_visible lines
        visible = entries[scroll_offset : scroll_offset + max_visible]
        for e in visible:
            level_tag = e.level.ljust(5)
            content.append(f"  {e.timestamp} {level_tag} {e.message}")

        total = len(entries)
        showing_end = min(scroll_offset + max_visible, total)
        if total > max_visible:
            content.append("")
            content.append(
                f"  ── mostrando {scroll_offset + 1}-{showing_end} de {total}"
                "  (↑↓ desplazar) ──"
            )
        content.append("")

    return Section(
        key="logs",
        label="Logs",
        hint=f"↑↓=desplazar · Eventos: {elog.count()}",
        content_lines=content,
        actions=[],
        field_map=[],
    )


LOGS_SECTION: Section = build_logs_section()
