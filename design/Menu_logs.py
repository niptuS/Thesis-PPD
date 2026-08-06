"""
Entrada: None
Salida: Section / EventLog
Descripción: Builds the Logs section showing the live event stream with
             filter support, plus the shared EventLog ring buffer.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime

from design.models import Section
from modules.i18n import t


LEVEL_INFO = "INFO"
LEVEL_WARN = "WARN"
LEVEL_ERROR = "ERROR"
LEVEL_OK = "OK"

ALL_LEVELS = [LEVEL_INFO, LEVEL_WARN, LEVEL_ERROR, LEVEL_OK]
FILTER_LABELS = ["All", "Info", "Warn", "Error"]


@dataclass
class LogEntry:
    """
    Entrada: timestamp (str), level (str), message (str)
    Salida: LogEntry instance
    Descripción: Dataclass holding a single log entry.
    """
    timestamp: str
    level: str
    message: str


class EventLog:
    """
    Entrada: None
    Salida: EventLog instance
    Descripción: Thread-safe ring-buffer of log events.
    """

    MAX_ENTRIES = 200

    '''
    Entrada: None
    Salida: None
    Descripción: Initializes the EventLog with an empty entries list and lock.
    '''
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[LogEntry] = []
        self._status_callback = None

    '''
    Entrada: callback (callable)
    Salida: None
    Descripción: Sets a status callback so WARN/ERROR/OK messages also
                 appear in the hint bar as visual feedback.
    '''
    def set_status_callback(self, callback) -> None:
        self._status_callback = callback

    '''
    Entrada: message (str), level (str)
    Salida: None
    Descripción: Appends a new entry, trimming to MAX_ENTRIES.
    '''
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

        # Show WARN/ERROR/OK in the status bar as visual feedback
        if self._status_callback and level in (LEVEL_WARN, LEVEL_ERROR, LEVEL_OK):
            kind = {"WARN": "warn", "ERROR": "err", "OK": "ok"}.get(level, "hint")
            try:
                self._status_callback(message, kind)
            except Exception:
                pass

    '''
    Entrada: msg (str)
    Salida: None
    Descripción: Adds an INFO-level entry.
    '''
    def info(self, msg: str) -> None:
        self.add(msg, LEVEL_INFO)

    '''
    Entrada: msg (str)
    Salida: None
    Descripción: Adds a WARN-level entry.
    '''
    def warn(self, msg: str) -> None:
        self.add(msg, LEVEL_WARN)

    '''
    Entrada: msg (str)
    Salida: None
    Descripción: Adds an ERROR-level entry.
    '''
    def error(self, msg: str) -> None:
        self.add(msg, LEVEL_ERROR)

    '''
    Entrada: msg (str)
    Salida: None
    Descripción: Adds an OK-level entry.
    '''
    def ok(self, msg: str) -> None:
        self.add(msg, LEVEL_OK)

    '''
    Entrada: level_filter (str)
    Salida: list[LogEntry]
    Descripción: Returns entries filtered by level (or all).
    '''
    def entries(self, level_filter: str = "All") -> list[LogEntry]:
        with self._lock:
            if level_filter == "All":
                return list(self._entries)
            return [e for e in self._entries if e.level == level_filter.upper()]

    '''
    Entrada: None
    Salida: int
    Descripción: Returns the total number of entries.
    '''
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    '''
    Entrada: None
    Salida: None
    Descripción: Clears all entries.
    '''
    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


EVENT_LOG = EventLog()



"""
Entrada: log (EventLog|None), level_filter (str), scroll_offset (int), max_visible (int)
Salida: Section
Descripción: Builds the logs section with localized labels and hints.
"""
def build_logs_section(
    log: EventLog | None = None,
    level_filter: str = "All",
    scroll_offset: int = 0,
    max_visible: int = 40,
) -> Section:
    elog = log if log is not None else EVENT_LOG
    entries = elog.entries(level_filter)

    content: list[str] = [
        f"─── {t('logs', 'title')} ────────────────────────────────",
    ]

    if not entries:
        content.append("")
        content.append(f"  {t('logs', 'no_events')}")
        content.append("")
    else:
        content.append("")
        visible = entries[scroll_offset : scroll_offset + max_visible]
        for e in visible:
            level_tag = e.level.ljust(5)
            content.append(f"  {e.timestamp} {level_tag} {e.message}")

        total = len(entries)
        showing_end = min(scroll_offset + max_visible, total)
        if total > max_visible:
            content.append("")
            content.append(
                "  "
                + t("logs", "showing_range", scroll_offset + 1, showing_end, total)
            )
        content.append("")

    return Section(
        key="logs",
        label=t("menu", "logs"),
        hint=t("logs", "hint", elog.count()),
        content_lines=content,
        actions=[],
        field_map=[],
    )


LOGS_SECTION: Section = build_logs_section()
