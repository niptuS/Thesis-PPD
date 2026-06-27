from __future__ import annotations

import curses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_logs import EVENT_LOG, FILTER_LABELS, build_logs_section


class LogsController:

    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._level_filter: str = "All"
        self._scroll_offset: int = 0

    def handle_key(self, key: int) -> bool:
        if key == curses.KEY_DOWN:
            self._scroll_offset += 1
            self._clamp_scroll()
            self._refresh()
            return True
        if key == curses.KEY_UP:
            self._scroll_offset = max(0, self._scroll_offset - 1)
            self._refresh()
            return True
        if key in (ord("f"), ord("F")):
            self._cycle_filter()
            return True
        if key in (ord("x"), ord("X")):
            EVENT_LOG.clear()
            self._scroll_offset = 0
            self._refresh()
            self._app.set_status("Logs limpiados.", "ok")
            return True
        if key in (ord("e"), ord("E")):
            self._app._dispatch("logs", "export_slice")
            return True
        if key == ord("/"):
            self._app._dispatch("logs", "search")
            return True
        return False

    # ── helpers ──────────────────────────────────────────────────

    def _cycle_filter(self) -> None:
        idx = FILTER_LABELS.index(self._level_filter) if self._level_filter in FILTER_LABELS else 0
        idx = (idx + 1) % len(FILTER_LABELS)
        self._level_filter = FILTER_LABELS[idx]
        self._scroll_offset = 0
        self._refresh()
        self._app.set_status(f"Filtro: {self._level_filter}", "ok")

    def _clamp_scroll(self) -> None:
        total = len(EVENT_LOG.entries(self._level_filter))
        max_offset = max(0, total - 1)
        self._scroll_offset = min(self._scroll_offset, max_offset)

    def _refresh(self) -> None:
        updated = build_logs_section(
            log=EVENT_LOG,
            level_filter=self._level_filter,
            scroll_offset=self._scroll_offset,
        )
        self._app.replace_section("logs", updated)
