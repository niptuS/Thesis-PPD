"""ArtifactsController — browse and view PCAP/CSV files."""
from __future__ import annotations
import curses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_logs import EVENT_LOG
from design.Menu_artifacts import build_artifacts_section, PAGE_SIZE
from modules.artifacts.pcap_viewer import list_capture_files, read_pcap, read_csv_file


class ArtifactsController:
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._files: list[dict] = []
        self._file_cursor: int = 0
        self._view_mode: str = "files"
        self._packets = []
        self._packet_cursor = 0
        self._packet_page = 0
        self._csv_headers = []
        self._csv_rows = []
        self._csv_cursor = 0
        self._csv_page = 0
        self._current_file = ""
        self._error = ""
        self._loaded = False

    def handle_key(self, key: int) -> bool:
        if not self._loaded:
            self._load_files()
        if self._view_mode == "files":
            return self._handle_files(key)
        return self._handle_view(key)

    def _handle_files(self, key):
        if key in (ord("r"), ord("R")):
            self._load_files()
            return True
        if key == curses.KEY_DOWN and self._files:
            self._file_cursor = min(len(self._files) - 1, self._file_cursor + 1)
            self._refresh()
            return True
        if key == curses.KEY_UP and self._files:
            self._file_cursor = max(0, self._file_cursor - 1)
            self._refresh()
            return True
        if key in (curses.KEY_ENTER, 10, 13):
            self._open_file()
            return True
        return False  # let sidebar handle LEFT/ESC

    def _handle_view(self, key):
        if key in (27, curses.KEY_LEFT):
            self._view_mode = "files"
            self._refresh()
            return True
        if key == curses.KEY_DOWN:
            if self._view_mode == "packets":
                self._packet_cursor = min(len(self._packets) - 1, self._packet_cursor + 1)
                self._packet_page = self._packet_cursor // PAGE_SIZE
            else:
                self._csv_cursor = min(len(self._csv_rows) - 1, self._csv_cursor + 1)
                self._csv_page = self._csv_cursor // PAGE_SIZE
            self._refresh()
            return True
        if key == curses.KEY_UP:
            if self._view_mode == "packets":
                self._packet_cursor = max(0, self._packet_cursor - 1)
                self._packet_page = self._packet_cursor // PAGE_SIZE
            else:
                self._csv_cursor = max(0, self._csv_cursor - 1)
                self._csv_page = self._csv_cursor // PAGE_SIZE
            self._refresh()
            return True
        if key == curses.KEY_NPAGE:
            if self._view_mode == "packets":
                tp = max(1, (len(self._packets) + PAGE_SIZE - 1) // PAGE_SIZE)
                if self._packet_page < tp - 1:
                    self._packet_page += 1
                    self._packet_cursor = self._packet_page * PAGE_SIZE
            else:
                tp = max(1, (len(self._csv_rows) + PAGE_SIZE - 1) // PAGE_SIZE)
                if self._csv_page < tp - 1:
                    self._csv_page += 1
                    self._csv_cursor = self._csv_page * PAGE_SIZE
            self._refresh()
            return True
        if key == curses.KEY_PPAGE:
            if self._view_mode == "packets" and self._packet_page > 0:
                self._packet_page -= 1
                self._packet_cursor = self._packet_page * PAGE_SIZE
            elif self._view_mode == "csv" and self._csv_page > 0:
                self._csv_page -= 1
                self._csv_cursor = self._csv_page * PAGE_SIZE
            self._refresh()
            return True
        return True

    def _load_files(self):
        import os
        self._files = []
        for d in ["data", "data/pcap", "data/metadata", "outputs", "outputs/pcap", "outputs/metadata"]:
            if os.path.isdir(d):
                self._files.extend(list_capture_files(d))
        # dedupe by normalized absolute path
        seen = set()
        unique = []
        for f in self._files:
            norm = os.path.normpath(os.path.abspath(f["path"]))
            if norm not in seen:
                seen.add(norm)
                unique.append(f)
        self._files = unique
        self._file_cursor = 0
        self._loaded = True
        EVENT_LOG.info(f"Artifacts: {len(self._files)} archivos")
        self._refresh()

    def _open_file(self):
        if not self._files or self._file_cursor >= len(self._files):
            return
        f = self._files[self._file_cursor]
        self._current_file = f["name"]
        self._error = ""
        if f["type"] in ("pcap", "pcapng"):
            EVENT_LOG.info(f"Abriendo PCAP: {f['name']}…")
            self._packets, self._error = read_pcap(f["path"])
            self._packet_cursor = 0
            self._packet_page = 0
            self._view_mode = "packets"
            if not self._error:
                EVENT_LOG.ok(f"{len(self._packets)} paquetes")
        elif f["type"] == "csv":
            EVENT_LOG.info(f"Abriendo CSV: {f['name']}…")
            self._csv_headers, self._csv_rows, self._error = read_csv_file(f["path"])
            self._csv_cursor = 0
            self._csv_page = 0
            self._view_mode = "csv"
            if not self._error:
                EVENT_LOG.ok(f"{len(self._csv_rows)} filas")
        if self._error:
            EVENT_LOG.error(self._error)
        self._refresh()

    def _refresh(self):
        updated = build_artifacts_section(
            files=self._files, file_cursor=self._file_cursor, view_mode=self._view_mode,
            packets=self._packets, packet_cursor=self._packet_cursor, packet_page=self._packet_page,
            csv_headers=self._csv_headers, csv_rows=self._csv_rows,
            csv_cursor=self._csv_cursor, csv_page=self._csv_page,
            current_file=self._current_file, error=self._error,
        )
        self._app.replace_section("artifacts", updated)
