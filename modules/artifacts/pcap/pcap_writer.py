from __future__ import annotations

import logging
import shutil
import subprocess
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_TCPDUMP_BIN = "tcpdump"


class PcapCaptureError(RuntimeError):
    pass


class PcapWriter:

    def __init__(
        self,
        output_path: str | Path,
        capture_interface: str,
        experiment_id: str,
        run_id: str,
        snaplen: int = 65535,
        extra_filter: str = "",
    ) -> None:
        self._path = Path(output_path)
        self._interface = capture_interface
        self._snaplen = snaplen
        self._filter = extra_filter
        self._exp_id = experiment_id
        self._run_id = run_id
        self._process: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._running: bool = False

    @property
    def interface(self) -> str:
        return self._interface

    @property
    def output_path(self) -> Path:
        return self._path

    def start(self) -> None:
        if self._running:
            logger.warning("capture already running run_id=%s", self._run_id)
            return

        if not shutil.which(_TCPDUMP_BIN):
            logger.warning("tcpdump not found — using stub capture run_id=%s", self._run_id)
            self._running = True
            return

        self._path.parent.mkdir(parents=True, exist_ok=True)

        cmd: list[str] = [
            _TCPDUMP_BIN,
            "-i", self._interface,
            "-s", str(self._snaplen),
            "-w", str(self._path),
            "-U",
        ]
        if self._filter:
            cmd.append(self._filter)

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_stderr,
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "tcpdump started pid=%d interface=%s output=%s",
                self._process.pid, self._interface, self._path,
            )
        except OSError as exc:
            raise PcapCaptureError(f"failed to start tcpdump: {exc}") from exc

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                logger.warning("tcpdump killed after timeout run_id=%s", self._run_id)
            self._process = None
        logger.info("capture stopped run_id=%s path=%s", self._run_id, self._path)

    def is_running(self) -> bool:
        return self._running

    def _monitor_stderr(self) -> None:
        if self._process is None or self._process.stderr is None:
            return
        for raw in self._process.stderr:
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                logger.debug("tcpdump stderr: %s", line)
