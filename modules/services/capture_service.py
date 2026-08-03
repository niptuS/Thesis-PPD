"""
Entrada: None
Salida: CaptureService class
Descripción: Capture service — finds the right capture tool (tcpdump/tshark/
             dumpcap) on the system and manages the PCAP capture subprocess.
             Extracted from the former LiveExecutionEngine monolith so that
             capture decisions can be tested independently of event execution
             and flow extraction.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class CaptureService:
    """
    Entrada: log_fn (Callable[[str, str], None] | None)
    Salida: None
    Descripción: Initializes the capture service with an optional logger
                 callback (message, level). No capture is started yet.
    """

    def __init__(self, log_fn: Optional[Callable[[str, str], None]] = None) -> None:
        self._log_fn = log_fn
        self._pcap_proc: Optional[subprocess.Popen] = None
        self._pcap_path: str = ""
        self._pcap_max_size_kb: int = 512000
        self._iface: str = ""
        self._capture_ok: bool = False

    """
    Entrada: iface (str), pcap_path (str), pcap_max_size_kb (int)
    Salida: None
    Descripción: Configures the capture parameters (interface, output path,
                 max chunk size). Must be called before start().
    """
    def configure(self, iface: str, pcap_path: str,
                  pcap_max_size_kb: int = 512000) -> None:
        self._iface = iface
        self._pcap_path = os.path.abspath(pcap_path)
        self._pcap_max_size_kb = pcap_max_size_kb

    """
    Entrada: None
    Salida: bool
    Descripción: Returns True if the capture subprocess is currently running.
    """
    @property
    def is_running(self) -> bool:
        return self._pcap_proc is not None and self._pcap_proc.poll() is None

    """
    Entrada: None
    Salida: bool
    Salida: True if the last capture start succeeded.
    """
    @property
    def capture_ok(self) -> bool:
        return self._capture_ok

    """
    Entrada: None
    Salida: str
    Descripción: Returns the configured PCAP output path.
    """
    @property
    def pcap_path(self) -> str:
        return self._pcap_path

    """
    Entrada: None
    Salida: None
    Descripción: Resolve the capture tool and start the PCAP capture process
                 on the configured interface. Logs errors via the callback.
    """
    def start(self) -> None:
        if not self._iface:
            self._log("No capture interface configured", "WARN")
            self._capture_ok = False
            return

        for d in (os.path.dirname(self._pcap_path),):
            os.makedirs(d, exist_ok=True)
            try:
                os.chmod(d, 0o777)
            except OSError:
                pass

        tool = self._find_capture_tool()
        if not tool:
            self._log(
                "Capture tool not found (tcpdump/tshark/dumpcap). "
                "Linux: sudo apt install tcpdump  |  Windows: install Wireshark",
                "ERROR",
            )
            self._capture_ok = False
            return

        tool_name = os.path.basename(tool).lower().replace(".exe", "")
        self._log(f"Capture tool: {tool_name} ({tool})", "INFO")

        try:
            cmd = self._build_command(tool, tool_name)
            self._log(f"Command: {' '.join(cmd)}", "INFO")
            self._pcap_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            time.sleep(1)
            if self._pcap_proc.poll() is not None:
                _, stderr = self._pcap_proc.communicate(timeout=3)
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                self._log(f"Capture failed to start: {err_msg}", "ERROR")
                self._capture_ok = False
                self._pcap_proc = None
                return

            self._capture_ok = True
            self._log(f"Capture started on {self._iface}", "OK")

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error starting capture: {exc}", "ERROR")
            self._capture_ok = False

    """
    Entrada: tool (str), tool_name (str)
    Salida: list[str]
    Descripción: Builds the capture command for the given tool. Handles
                 tcpdump, tshark and dumpcap, with chunk rotation when
                 _pcap_max_size_kb > 0.
    """
    def _build_command(self, tool: str, tool_name: str) -> list[str]:
        if "tcpdump" in tool_name:
            cmd = [
                tool, "-i", self._iface,
                "-w", self._pcap_path,
                "-U", "-B", "4096", "--immediate-mode",
            ]
            if self._pcap_max_size_kb > 0:
                size_mb = max(1, self._pcap_max_size_kb // 1024)
                cmd.extend(["-C", str(size_mb)])
            return cmd
        if "tshark" in tool_name:
            cmd = [tool, "-i", self._iface, "-w", self._pcap_path, "-q"]
            if self._pcap_max_size_kb > 0:
                cmd.extend(["-b", f"filesize:{self._pcap_max_size_kb}"])
            return cmd
        if "dumpcap" in tool_name:
            cmd = [tool, "-i", self._iface, "-w", self._pcap_path, "-q"]
            if self._pcap_max_size_kb > 0:
                cmd.extend(["-b", f"filesize:{self._pcap_max_size_kb}"])
            return cmd
        return [tool, "-i", self._iface, "-w", self._pcap_path]

    """
    Entrada: None
    Salida: None
    Descripción: Stop the running PCAP capture process and log the total
                 captured file size.
    """
    def stop(self) -> None:
        import platform
        if self._pcap_proc is None:
            return
        try:
            if platform.system() != "Windows":
                self._pcap_proc.send_signal(signal.SIGINT)
            else:
                self._pcap_proc.terminate()
            self._pcap_proc.wait(timeout=5)
        except Exception:  # pylint: disable=broad-exception-caught
            try:
                self._pcap_proc.terminate()
                self._pcap_proc.wait(timeout=3)
            except Exception:  # pylint: disable=broad-exception-caught
                try:
                    self._pcap_proc.kill()
                except Exception:  # pylint: disable=broad-exception-caught
                    pass

        pcap_files = self.find_pcap_files()
        if pcap_files:
            total_size = sum(os.path.getsize(f) for f in pcap_files)
            size_str = (f"{total_size / 1048576:.1f} MB" if total_size > 1048576
                        else f"{total_size / 1024:.1f} KB")
            self._log(
                f"Capture stopped — {len(pcap_files)} PCAP file(s), {size_str} total",
                "OK",
            )
        else:
            self._log("Capture stopped — PCAP not generated", "WARN")
        self._pcap_proc = None
        self._capture_ok = False

    """
    Entrada: None
    Salida: str
    Descripción: Find tcpdump, tshark, or dumpcap on the system; returns the
                 tool path or empty string.
    """
    @staticmethod
    def find_capture_tool() -> str:
        import shutil
        import platform
        if platform.system() != "Windows":
            for tool in ["tcpdump", "dumpcap", "tshark"]:
                if shutil.which(tool):
                    return tool
            return ""
        for tool in ["tshark", "dumpcap"]:
            if shutil.which(tool):
                return tool
        import glob
        for pattern in [
            r"C:\Program Files\Wireshark\*.exe",
            r"C:\Program Files (x86)\Wireshark\*.exe",
        ]:
            for path in glob.glob(pattern):
                name = os.path.basename(path).lower()
                if "tshark" in name:
                    return path
                if "dumpcap" in name:
                    return path
        return ""

    # Backwards-compatible alias
    _find_capture_tool = find_capture_tool

    """
    Entrada: pcap_path (str)
    Salida: list[str]
    Descripción: Find all PCAP chunks for the given path and rename to
                 base_partN.pcap format. Handles dumpcap/tshark -b chunks
                 (base_00001_TIMESTAMP.pcapng) and tcpdump -C chunks
                 (base.pcap1, base.pcap2). Produces base.pcap, base_part1.pcap, ...
    """
    @staticmethod
    def find_pcap_files(pcap_path: str = "",
                        log_fn: Optional[Callable[[str, str], None]] = None) -> list[str]:
        if not pcap_path:
            return []
        pcap_dir = os.path.dirname(pcap_path)
        base_name = os.path.basename(pcap_path)
        base = base_name.rsplit(".", 1)[0]

        if not os.path.isdir(pcap_dir):
            return [pcap_path] if os.path.exists(pcap_path) else []

        exact_match = None
        rotated = []
        for fn in sorted(os.listdir(pcap_dir)):
            full = os.path.join(pcap_dir, fn)
            if not os.path.isfile(full):
                continue
            if fn == base_name:
                exact_match = full
            elif fn.startswith(base + "_") and any(
                fn.endswith(e) for e in (".pcap", ".pcapng")
            ):
                rotated.append(full)
            elif fn.startswith(base_name) and fn[len(base_name):].isdigit():
                rotated.append(full)

        renamed = []
        if exact_match:
            renamed.append(exact_match)
        elif rotated:
            first = rotated.pop(0)
            ext = ".pcapng" if first.endswith(".pcapng") else ".pcap"
            new_base = os.path.join(pcap_dir, base + ext)
            try:
                os.rename(first, new_base)
                if log_fn:
                    log_fn(f"Chunk: {os.path.basename(first)} → {base}{ext}", "INFO")
                renamed.append(new_base)
            except OSError:
                renamed.append(first)

        for i, fpath in enumerate(rotated, start=1):
            fn = os.path.basename(fpath)
            ext = ".pcapng" if fpath.endswith(".pcapng") else ".pcap"
            new_name = os.path.join(pcap_dir, f"{base}_part{i}{ext}")
            if fpath != new_name and not os.path.exists(new_name):
                try:
                    os.rename(fpath, new_name)
                    if log_fn:
                        log_fn(f"Chunk: {fn} → {os.path.basename(new_name)}", "INFO")
                    fpath = new_name
                except OSError:
                    pass
            renamed.append(fpath)

        if not renamed and os.path.exists(pcap_path):
            renamed.append(pcap_path)
        return renamed

    """
    Entrada: msg (str), level (str)
    Salida: None
    Descripción: Forward a log message to the external logger callback if set.
    """
    def _log(self, msg: str, level: str = "INFO") -> None:
        if self._log_fn:
            self._log_fn(msg, level)
