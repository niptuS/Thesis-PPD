"""
Entrada: None
Salida: FlowExtractor class
Descripción: Flow extractor — reads PCAP file(s) and emits raw flow rows
             (one per bidirectional flow). Tries NFStream first and falls
             back to tshark. Extracted from the former LiveExecutionEngine
             monolith so that extraction can be tested independently of
             capture and labeling.
"""
from __future__ import annotations

import csv
import os
import subprocess
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# Curated attribute list that works across nfstream versions
_SAFE_ATTRS = [
    "id", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "ip_version", "vlan_id",
    "bidirectional_packets", "bidirectional_bytes",
    "bidirectional_duration_ms",
    "src2dst_packets", "src2dst_bytes",
    "dst2src_packets", "dst2src_bytes",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "application_name", "application_category_name",
    "requested_server_name", "client_fingerprint", "server_fingerprint",
]


class FlowExtractor:
    """
    Entrada: log_fn (Callable[[str, str], None] | None)
    Salida: None
    Descripción: Initializes the flow extractor with an optional logger.
    """

    def __init__(self, log_fn: Optional[Callable[[str, str], None]] = None) -> None:
        self._log_fn = log_fn
        self.flows_count: int = 0
        self.stats: dict[str, int] = {"attack": 0, "benign": 0, "unknown": 0}

    """
    Entrada: pcap_files (list[str]), flows_path (str)
    Salida: bool
    Descripción: Extract flows from the given PCAP file(s) and write them to
                 flows_path as a CSV. Returns True on success. Tries NFStream
                 first, then falls back to tshark.
    """
    def extract(self, pcap_files: list[str], flows_path: str) -> bool:
        if self._extract_nfstream(pcap_files, flows_path):
            return True
        if self._extract_tshark(pcap_files, flows_path):
            return True
        self._log(
            "Could not extract flows — install nfstream "
            "(pip install nfstream) or tshark (Wireshark)",
            "ERROR",
        )
        return False

    """
    Entrada: pcap_files (list[str]), flows_path (str)
    Salida: bool
    Descripción: Try NFStream extraction from all PCAP files; returns True on
                 success. Writes raw flow rows (no labels) — labeling is the
                 FlowLabeler's job.
    """
    def _extract_nfstream(self, pcap_files: list[str], flows_path: str) -> bool:
        self._log("Attempting NFStream…", "INFO")
        try:
            from nfstream import NFStreamer
        except ImportError:
            self._log("nfstream not installed", "WARN")
            return False

        if not pcap_files:
            self._log("No PCAP files to process", "WARN")
            return False

        try:
            self._log(f"Processing {len(pcap_files)} PCAP file(s)…", "INFO")
            count = 0
            self.stats = {"attack": 0, "benign": 0, "unknown": 0}

            with open(flows_path, "w", newline="", encoding="utf-8") as f:
                writer = None
                for pcap_file in pcap_files:
                    try:
                        streamer = NFStreamer(
                            source=pcap_file,
                            statistical_analysis=False,
                        )
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        self._log(
                            f"NFStream skip {os.path.basename(pcap_file)}: {exc}",
                            "WARN",
                        )
                        continue

                    for flow in streamer:
                        row = self._flow_to_dict(flow)
                        # src_role/dst_role/label/sublabel are filled by the
                        # FlowLabeler in a second pass; here we just emit raw.
                        for k in ("src_role", "dst_role", "label",
                                  "sublabel", "kill_chain", "subcategory"):
                            row.setdefault(k, "")
                        if writer is None:
                            writer = csv.DictWriter(f, fieldnames=row.keys())
                            writer.writeheader()
                        writer.writerow(row)
                        count += 1

            self.flows_count = count
            self._log(
                f"NFStream OK: {count} flows → {os.path.basename(flows_path)}",
                "OK",
            )
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"NFStream failed: {exc}", "WARN")
            return False

    """
    Entrada: pcap_files (list[str]), flows_path (str)
    Salida: bool
    Descripción: Fallback flow extraction using tshark (shipped with Wireshark).
                 Returns True on success. Emits packet-level rows (tshark does
                 not natively aggregate flows).
    """
    def _extract_tshark(self, pcap_files: list[str], flows_path: str) -> bool:
        import shutil
        tshark = shutil.which("tshark")
        if not tshark:
            import glob
            for p in glob.glob(r"C:\Program Files*\Wireshark\tshark.exe"):
                tshark = p
                break
        if not tshark:
            self._log("tshark not found", "WARN")
            return False

        self._log("Using tshark to extract flows…", "INFO")
        try:
            fields = [
                "frame.number", "frame.time", "frame.len",
                "ip.src", "ip.dst", "ip.proto",
                "tcp.srcport", "tcp.dstport",
                "udp.srcport", "udp.dstport",
            ]
            field_args = []
            for fld in fields:
                field_args.extend(["-e", fld])

            pcap_source = pcap_files[0] if pcap_files else ""
            if not pcap_source or not os.path.exists(pcap_source):
                self._log("tshark: no PCAP file to read", "WARN")
                return False

            cmd = [
                tshark, "-r", pcap_source,
                "-T", "fields",
                *field_args,
                "-E", "header=y",
                "-E", "separator=,",
                "-E", "quote=d",
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, check=False,
            )
            if result.returncode != 0:
                self._log(f"tshark error: {result.stderr[:200]}", "ERROR")
                return False

            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                self._log("tshark: no packets", "WARN")
                return False

            count = 0
            self.stats = {"attack": 0, "benign": 0, "unknown": 0}

            with open(flows_path, "w", newline="", encoding="utf-8") as f:
                header = lines[0].split(",")
                header.extend(["src_role", "dst_role", "flow_label",
                               "sublabel", "kill_chain", "subcategory"])
                writer = csv.writer(f)
                writer.writerow(header)

                for line in lines[1:]:
                    cols = line.split(",")
                    if len(cols) < len(fields):
                        continue
                    cols.extend(["", "", "", "", "", ""])  # placeholders for labels
                    writer.writerow(cols)
                    count += 1

            self.flows_count = count
            self._log(
                f"tshark OK: {count} packets → {os.path.basename(flows_path)}",
                "OK",
            )
            return True

        except subprocess.TimeoutExpired:
            self._log("tshark timeout", "ERROR")
            return False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"tshark error: {exc}", "ERROR")
            return False

    """
    Entrada: flow
    Salida: dict
    Descripción: Extract flow attributes safely — works with any nfstream
                 version. Uses the curated _SAFE_ATTRS list with fallbacks
                 for src/dst IP.
    """
    @staticmethod
    def _flow_to_dict(flow) -> dict:
        row = {}
        for attr in _SAFE_ATTRS:
            try:
                val = getattr(flow, attr, None)
                if val is not None and not callable(val):
                    row[attr] = val
            except (AttributeError, TypeError):
                pass
        if "src_ip" not in row:
            for fallback in ["src_addr", "source_ip", "ip_src"]:
                try:
                    row["src_ip"] = getattr(flow, fallback)
                    break
                except AttributeError:
                    pass
        if "dst_ip" not in row:
            for fallback in ["dst_addr", "dest_ip", "ip_dst"]:
                try:
                    row["dst_ip"] = getattr(flow, fallback)
                    break
                except AttributeError:
                    pass
        return row

    """
    Entrada: msg (str), level (str)
    Salida: None
    Descripción: Forward a log message to the external logger callback if set.
    """
    def _log(self, msg: str, level: str = "INFO") -> None:
        if self._log_fn:
            self._log_fn(msg, level)
