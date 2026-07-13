"""
Entrada: None
Salida: pcap_viewer module
Descripción: PCAP/CSV Viewer — reads capture files and extracts packet/flow data.
             Uses tshark for PCAPs, csv module for CSVs.
"""
from __future__ import annotations
import csv
import os
import subprocess
import shutil
from dataclasses import dataclass


@dataclass
class PacketRow:
    no: str = ""
    time: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    length: str = ""
    src_port: str = ""
    dst_port: str = ""
    flags: str = ""
    info: str = ""


def read_pcap(path: str, max_packets: int = 500) -> tuple[list[PacketRow], str]:
    """Read PCAP using tshark. Returns (packets, error)."""
    tshark = shutil.which("tshark")
    if not tshark:
        import glob
        for p in glob.glob(r"C:\Program Files*\Wireshark\tshark.exe"):
            tshark = p
            break
    if not tshark:
        return [], "tshark not found (install Wireshark)"
    if not os.path.exists(path):
        return [], f"File not found: {path}"

    try:
        cmd = [
            tshark, "-r", path, "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.flags.str",
            "-e", "_ws.col.Info",
            "-E", "header=y",
            "-E", "separator=|",
            "-c", str(max_packets),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            return [], f"tshark error: {result.stderr[:200]}"

        packets = []
        lines = result.stdout.strip().split("\n")
        for line in lines[1:]:
            cols = line.split("|")
            if len(cols) < 6:
                continue
            packets.append(PacketRow(
                no=cols[0].strip(),
                time=cols[1].strip()[:8],
                src_ip=cols[2].strip(),
                dst_ip=cols[3].strip(),
                protocol=cols[4].strip(),
                length=cols[5].strip(),
                src_port=cols[6].strip() if len(cols) > 6 else "",
                dst_port=cols[7].strip() if len(cols) > 7 else "",
                flags=cols[8].strip() if len(cols) > 8 else "",
                info=cols[9].strip()[:40] if len(cols) > 9 else "",
            ))
        return packets, ""
    except subprocess.TimeoutExpired:
        return [], "tshark timeout"
    except (OSError, ValueError, RuntimeError) as e:
        return [], str(e)


def read_csv_file(path: str, max_rows: int = 500) -> tuple[list[str], list[list[str]], str]:
    """Read CSV file. Returns (headers, rows, error)."""
    if not os.path.exists(path):
        return [], [], f"File not found: {path}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            rows = []
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                rows.append(row)
        return headers, rows, ""
    except (OSError, ValueError, RuntimeError) as e:
        return [], [], str(e)


def list_capture_files(output_dir: str = "data") -> list[dict]:
    """List available PCAP and CSV files in the output directory."""
    files = []
    for root, dirs, filenames in os.walk(output_dir):
        for fn in sorted(filenames):
            ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
            if ext in ("pcap", "pcapng", "csv"):
                full = os.path.join(root, fn)
                size = os.path.getsize(full)
                files.append({
                    "name": fn,
                    "path": full,
                    "type": ext,
                    "size": size,
                    "size_str": f"{size / 1024:.1f} KB" if size < 1048576 else f"{size / 1048576:.1f} MB",
                })
    return files
