"""
Entrada: None
Salida: ArtifactManifestWriter class
Descripción: Artifact manifest writer — generates the metadata JSON manifest
             (experiment info, devices, events, artifacts with SHA-256) and
             saves the execution log. Extracted from the former
             LiveExecutionEngine monolith so artifact serialization can be
             tested independently of capture and labeling.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class ArtifactManifestWriter:
    """
    Entrada: log_fn (Callable[[str, str], None] | None)
    Salida: None
    Descripción: Initializes the manifest writer with an optional logger.
    """

    def __init__(self, log_fn: Optional[Callable[[str, str], None]] = None) -> None:
        self._log_fn = log_fn

    """
    Entrada: meta_path, pcap_path, flows_path, config, state, started_at,
             ended_at, planned_s, iface, device_map, events,
             events_fired, flows_count
    Salida: bool
    Descripción: Generate and write the metadata JSON manifest summarizing
                 the execution, artifacts (with SHA-256), and enriched event
                 metadata. Returns True on success.
    """
    def write_manifest(
        self,
        meta_path: str,
        pcap_path: str,
        flows_path: str,
        config,
        state: str,
        started_at: float,
        ended_at: float,
        planned_s: float,
        iface: str,
        device_map: dict,
        device_info: dict | None = None,
        events: list = None,
        events_fired: int = 0,
        flows_count: int = 0,
    ) -> bool:
        exp_id = getattr(config, "experiment_id", "EXP")
        now = datetime.now(timezone.utc).isoformat()
        actual_dur = (ended_at - started_at) if ended_at else 0.0

        artifacts = []
        # Collect all PCAP chunks
        from modules.services.capture_service import CaptureService
        for pf in CaptureService.find_pcap_files(pcap_path):
            if os.path.exists(pf):
                artifacts.append({
                    "name": os.path.basename(pf),
                    "type": "PCAP",
                    "size_bytes": os.path.getsize(pf),
                    "sha256": self.sha256(pf),
                    "path": pf,
                })
        for path in (flows_path, meta_path):
            if os.path.exists(path):
                artifacts.append({
                    "name": os.path.basename(path),
                    "type": path.rsplit(".", 1)[-1].upper(),
                    "size_bytes": os.path.getsize(path),
                    "sha256": self.sha256(path),
                    "path": path,
                })

        metadata = {
            "experiment_id": exp_id,
            "environment": getattr(config, "environment", ""),
            "orchestrator_version": getattr(config, "orchestrator_version", "1.0.0"),
            "started_at": (
                datetime.fromtimestamp(started_at, timezone.utc).isoformat()
                if started_at else ""
            ),
            "finished_at": now,
            "planned_duration_s": planned_s,
            "actual_duration_s": round(actual_dur, 2),
            "state": state,
            "capture_interface": iface,
            "devices": {ip: (device_info or {}).get(ip, {"role": role, "mac": ""})
                        for ip, role in device_map.items()},
            "events_total": len(events),
            "events_fired": events_fired,
            "flows_extracted": flows_count,
            "events": [self.enrich_event_metadata(ev, device_map) for ev in events],
            "artifacts": artifacts,
        }

        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, default=str)
            self._log(f"Metadata: {os.path.basename(meta_path)}", "OK")
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error generating metadata: {exc}", "ERROR")
            return False

    """
    Entrada: pcap_path (str)
    Salida: bool
    Descripción: Save the event log to a text file inside the output directory.
                 The log entries are read from the shared EVENT_LOG ring buffer
                 (imported lazily to avoid circular imports).
    """
    def save_execution_log(self, pcap_path: str) -> bool:
        try:
            log_dir = os.path.join(
                os.path.dirname(os.path.dirname(pcap_path)), "logs",
            )
            os.makedirs(log_dir, exist_ok=True)
            base_name = os.path.basename(pcap_path).rsplit(".", 1)[0]
            log_path = os.path.join(log_dir, f"{base_name}_log.txt")
            from design.Menu_logs import EVENT_LOG
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("SH-DATASET Execution Log\n")
                f.write("========================\n\n")
                for entry in EVENT_LOG.entries():
                    f.write(f"{entry.timestamp} {entry.level:<5} {entry.message}\n")
            self._log(f"Log saved: {os.path.basename(log_path)}", "OK")
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error saving log: {exc}", "WARN")
            return False

    """
    Entrada: ev (dict), device_map (dict)
    Salida: dict
    Descripción: Enrich an event dict with kill-chain classification, MITRE
                 reference, and tool metadata for attack events.
    """
    @staticmethod
    def enrich_event_metadata(ev: dict, device_map: dict) -> dict:
        from modules.devices.host_detector import get_host_ip
        source = ev.get("source", "")
        if source and source not in device_map:
            source = get_host_ip()
        meta = {
            "event_type": ev.get("event_type", ""),
            "action": ev.get("action", ""),
            "target": ev.get("target", ""),
            "source": source,
            "scheduled_dt": ev.get("scheduled_dt", ""),
            "duration_s": ev.get("duration_s", 0),
            "status": ev.get("status", ""),
            "label": "attack" if ev.get("event_type") == "attack" else "benign",
            "sublabel": "artificial",
        }
        if ev.get("event_type") == "attack":
            action = ev.get("action", "")
            from modules.attacks import get_attack_class, get_plugin_attacks
            atk = get_attack_class(action)
            if atk is None:
                plugins = get_plugin_attacks() or []
                for p in plugins:
                    if p.name == action:
                        atk = p
                        break
            if atk:
                meta["category"] = getattr(atk, "kill_chain", "")
                meta["subcategory"] = getattr(atk, "subcategory", "")
                meta["mitre_ref"] = getattr(atk, "mitre_ref", "")
                meta["tool"] = getattr(atk, "tool", "")
        return meta

    """
    Entrada: path (str)
    Salida: str
    Descripción: Compute the SHA-256 hex digest of a file, or return an empty
                 string on error.
    """
    @staticmethod
    def sha256(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:  # pylint: disable=broad-exception-caught
            return ""

    """
    Entrada: msg (str), level (str)
    Salida: None
    Descripción: Forward a log message to the external logger callback if set.
    """
    def _log(self, msg: str, level: str = "INFO") -> None:
        if self._log_fn:
            self._log_fn(msg, level)
