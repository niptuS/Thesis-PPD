"""
Entrada: None
Salida: FlowLabeler class
Descripción: Flow labeler — assigns (src_role, dst_role, label, sublabel,
             kill_chain, subcategory) to each flow row based on the device
             map and the scheduled attack events. This is the scientific
             decision extracted from the former LiveExecutionEngine monolith
             so it can be unit-tested independently of capture and extraction.
"""
from __future__ import annotations

import csv
import os
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class FlowLabeler:
    """
    Entrada: device_map (dict[str, str]), events (list[dict]), capture_benign (bool), log_fn (Callable | None)
    Salida: None
    Descripción: Initializes the flow labeler with the device {ip: role} map
                 and the list of scheduled timeline events. capture_benign
                 controls whether benign flows are kept or filtered out.
    """

    def __init__(
        self,
        device_map: dict[str, str],
        events: list[dict],
        capture_benign: bool = True,
        log_fn: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._device_map = dict(device_map or {})
        self._events = list(events or [])
        self._capture_benign = capture_benign
        self._log_fn = log_fn
        self.stats: dict[str, int] = {"attack": 0, "benign": 0, "unknown": 0}
        self.labeled_count: int = 0
        self.filtered_count: int = 0

    """
    Entrada: src_ip (str), dst_ip (str)
    Salida: tuple
    Descripción: Classify a flow and return
                 (src_role, dst_role, label, sublabel, kill_chain, subcategory)
                 based on the device map and matching attack events.
    """
    def classify(self, src_ip: str, dst_ip: str) -> tuple:
        src_role = self._device_map.get(src_ip, "unknown")
        dst_role = self._device_map.get(dst_ip, "unknown")

        if src_role == "attacker" or dst_role == "attacker":
            label = "attack"
        else:
            label = "benign"

        sublabel = "artificial"

        kill_chain = ""
        subcategory = ""
        if label == "attack":
            for ev in self._events:
                if ev.get("event_type") == "attack":
                    ev_target = ev.get("target", "")
                    ev_source = ev.get("source", "")
                    if (dst_ip == ev_target or src_ip == ev_target) and \
                       (src_ip == ev_source or dst_ip == ev_source or not ev_source):
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
                            kill_chain = getattr(atk, "kill_chain", "")
                            subcategory = getattr(atk, "subcategory", "")
                        break

        return src_role, dst_role, label, sublabel, kill_chain, subcategory

    """
    Entrada: flows_path (str)
    Salida: bool
    Descripción: Read the CSV at flows_path, fill the src_role/dst_role/label/
                 sublabel/kill_chain/subcategory columns using classify(), and
                 optionally filter out benign flows when capture_benign=False.
                 Returns True on success.
    """
    def label(self, flows_path: str) -> bool:
        if not os.path.exists(flows_path):
            self._log(f"Flows file not found: {flows_path}", "ERROR")
            return False

        try:
            with open(flows_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                fieldnames = reader.fieldnames or []
        except (OSError, csv.Error) as exc:
            self._log(f"Error reading flows: {exc}", "ERROR")
            return False

        # Make sure the labeling columns exist
        for col in ("src_role", "dst_role", "label", "sublabel",
                    "kill_chain", "subcategory"):
            if col not in fieldnames:
                fieldnames.append(col)

        self.stats = {"attack": 0, "benign": 0, "unknown": 0}
        self.labeled_count = 0
        self.filtered_count = 0
        kept_rows = []

        for row in rows:
            src_ip = row.get("src_ip", "")
            dst_ip = row.get("dst_ip", "")
            src_role, dst_role, label, sublabel, kill_chain, subcat = self.classify(
                src_ip, dst_ip,
            )
            self.stats[label] = self.stats.get(label, 0) + 1

            if not self._capture_benign and label != "attack":
                self.filtered_count += 1
                continue

            row["src_role"] = src_role
            row["dst_role"] = dst_role
            row["label"] = label
            row["sublabel"] = sublabel
            row["kill_chain"] = kill_chain
            row["subcategory"] = subcat
            kept_rows.append(row)
            self.labeled_count += 1

        try:
            with open(flows_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(kept_rows)
        except (OSError, csv.Error) as exc:
            self._log(f"Error writing labeled flows: {exc}", "ERROR")
            return False

        self._log(
            f"Labeled {self.labeled_count} flows "
            f"({self.stats['attack']} attack, {self.stats['benign']} benign, "
            f"{self.stats['unknown']} unknown) — "
            f"{self.filtered_count} benign filtered out",
            "OK",
        )
        return True

    """
    Entrada: msg (str), level (str)
    Salida: None
    Descripción: Forward a log message to the external logger callback if set.
    """
    def _log(self, msg: str, level: str = "INFO") -> None:
        if self._log_fn:
            self._log_fn(msg, level)
