from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Literal

CSV_VERSION = "1.0"
CSV_DELIMITER = ","
CSV_ENCODING = "utf-8"
CSV_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

EventKind = Literal["benign", "attack", "system"]

HEADER_FIELDS: list[str] = [
    "csv_version",
    "schema_version",
    "experiment_id",
    "environment",
    "scenario_name",
    "start_time",
    "planned_duration_s",
    "generated_at",
    "pcap_file",
    "orchestrator_version",
]

ROW_FIELDS: list[str] = [
    "row_id",
    "experiment_id",
    "run_id",
    "absolute_timestamp",
    "relative_timestamp_s",
    "event_kind",
    "source_node",
    "source_ip",
    "source_mac",
    "target_node",
    "target_ip",
    "target_mac",
    "protocol",
    "action",
    "label",
    "mitre_technique",
    "mitre_subtechnique",
    "attack_intensity",
    "benign_profile",
    "duration_s",
    "notes",
    "row_checksum",
]


@dataclass
class ExperimentHeader:
    csv_version: str = CSV_VERSION
    schema_version: str = "1.0"
    experiment_id: str = ""
    environment: str = ""
    scenario_name: str = ""
    start_time: str = ""
    planned_duration_s: int = 0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(CSV_DATE_FORMAT)
    )
    pcap_file: str = ""
    orchestrator_version: str = "1.0.0"

    """
    Entrada: None
    Salida: list[str]
    Descripción: Returns the header fields as comment lines for the CSV file.
    """
    def to_comment_block(self) -> list[str]:
        lines: list[str] = ["# SH-DATASET metadata export"]
        for f in fields(self):
            lines.append(f"# {f.name}: {getattr(self, f.name)}")
        return lines


@dataclass
class MetadataRow:
    row_id: int = 0
    experiment_id: str = ""
    run_id: str = ""
    absolute_timestamp: str = ""
    relative_timestamp_s: float = 0.0
    event_kind: str = "system"
    source_node: str = ""
    source_ip: str = ""
    source_mac: str = ""
    target_node: str = ""
    target_ip: str = ""
    target_mac: str = ""
    protocol: str = ""
    action: str = ""
    label: str = ""
    mitre_technique: str = ""
    mitre_subtechnique: str = ""
    attack_intensity: str = ""
    benign_profile: str = ""
    duration_s: float = 0.0
    notes: str = ""
    row_checksum: str = ""

    """
    Entrada: None
    Salida: list[str]
    Descripción: Returns the row fields as a list of CSV cell strings.
    """
    def to_csv_row(self) -> list[str]:
        return [str(getattr(self, f.name)) for f in fields(self)]

    """
    Entrada: None
    Salida: None
    Descripción: Computes and sets the row checksum from all fields except row_checksum.
    """
    def compute_and_set_checksum(self) -> None:
        payload = CSV_DELIMITER.join(
            str(getattr(self, f.name))
            for f in fields(self)
            if f.name != "row_checksum"
        )
        self.row_checksum = hashlib.sha256(payload.encode(CSV_ENCODING)).hexdigest()[:16]


"""
Entrada: experiment_id, environment, scenario_name, start_time,
         planned_duration_s, pcap_file, orchestrator_version
Salida: ExperimentHeader
Descripción: Builds an ExperimentHeader instance from the given
             experiment metadata.
"""
def build_header(
    experiment_id: str,
    environment: str,
    scenario_name: str,
    start_time: datetime,
    planned_duration_s: int,
    pcap_file: str,
    orchestrator_version: str = "1.0.0",
) -> ExperimentHeader:
    return ExperimentHeader(
        experiment_id=experiment_id,
        environment=environment,
        scenario_name=scenario_name,
        start_time=start_time.strftime(CSV_DATE_FORMAT),
        planned_duration_s=planned_duration_s,
        pcap_file=pcap_file,
        orchestrator_version=orchestrator_version,
    )


"""
Entrada: row_id, experiment_id, run_id, event_ts, scenario_start,
         event_kind, source_node, source_ip, source_mac,
         target_node, target_ip, target_mac, protocol, action,
         label, mitre_technique, mitre_subtechnique,
         attack_intensity, benign_profile, duration_s, notes
Salida: MetadataRow
Descripción: Builds a MetadataRow from an event, computing relative
             time and checksum.
"""
def build_row_from_event(
    row_id: int,
    experiment_id: str,
    run_id: str,
    event_ts: datetime,
    scenario_start: datetime,
    event_kind: EventKind,
    source_node: str,
    source_ip: str,
    source_mac: str,
    target_node: str = "",
    target_ip: str = "",
    target_mac: str = "",
    protocol: str = "",
    action: str = "",
    label: str = "",
    mitre_technique: str = "",
    mitre_subtechnique: str = "",
    attack_intensity: str = "",
    benign_profile: str = "",
    duration_s: float = 0.0,
    notes: str = "",
) -> MetadataRow:
    relative_s = (event_ts - scenario_start).total_seconds()
    row = MetadataRow(
        row_id=row_id,
        experiment_id=experiment_id,
        run_id=run_id,
        absolute_timestamp=event_ts.strftime(CSV_DATE_FORMAT),
        relative_timestamp_s=round(relative_s, 3),
        event_kind=event_kind,
        source_node=source_node,
        source_ip=source_ip,
        source_mac=source_mac,
        target_node=target_node,
        target_ip=target_ip,
        target_mac=target_mac,
        protocol=protocol,
        action=action,
        label=label,
        mitre_technique=mitre_technique,
        mitre_subtechnique=mitre_subtechnique,
        attack_intensity=attack_intensity,
        benign_profile=benign_profile,
        duration_s=round(duration_s, 3),
        notes=notes,
    )
    row.compute_and_set_checksum()
    return row
