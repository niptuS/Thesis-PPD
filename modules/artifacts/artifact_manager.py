from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from modules.artifacts.metadata.schema import build_header, build_row_from_event, MetadataRow, EventKind
from modules.artifacts.metadata.csv_writer import MetadataCsvWriter
from modules.artifacts.metadata.csv_reader import MetadataCsvReader
from modules.artifacts.metadata.checksum import compute_file_checksum
from modules.artifacts.pcap.pcap_writer import PcapWriter

logger = logging.getLogger(__name__)


class ArtifactManager:

    """
    Entrada: output_dir (str | Path), experiment_id (str), run_id (str), environment (str), scenario_name (str), scenario_start (datetime), planned_duration_s (int), orchestrator_version (str), capture_interface (str)
    Salida: None
    Descripción: Initializes the artifact manager, opening PCAP and metadata CSV writers.
    """
    def __init__(
        self,
        output_dir: str | Path,
        experiment_id: str,
        run_id: str,
        environment: str,
        scenario_name: str,
        scenario_start: datetime,
        planned_duration_s: int,
        orchestrator_version: str = "1.0.0",
        capture_interface: str = "eth0",
    ) -> None:
        self._output_dir = Path(output_dir)
        self._experiment_id = experiment_id
        self._run_id = run_id
        self._scenario_start = scenario_start
        self._row_counter = 0

        pcap_path = self._output_dir / f"{experiment_id}-{run_id}.pcap"
        metadata_path = self._output_dir / f"{experiment_id}-{run_id}.csv"

        self._pcap_writer = PcapWriter(
            output_path=pcap_path,
            capture_interface=capture_interface,
            experiment_id=experiment_id,
            run_id=run_id,
        )

        header = build_header(
            experiment_id=experiment_id,
            environment=environment,
            scenario_name=scenario_name,
            start_time=scenario_start,
            planned_duration_s=planned_duration_s,
            pcap_file=pcap_path.name,
            orchestrator_version=orchestrator_version,
        )
        self._csv_writer = MetadataCsvWriter(metadata_path)
        self._csv_writer.set_header(header)

        self._metadata_path = metadata_path
        self._pcap_path = pcap_path

    """
    Entrada: None
    Salida: None
    Descripción: Starts PCAP capture.
    """
    def start_capture(self) -> None:
        self._pcap_writer.start()
        logger.info("capture started interface=%s", self._pcap_writer.interface)

    """
    Entrada: None
    Salida: None
    Descripción: Stops PCAP capture.
    """
    def stop_capture(self) -> None:
        self._pcap_writer.stop()
        logger.info("capture stopped pcap=%s", self._pcap_path)

    """
    Entrada: event_ts (datetime), event_kind (EventKind), source_node (str), source_ip (str), source_mac (str), target_node (str), target_ip (str), target_mac (str), protocol (str), action (str), label (str), mitre_technique (str), mitre_subtechnique (str), attack_intensity (str), benign_profile (str), duration_s (float), notes (str)
    Salida: MetadataRow
    Descripción: Records an event row in the metadata CSV.
    """
    def record_event(
        self,
        event_ts: datetime,
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
        self._row_counter += 1
        row = build_row_from_event(
            row_id=self._row_counter,
            experiment_id=self._experiment_id,
            run_id=self._run_id,
            event_ts=event_ts,
            scenario_start=self._scenario_start,
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
            duration_s=duration_s,
            notes=notes,
        )
        self._csv_writer.append_row(row)
        return row

    """
    Entrada: None
    Salida: Path
    Descripción: Flushes pending metadata rows to disk.
    """
    def flush_metadata(self) -> Path:
        path = self._csv_writer.flush()
        logger.info("metadata flushed path=%s rows=%d", path, self._csv_writer.row_count())
        return path

    """
    Entrada: None
    Salida: dict[str, str]
    Descripción: Stops capture, flushes metadata, and returns artifact paths and checksums.
    """
    def finalize(self) -> dict[str, str]:
        self.stop_capture()
        meta_path = self.flush_metadata()
        return {
            "pcap": str(self._pcap_path),
            "metadata_csv": str(meta_path),
            "pcap_sha256": compute_file_checksum(self._pcap_path) if self._pcap_path.exists() else "",
            "csv_sha256": compute_file_checksum(meta_path) if meta_path.exists() else "",
        }

    """
    Entrada: None
    Salida: MetadataCsvReader
    Descripción: Returns a CSV reader bound to the metadata file.
    """
    def reader(self) -> MetadataCsvReader:
        return MetadataCsvReader(self._metadata_path)

    """
    Entrada: None
    Salida: Path
    Descripción: Returns the PCAP file path.
    """
    @property
    def pcap_path(self) -> Path:
        return self._pcap_path

    """
    Entrada: None
    Salida: Path
    Descripción: Returns the metadata CSV file path.
    """
    @property
    def metadata_path(self) -> Path:
        return self._metadata_path
