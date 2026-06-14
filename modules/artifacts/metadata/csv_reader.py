from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Generator

from modules.artifacts.metadata.schema import (
    CSV_DELIMITER,
    CSV_ENCODING,
    MetadataRow,
    ROW_FIELDS,
)

logger = logging.getLogger(__name__)

_COMMENT_PREFIX = "#"


class CsvSchemaError(ValueError):
    pass


class MetadataCsvReader:

    def __init__(self, input_path: str | Path) -> None:
        self._path = Path(input_path)

    def read_header_comments(self) -> dict[str, str]:
        meta: dict[str, str] = {}
        with self._path.open("r", encoding=CSV_ENCODING) as fh:
            for raw in fh:
                line = raw.strip()
                if not line.startswith(_COMMENT_PREFIX):
                    break
                if ": " in line:
                    _, rest = line.split(" ", 1)
                    key, val = rest.split(": ", 1)
                    meta[key] = val
        return meta

    def iter_rows(self) -> Generator[MetadataRow, None, None]:
        with self._path.open("r", encoding=CSV_ENCODING) as fh:
            non_comment = (ln for ln in fh if not ln.startswith(_COMMENT_PREFIX))
            reader = csv.DictReader(non_comment, delimiter=CSV_DELIMITER)
            self._validate_columns(reader.fieldnames or [])
            for i, raw in enumerate(reader):
                try:
                    yield self._parse_row(raw)
                except (ValueError, KeyError) as exc:
                    logger.warning("skipping malformed row=%d error=%s", i + 1, exc)

    def read_all(self) -> list[MetadataRow]:
        return list(self.iter_rows())

    def _validate_columns(self, fieldnames: list[str]) -> None:
        missing = set(ROW_FIELDS) - set(fieldnames)
        if missing:
            raise CsvSchemaError(f"missing columns: {sorted(missing)}")

    def _parse_row(self, raw: dict[str, str]) -> MetadataRow:
        return MetadataRow(
            row_id=int(raw["row_id"]),
            experiment_id=raw["experiment_id"],
            run_id=raw["run_id"],
            absolute_timestamp=raw["absolute_timestamp"],
            relative_timestamp_s=float(raw["relative_timestamp_s"]),
            event_kind=raw["event_kind"],
            source_node=raw["source_node"],
            source_ip=raw["source_ip"],
            source_mac=raw["source_mac"],
            target_node=raw["target_node"],
            target_ip=raw["target_ip"],
            target_mac=raw["target_mac"],
            protocol=raw["protocol"],
            action=raw["action"],
            label=raw["label"],
            mitre_technique=raw["mitre_technique"],
            mitre_subtechnique=raw["mitre_subtechnique"],
            attack_intensity=raw["attack_intensity"],
            benign_profile=raw["benign_profile"],
            duration_s=float(raw["duration_s"]),
            notes=raw["notes"],
            row_checksum=raw["row_checksum"],
        )
