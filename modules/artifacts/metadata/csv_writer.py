from __future__ import annotations

import csv
import logging
import os
from pathlib import Path

from modules.artifacts.metadata.schema import (
    CSV_DELIMITER,
    CSV_ENCODING,
    ExperimentHeader,
    MetadataRow,
    ROW_FIELDS,
)

logger = logging.getLogger(__name__)


class MetadataCsvWriter:

    """
    Entrada: output_path (str | Path)
    Salida: None
    Descripción: Initializes the CSV writer bound to an output path.
    """
    def __init__(self, output_path: str | Path) -> None:
        self._path = Path(output_path)
        self._row_buf: list[MetadataRow] = []
        self._header: ExperimentHeader | None = None

    """
    Entrada: header (ExperimentHeader)
    Salida: None
    Descripción: Sets the experiment header to emit as comment block.
    """
    def set_header(self, header: ExperimentHeader) -> None:
        self._header = header

    """
    Entrada: row (MetadataRow)
    Salida: None
    Descripción: Appends a metadata row to the in-memory buffer.
    """
    def append_row(self, row: MetadataRow) -> None:
        self._row_buf.append(row)

    """
    Entrada: None
    Salida: Path
    Descripción: Writes the buffered rows and header to disk and returns the file path.
    """
    def flush(self) -> Path:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w", newline="", encoding=CSV_ENCODING) as fh:
            self._write_comment_block(fh)
            writer = csv.writer(fh, delimiter=CSV_DELIMITER, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(ROW_FIELDS)
            for row in self._row_buf:
                writer.writerow(row.to_csv_row())
        logger.info("metadata written path=%s rows=%d", self._path, len(self._row_buf))
        return self._path

    """
    Entrada: fh (file handle)
    Salida: None
    Descripción: Writes the header comment block to the open file handle.
    """
    def _write_comment_block(self, fh) -> None:
        if self._header is None:
            return
        for line in self._header.to_comment_block():
            fh.write(line + os.linesep)

    """
    Entrada: None
    Salida: int
    Descripción: Returns the number of buffered rows.
    """
    def row_count(self) -> int:
        return len(self._row_buf)

    """
    Entrada: None
    Salida: None
    Descripción: Clears the row buffer and header.
    """
    def clear(self) -> None:
        self._row_buf.clear()
        self._header = None
