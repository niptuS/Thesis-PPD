from __future__ import annotations

from pathlib import Path
from typing import Optional

from design.Menu_types import Section, FieldMeta


def _format_size(path: Path) -> str:
    if not path.exists():
        return "—"
    size = path.stat().st_size
    if size >= 1_073_741_824:
        return f"{size / 1_073_741_824:.1f} GB"
    if size >= 1_048_576:
        return f"{size / 1_048_576:.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _build_file_rows(manager) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    if manager is None:
        return rows

    pcap = manager.pcap_path
    if pcap:
        status = "complete" if pcap.exists() else "pending"
        rows.append((pcap.name, "PCAP", _format_size(pcap), status))

    csv_p = manager.metadata_path
    if csv_p:
        status = "complete" if csv_p.exists() else "pending"
        rows.append((csv_p.name, "metadata", _format_size(csv_p), status))

    log_p = pcap.with_suffix(".log") if pcap else None
    if log_p and log_p.exists():
        rows.append((log_p.name, "log", _format_size(log_p), "complete"))

    return rows


def _build_detail_block(manager, selected_artifact: str) -> list[str]:
    if manager is None or not selected_artifact:
        return ["  (sin selección)"]

    lines: list[str] = [f"─── Seleccionado: {selected_artifact} ────────────"]

    csv_p = manager.metadata_path
    if csv_p and csv_p.name == selected_artifact and csv_p.exists():
        try:
            from modules.artifacts.metadata.csv_reader import MetadataCsvReader
            from modules.artifacts.metadata.checksum   import compute_file_checksum
            reader   = MetadataCsvReader(csv_p)
            comments = reader.read_header_comments()
            rows     = reader.read_all()
            checksum = compute_file_checksum(csv_p)[:16]
            lines += [
                "",
                f"  Schema version : {comments.get('csv_version', '—')}",
                f"  Experiment ID  : {comments.get('experiment_id', '—')}",
                f"  Start time     : {comments.get('start_time', '—')}",
                f"  Events         : {len(rows)}",
                f"  SHA-256 (16)   : {checksum}",
                f"  Exportable     : yes",
            ]
            return lines
        except Exception:
            pass

    pcap = manager.pcap_path
    if pcap and pcap.name == selected_artifact and pcap.exists():
        try:
            from modules.artifacts.metadata.checksum import compute_file_checksum
            checksum = compute_file_checksum(pcap)[:16]
            lines += [
                "",
                f"  Size           : {_format_size(pcap)}",
                f"  SHA-256 (16)   : {checksum}",
                f"  Exportable     : yes",
            ]
            return lines
        except Exception:
            pass

    lines += ["", "  (detalles no disponibles)"]
    return lines


def build_artifacts_section(
    manager=None,
    selected_artifact: str = "",
    cursor_idx: int = 0,
) -> Section:
    file_rows = _build_file_rows(manager)

    col_name   = 24
    col_type   = 10
    col_size   = 10

    header_line = (
        f"  {'Name':<{col_name}} {'Type':<{col_type}} {'Size':<{col_size}} Status"
    )

    file_lines: list[str] = []
    for i, (name, ftype, size, status) in enumerate(file_rows):
        prefix = "> " if i == cursor_idx else "  "
        file_lines.append(
            f"{prefix}{name:<{col_name}} {ftype:<{col_type}} {size:<{col_size}} {status}"
        )

    if not file_lines:
        file_lines = ["  (sin archivos — ejecuta un escenario primero)"]

    detail_lines = _build_detail_block(manager, selected_artifact)

    lines: list[str] = [
        "─── Archivos generados ───────────────────────────",
        "",
        header_line,
        "",
        *file_lines,
        "",
        *detail_lines,
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [Enter] Ver info    [E] Exportar    [C] Checksum",
    ]

    field_map: list[FieldMeta] = []
    for i, (name, _, _, _) in enumerate(file_rows):
        line_idx = 4 + i
        field_map.append(
            FieldMeta(
                attr_path = f"artifact:{name}",
                label     = name,
                editable  = False,
                line_idx  = line_idx,
            )
        )

    return Section(
        key="artifacts",
        label="Artifacts",
        hint="↑↓ seleccionar archivo · Enter ver info · E exportar · C checksum",
        content_lines=lines,
        actions=[],
        field_map=field_map,
    )


ARTIFACTS_SECTION = build_artifacts_section()