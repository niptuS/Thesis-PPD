from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from design.Menu_types import Section, FieldMeta


def build_live_section(
    manager=None,
    scenario_start: Optional[datetime] = None,
    planned_duration_s: int = 0,
    next_event_label: str = "—",
    active_benign: str = "—",
    active_attack: str = "—",
) -> Section:
    elapsed_s    = 0.0
    remaining_s  = float(planned_duration_s)
    pcap_file    = "—"
    meta_file    = "—"
    capture_ok   = "—"
    is_running   = False

    if manager is not None and scenario_start is not None:
        now          = datetime.now(timezone.utc)
        elapsed_s    = max(0.0, (now - scenario_start).total_seconds())
        remaining_s  = max(0.0, planned_duration_s - elapsed_s)
        pcap_file    = manager.pcap_path.name    if manager.pcap_path    else "—"
        meta_file    = manager.metadata_path.name if manager.metadata_path else "—"
        is_running   = manager._pcap_writer.is_running()
        capture_ok   = "OK" if is_running else "STOPPED"

    def fmt_time(seconds: float) -> str:
        h  = int(seconds) // 3600
        m  = (int(seconds) % 3600) // 60
        s  = int(seconds) % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

    capture_badge = f"[capture: {capture_ok}]"
    logger_badge  = "[logger: OK]"
    clock_badge   = "[clock sync: OK]"

    lines: list[str] = [
        "─── Runtime ──────────────────────────────────────",
        "",
        f"  Started at    : {scenario_start.strftime('%H:%M:%S') if scenario_start else '—'}",
        f"  Elapsed       : {fmt_time(elapsed_s)}",
        f"  Remaining     : {fmt_time(remaining_s)}",
        f"  PCAP file     : {pcap_file}",
        f"  Metadata file : {meta_file}",
        "",
        "─── Current Activity ─────────────────────────────",
        "",
        f"  Active benign : {active_benign}",
        f"  Active attack : {active_attack}",
        f"  Next event    : {next_event_label}",
        "",
        "─── Health ───────────────────────────────────────",
        "",
        f"  {capture_badge}    {logger_badge}    {clock_badge}",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [Ctrl+P] Pausa    [Ctrl+R] Reanudar    [Ctrl+X] Abortar",
    ]

    hint = (
        "Ejecución activa — Ctrl+P pausar · Ctrl+R reanudar · Ctrl+X abortar"
        if is_running else
        "Sin ejecución activa — Ctrl+R para iniciar · Ctrl+O para cargar escenario"
    )

    return Section(
        key="live",
        label="Live Execution",
        hint=hint,
        content_lines=lines,
        actions=[],
        field_map=[],
    )


LIVE_SECTION = build_live_section()