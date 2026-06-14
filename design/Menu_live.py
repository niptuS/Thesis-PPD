from __future__ import annotations
from design.models import Section


def _fmt_time(seconds: float) -> str:
    s = int(seconds)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _state_indicator(ok: bool) -> str:
    return "OK" if ok else "!!"


def build_live_section(
    state="IDLE", started_at="—", elapsed_s=0.0, remaining_s=0.0,
    planned_s=0.0, pcap_path="", metadata_path="", flows_path="",
    active_benign="—", active_attack="—", next_event="—",
    capture_ok=False, logger_ok=True, events_fired=0, events_total=0,
    flows_generated=0, error="",
) -> Section:
    content = [
        "─── Runtime ──────────────────────────────────────────",
        f"  Estado      : {state}",
        f"  Inicio      : {started_at}",
        f"  Transcurrido: {_fmt_time(elapsed_s)}",
        f"  Restante    : {_fmt_time(remaining_s)}",
        f"  Duración    : {_fmt_time(planned_s)}",
        "",
        "─── Archivos de salida ───────────────────────────────",
        f"  PCAP        : {pcap_path or '(pendiente)'}",
        f"  Metadatos   : {metadata_path or '(pendiente)'}",
        f"  Flujos CSV  : {flows_path or '(pendiente)'}",
        "",
        "─── Actividad actual ─────────────────────────────────",
        f"  Benigno     : {active_benign}",
        f"  Ataque      : {active_attack}",
        f"  Próximo     : {next_event}",
        f"  Eventos     : {events_fired}/{events_total}",
    ]
    if flows_generated > 0:
        content.append(f"  Flujos NFStream: {flows_generated}")
    content.append("")
    content.append("─── Health ───────────────────────────────────────────")
    content.append(f"  [capture= {_state_indicator(capture_ok)}]  [logger= {_state_indicator(logger_ok)}]")
    if error:
        content.append(f"  ⚠ Error: {error}")

    if state == "IDLE":
        hint = "Ctrl+R=iniciar · Configure escenario y dispositivos antes de ejecutar"
    elif state in ("RUNNING", "PAUSED"):
        hint = f"Ctrl+P=pausar · Ctrl+X=abortar · {_fmt_time(elapsed_s)}/{_fmt_time(planned_s)}"
    else:
        hint = f"Estado: {state} · Flujos: {flows_generated} · Ctrl+R=reiniciar"

    return Section(key="live", label="Live Execution", hint=hint,
                   content_lines=content, actions=[], field_map=[])


LIVE_SECTION: Section = build_live_section()
