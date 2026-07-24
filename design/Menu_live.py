"""
Entrada: None
Salida: Section
Descripción: Builds the Live Execution section showing runtime state, output
             file paths, current activity, and health indicators.
"""
from __future__ import annotations
from design.models import Section
from modules.i18n import t


"""
Entrada: seconds (float)
Salida: str
Descripción: Formats seconds as HH:MM:SS.
"""
def _fmt_time(seconds: float) -> str:
    s = int(seconds)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


"""
Entrada: ok (bool)
Salida: str
Descripción: Returns "OK" or "!!" based on the boolean.
"""
def _state_indicator(ok: bool) -> str:
    return "OK" if ok else "!!"


"""
Entrada: state, started_at, elapsed_s, remaining_s, planned_s, pcap_path,
         metadata_path, flows_path, active_benign, active_attack, next_event,
         capture_ok, logger_ok, events_fired, events_total, flows_generated, error
Salida: Section
Descripción: Builds the live execution section with localized labels.
"""
def build_live_section(
    state="IDLE", started_at="—", elapsed_s=0.0, remaining_s=0.0,
    planned_s=0.0, pcap_path="", metadata_path="", flows_path="",
    active_benign="—", active_attack="—", next_event="—",
    capture_ok=False, logger_ok=True, events_fired=0, events_total=0,
    flows_generated=0, error="",
) -> Section:
    pending = t("live", "pending")
    content = [
        f"─── {t('live', 'runtime')} ──────────────────────────────────────────",
        f"  {t('live', 'state'):<12}: {state}",
        f"  {t('live', 'start'):<12}: {started_at}",
        f"  {t('live', 'elapsed'):<12}: {_fmt_time(elapsed_s)}",
        f"  {t('live', 'remaining'):<12}: {_fmt_time(remaining_s)}",
        f"  {t('live', 'duration'):<12}: {_fmt_time(planned_s)}",
        "",
        f"─── {t('live', 'output_files')} ───────────────────────────────",
        f"  PCAP        : {pcap_path or pending}",
        f"  Metadata    : {metadata_path or pending}",
        f"  Flows CSV   : {flows_path or pending}",
        "",
        f"─── {t('live', 'current_activity')} ─────────────────────────────────",
        f"  {t('live', 'benign'):<12}: {active_benign}",
        f"  {t('live', 'attack'):<12}: {active_attack}",
        f"  {t('live', 'next'):<12}: {next_event}",
        f"  {t('live', 'events'):<12}: {events_fired}/{events_total}",
    ]
    if flows_generated > 0:
        content.append(f"  {t('live', 'flows_nfstream')}: {flows_generated}")
    content.append("")
    content.append(f"─── {t('live', 'health')} ───────────────────────────────────────────")
    content.append(f"  [capture= {_state_indicator(capture_ok)}]  [logger= {_state_indicator(logger_ok)}]")
    if error:
        content.append(f"  ⚠ Error: {error}")

    if state == "IDLE":
        hint = t("live", "hint_idle")
    elif state in ("RUNNING", "PAUSED"):
        hint = t("live", "hint_running", _fmt_time(elapsed_s), _fmt_time(planned_s))
    else:
        hint = t("live", "hint_other", state, flows_generated)

    return Section(key="live", label="Live Execution", hint=hint,
                   content_lines=content, actions=[], field_map=[])


LIVE_SECTION: Section = build_live_section()
