"""
Entrada: None
Salida: Section
Descripción: Builds the Timeline section showing scheduled events in a table
             with pagination, plus a detail view for the selected event.
"""
from __future__ import annotations
from design.models import Section
from modules.i18n import t

PAGE_SIZE = 12
EVENT_TYPES = ["benign", "attack"]

_STATUS_ICON = {
    "queued": "○",
    "running": "▶",
    "completed": "✓",
    "skipped": "—",
    "expired": "✗",
}


def _build_event_table(events, cursor=0, page=0):
    lines = []
    header = f"  {'':2} {t('timeline', 'col_st'):2} {t('timeline', 'col_offset'):<10} {t('timeline', 'col_type'):<8} {t('timeline', 'col_action'):<16} {t('timeline', 'col_target'):<14} {t('timeline', 'col_scheduled'):<12}"
    lines.append(header)
    lines.append("  " + "─" * (len(header) - 2))
    if not events:
        lines.append(f"     {t('timeline', 'no_events_add')}")
        return lines
    total = len(events)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, total_pages - 1)
    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, total)
    for i, ev in enumerate(events[start:end]):
        abs_idx = start + i
        marker = "►" if abs_idx == cursor else " "
        icon = _STATUS_ICON.get(ev.status, "?")
        action_short = (ev.action or ev.label)[:15]
        tgt_short = ev.target[:13]
        sched = ev.scheduled_dt[-8:] if ev.scheduled_dt else "—"
        lines.append(
            f"  {marker} {icon}  {ev.offset_str():<10} {ev.event_type:<8} "
            f"{action_short:<16} {tgt_short:<14} {sched}"
        )
    if total_pages > 1:
        lines.append("")
        lines.append(f"  {t('common', 'page')} {page + 1}/{total_pages}    ◄ PgUp  PgDn ►")
    return lines


def _build_selected_detail(ev):
    return [
        f"  {t('timeline', 'lbl_id'):<13}: {ev.event_id}",
        f"  {t('timeline', 'lbl_offset'):<13}: {ev.offset_str()} ({ev.offset_s}s)",
        f"  {t('timeline', 'lbl_scheduled'):<13}: {ev.scheduled_dt or t('timeline', 'not_calculated')}",
        f"  {t('timeline', 'event_type'):<13}: {ev.event_type}",
        f"  {t('timeline', 'lbl_action'):<13}: {ev.action}",
        f"  {t('timeline', 'lbl_source'):<13}: {ev.source} {t('timeline', 'auto_host')}",
        f"  {t('timeline', 'lbl_target'):<13}: {ev.target}",
        f"  {t('timeline', 'lbl_duration'):<13}: {ev.duration_s}s",
        f"  {t('timeline', 'lbl_status'):<13}: {ev.status}",
        f"  {t('timeline', 'lbl_notes'):<13}: {ev.notes or '—'}",
    ]


def build_timeline_section(events=None, cursor=0, page=0):
    event_list = events if events is not None else []
    selected = event_list[cursor] if event_list and 0 <= cursor < len(event_list) else None
    content = [f"─── {t('timeline', 'scheduled_events')} ─────────────────────────────────"]
    content.extend(_build_event_table(event_list, cursor, page))
    if selected is not None:
        content.append("")
        content.append(f"─── {selected.label} ────────────────────────────")
        content.extend(_build_selected_detail(selected))
    total = len(event_list)
    pending = sum(1 for e in event_list if e.status == "queued")
    done = sum(1 for e in event_list if e.status == "completed")
    return Section(
        key="timeline", label=t("menu", "timeline"),
        hint=t("timeline", "events_summary", total, pending, done),
        content_lines=content, actions=[], field_map=[],
    )


TIMELINE_SECTION: Section = build_timeline_section()
