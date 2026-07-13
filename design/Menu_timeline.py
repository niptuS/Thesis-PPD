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


"""
Entrada: events (list), cursor (int), page (int)
Salida: list[str]
Descripción: Builds the paginated event table lines.
"""
def _build_event_table(events, cursor=0, page=0):
    lines = []
    header = f"  {'':2} {'St':2} {'Offset':<10} {'Type':<8} {'Action':<16} {'Target':<14} {'Scheduled':<12}"
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


"""
Entrada: ev (TimelineEvent)
Salida: list[str]
Descripción: Builds the detail lines for the selected event.
"""
def _build_selected_detail(ev):
    return [
        f"  ID          : {ev.event_id}",
        f"  Offset      : {ev.offset_str()} ({ev.offset_s}s)",
        f"  Scheduled   : {ev.scheduled_dt or t('timeline', 'not_calculated')}",
        f"  Event type  : {ev.event_type}",
        f"  Action      : {ev.action}",
        f"  Source      : {ev.source} (auto: host)",
        f"  Target      : {ev.target}",
        f"  Duration    : {ev.duration_s}s",
        f"  Status      : {ev.status}",
        f"  Notes       : {ev.notes or '—'}",
    ]


"""
Entrada: events (list|None), cursor (int), page (int)
Salida: Section
Descripción: Builds the full timeline section with table and detail.
"""
def build_timeline_section(events=None, cursor=0, page=0):
    event_list = events if events is not None else []
    selected = event_list[cursor] if event_list and 0 <= cursor < len(event_list) else None
    content = ["─── Scheduled Events ─────────────────────────────────"]
    content.extend(_build_event_table(event_list, cursor, page))
    if selected is not None:
        content.append("")
        content.append(f"─── {selected.label} ────────────────────────────")
        content.extend(_build_selected_detail(selected))
    total = len(event_list)
    pending = sum(1 for e in event_list if e.status == "queued")
    done = sum(1 for e in event_list if e.status == "completed")
    return Section(
        key="timeline", label="Timeline",
        hint=t("timeline", "events_summary", total, pending, done),
        content_lines=content, actions=[], field_map=[],
    )


TIMELINE_SECTION: Section = build_timeline_section()
