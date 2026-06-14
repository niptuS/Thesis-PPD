from __future__ import annotations
from design.models import Section

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
    header = f"  {'':2} {'St':2} {'Offset':<10} {'Type':<8} {'Action':<16} {'Target':<14} {'Scheduled':<12}"
    lines.append(header)
    lines.append("  " + "─" * (len(header) - 2))
    if not events:
        lines.append("     (sin eventos — A para agregar)")
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
        sched = ev.scheduled_dt[-8:] if ev.scheduled_dt else "—"  # show HH:MM:SS
        lines.append(
            f"  {marker} {icon}  {ev.offset_str():<10} {ev.event_type:<8} "
            f"{action_short:<16} {tgt_short:<14} {sched}"
        )
    if total_pages > 1:
        lines.append("")
        lines.append(f"  Pág {page + 1}/{total_pages}    ◄ PgUp  PgDn ►")
    return lines


def _build_selected_detail(ev):
    return [
        f"  ID          : {ev.event_id}",
        f"  Offset      : {ev.offset_str()} ({ev.offset_s}s)",
        f"  Scheduled   : {ev.scheduled_dt or '(sin calcular)'}",
        f"  Event type  : {ev.event_type}",
        f"  Action      : {ev.action}",
        f"  Source      : {ev.source} (auto: host)",
        f"  Target      : {ev.target}",
        f"  Duration    : {ev.duration_s}s",
        f"  Status      : {ev.status}",
        f"  Notes       : {ev.notes or '—'}",
    ]


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
    attacks = sum(1 for e in event_list if e.event_type == "attack")
    pending = sum(1 for e in event_list if e.status == "queued")
    done = sum(1 for e in event_list if e.status == "completed")
    return Section(
        key="timeline", label="Timeline",
        hint=(
            "A=agregar · E=editar · X=eliminar · M=mover · "
            f"{total} eventos ({pending} pendientes, {done} completados)"
        ),
        content_lines=content, actions=[], field_map=[],
    )


TIMELINE_SECTION: Section = build_timeline_section()
