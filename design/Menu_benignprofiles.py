"""Benign Profiles — manage IoT device profiles with auto-scanned endpoints."""
from __future__ import annotations
from design.models import Section

PAGE_SIZE = 10


def _action_icon(action) -> str:
    if "_auth" in action.name:
        return "🔒"
    return "✓"


def build_benign_profiles_section(profiles=None, cursor=0, page=0, detail_cursor=-1):
    profs = profiles if profiles is not None else []
    selected = profs[cursor] if profs and 0 <= cursor < len(profs) else None

    content = ["─── Benign Profiles ──────────────────────────────────", ""]
    if not profs:
        content.append("  (sin perfiles — A para agregar)")
    else:
        content.append(f"  {'':2} {'Tag':<16} {'Type':<10} {'IP':<16} {'Port':<6} {'Actions'}")
        content.append("  " + "─" * 55)
        for i, p in enumerate(profs):
            marker = "►" if i == cursor else " "
            n_ok = sum(1 for a in p.actions if "_auth" not in a.name)
            n_auth = sum(1 for a in p.actions if "_auth" in a.name)
            status = f"{n_ok}✓"
            if n_auth:
                status += f" {n_auth}🔒"
            content.append(
                f"  {marker} {(p.device_tag or p.profile_id)[:15]:<16} {p.device_type:<10} "
                f"{p.device_ip:<16} {p.port:<6} {status}"
            )

    if selected:
        content.append("")
        content.append(f"─── {selected.device_tag or selected.device_type} ────────────────")
        content.append(f"  IP: {selected.device_ip}  Port: {selected.port}  Auth: {selected.auth_user or '—'}")
        content.append("")
        if selected.actions:
            content.append("  ── Acciones (solo las disponibles aparecen en Timeline) ──")
            for i, a in enumerate(selected.actions):
                marker = "►" if i == detail_cursor else " "
                icon = _action_icon(a)
                content.append(f"  {marker} {icon} {a.name:<20} {a.method:<5} {a.endpoint}")
        else:
            content.append("  (sin acciones — S para escanear endpoints)")

    n = len(profs)
    return Section(
        key="benign_profiles", label="Benign Profiles",
        hint=f"A=agregar · S=escanear endpoints · E=editar · R=remover · {n} perfiles",
        content_lines=content, actions=[], field_map=[],
    )


BENIGN_PROFILES_SECTION = build_benign_profiles_section()
