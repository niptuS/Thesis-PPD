"""
Entrada: None
Salida: Section
Descripción: Builds the Benign Profiles section showing IoT device profiles
             with auto-scanned endpoints, plus detail view for selected profile.
"""
from __future__ import annotations
from design.models import Section
from modules.i18n import t

PAGE_SIZE = 10


def _action_icon(action) -> str:
    if "_auth" in action.name:
        return "🔒"
    return "✓"


def build_benign_profiles_section(profiles=None, cursor=0, page=0, detail_cursor=-1):
    profs = profiles if profiles is not None else []
    selected = profs[cursor] if profs and 0 <= cursor < len(profs) else None

    content = [f"─── {t('profiles', 'title')} ──────────────────────────────────", ""]
    if not profs:
        content.append(f"  {t('profiles', 'no_profiles_add')}")
    else:
        content.append(f"  {'':2} {t('profiles', 'col_tag'):<16} {t('profiles', 'col_type'):<10} {t('profiles', 'col_ip'):<16} {t('profiles', 'col_port'):<6} {t('profiles', 'col_actions')}")
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
        content.append(f"  {t('profiles', 'lbl_ip')}: {selected.device_ip}  {t('profiles', 'lbl_port')}: {selected.port}  {t('profiles', 'lbl_auth')}: {selected.auth_user or '—'}")
        content.append("")
        if selected.actions:
            content.append(f"  ── {t('profiles', 'actions_available')} ──")
            for i, a in enumerate(selected.actions):
                marker = "►" if i == detail_cursor else " "
                icon = _action_icon(a)
                content.append(f"  {marker} {icon} {a.name:<20} {a.method:<5} {a.endpoint}")
        else:
            content.append(f"  {t('profiles', 'no_actions_scan')}")

    n = len(profs)
    return Section(
        key="benign_profiles", label=t("menu", "benign_profiles"),
        hint=t("profiles", "hint_default", n),
        content_lines=content, actions=[], field_map=[],
    )


BENIGN_PROFILES_SECTION = build_benign_profiles_section()
