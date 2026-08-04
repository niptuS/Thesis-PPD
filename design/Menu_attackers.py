"""
Entrada: None
Salida: Section
Descripción: Attackers panel - manage attacker devices and their SSH connections.
"""
from __future__ import annotations
from design.models import Section
from modules.i18n import t
from modules.comms.attacker_profile import AttackerProfile


def build_attackers_section(profiles: list[AttackerProfile] | None = None,
                            cursor: int = 0, detail_cursor: int = -1) -> Section:
    profs = profiles or []
    selected = profs[cursor] if profs and 0 <= cursor < len(profs) else None

    content = [f"─── {t('attackers', 'title')} ─────────────────────────────────"]
    if not profs:
        content.append(f"  {t('attackers', 'no_attackers_add')}")
    else:
        header = f"  {'':2} {t('attackers', 'col_tag'):<18} {t('attackers', 'col_mode'):<8} {t('attackers', 'col_ip'):<16} {t('attackers', 'col_user'):<10} {t('attackers', 'col_port'):<6}"
        content.append(header)
        content.append("  " + "─" * (len(header) - 2))
        for i, p in enumerate(profs):
            marker = "►" if i == cursor else " "
            tag = (p.tag or p.device_ip)[:17]
            content.append(
                f"  {marker} {tag:<18} {p.mode:<8} {p.device_ip:<16} "
                f"{p.ssh_user:<10} {p.ssh_port}"
            )

    if selected:
        content.append("")
        content.append(f"─── {selected.label} ────────────────────────────────")
        fields = [
            ("mode", t('attackers', 'lbl_connection'), selected.mode),
            ("ssh_user", t('attackers', 'lbl_ssh_user'), selected.ssh_user),
            ("ssh_port", t('attackers', 'lbl_ssh_port'), str(selected.ssh_port)),
            ("ssh_password", t('attackers', 'lbl_ssh_password'),
             "●●●●●●●●" if selected.ssh_password else t('attackers', 'enter_to_set')),
            ("ssh_key", t('attackers', 'lbl_ssh_key'),
             selected.ssh_key or t("attackers", "not_configured")),
        ]
        for i, (attr, label, val) in enumerate(fields):
            marker = "►" if i == detail_cursor else " "
            editable = " " if (attr == "mode" and selected.is_local) else "✎"
            if selected.is_local and attr in ("ssh_user", "ssh_port", "ssh_password", "ssh_key"):
                editable = " "
                val = "—"
            content.append(f"  {marker}{editable} {label:<14}: {val}")

    n = len(profs)
    local = sum(1 for p in profs if p.is_local)
    ssh = n - local
    return Section(
        key="attackers", label=t("menu", "attackers"),
        hint=t("attackers", "attackers_summary", n, local, ssh),
        content_lines=content, actions=[], field_map=[],
    )


ATTACKERS_SECTION = build_attackers_section()
