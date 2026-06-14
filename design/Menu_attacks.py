"""
Attack Library section — shows all available attacks grouped by category,
with tool availability status (✓ available / ✗ not found).
"""
from __future__ import annotations
from design.models import Section
from modules.attacks import ATTACK_LIBRARY
from modules.attacks.base import AttackDef

PAGE_SIZE = 14


def build_attacks_section(
    cursor: int = 0,
    tool_status: dict[str, bool] | None = None,
    scan_mode: str = "—",
) -> Section:
    attacks = ATTACK_LIBRARY
    status = tool_status or {}

    # group by category
    categories: dict[str, list[AttackDef]] = {}
    for a in attacks:
        categories.setdefault(a.category, []).append(a)

    content: list[str] = [
        f"─── Attack Library ({len(attacks)} ataques) ─────────────────────",
        f"  Verificación: {scan_mode}",
        "",
    ]

    flat_list: list[AttackDef] = []
    for cat in sorted(categories.keys()):
        cat_label = cat.upper().replace("_", " ")
        content.append(f"  ── {cat_label} ──")
        for a in categories[cat]:
            idx = len(flat_list)
            marker = "►" if idx == cursor else " "
            available = status.get(a.tool)
            if available is True:
                st = "✓"
            elif available is False:
                st = "✗"
            else:
                st = "?"
            content.append(
                f"  {marker} [{st}] {a.name:<18} {a.tool:<12} {a.description[:30]}"
            )
            flat_list.append(a)
        content.append("")

    # selected detail
    if flat_list and 0 <= cursor < len(flat_list):
        sel = flat_list[cursor]
        avail = status.get(sel.tool)
        avail_str = "Disponible ✓" if avail is True else "No encontrado ✗" if avail is False else "Sin verificar"
        content.append(f"─── {sel.name} ─────────────────────────────────")
        content.append(f"  Tool        : {sel.tool}  ({avail_str})")
        content.append(f"  MITRE       : {sel.mitre_ref}")
        content.append(f"  Category    : {sel.category}")
        dur_min = sel.recommended_dur_s // 60
        dur_sec = sel.recommended_dur_s % 60
        dur_str = f"{dur_min}m {dur_sec}s" if dur_min else f"{dur_sec}s"
        content.append(f"  Duración    : {dur_str} recomendado")
        content.append(f"  Root        : {'Sí' if sel.requires_root else 'No'}")
        content.append(f"  Comando     : {sel.command}")

    n_ok = sum(1 for v in status.values() if v is True)
    n_fail = sum(1 for v in status.values() if v is False)
    tools_total = len(set(a.tool for a in attacks))

    return Section(
        key="attacks", label="Attack Library",
        hint=(
            "V=verificar herramientas · ↑↓=navegar · "
            f"Tools: {n_ok}/{tools_total} disponibles"
            + (f" · {n_fail} no encontradas" if n_fail else "")
        ),
        content_lines=content, actions=[], field_map=[],
    )


ATTACKS_SECTION = build_attacks_section()
