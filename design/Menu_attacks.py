from __future__ import annotations
from design.models import Section
from modules.attacks import ATTACK_LIBRARY, get_plugin_attacks, get_plugin_statuses
from modules.attacks.base import AttackDef

PAGE_SIZE = 14


def build_attacks_section(
    cursor: int = 0,
    tool_status: dict[str, bool] | None = None,
    scan_mode: str = "—",
) -> Section:
    status = tool_status or {}

    # ── Separar nativos de plugins ──────────────────────────────
    native  = ATTACK_LIBRARY
    plugins = get_plugin_attacks() or []

    all_attacks = native + plugins
    total = len(all_attacks)

    content: list[str] = [
        f"─── Attack Library ({len(native)} nativos · {len(plugins)} plugins) ───",
        f"  Verificación: {scan_mode}",
        "",
    ]

    flat_list: list[AttackDef] = []

    # ── Bloque nativos ──────────────────────────────────────────
    categories: dict[str, list[AttackDef]] = {}
    for a in native:
        categories.setdefault(a.category, []).append(a)

    for cat in sorted(categories.keys()):
        content.append(f"  ── {cat.upper().replace('_', ' ')} ──")
        for a in categories[cat]:
            idx = len(flat_list)
            marker = "►" if idx == cursor else " "
            available = status.get(a.tool)
            st = "✓" if available is True else "✗" if available is False else "?"
            content.append(
                f"  {marker} [{st}] {a.name:<18} {a.tool:<12} {a.description[:30]}"
            )
            flat_list.append(a)
        content.append("")

    # ── Separador visual de plugins ─────────────────────────────
    if plugins:
        content.append("  ══ PLUGINS ══════════════════════════════════")

        plugin_cats: dict[str, list[AttackDef]] = {}
        for a in plugins:
            # quitar el prefijo "plugin:" para mostrar
            clean_cat = a.category.removeprefix("plugin:")
            plugin_cats.setdefault(clean_cat, []).append(a)

        for cat in sorted(plugin_cats.keys()):
            content.append(f"  ── {cat.upper().replace('_', ' ')} (plugin) ──")
            for a in plugin_cats[cat]:
                idx = len(flat_list)
                marker = "►" if idx == cursor else " "
                # para plugins: tool puede ser "python/scapy" — siempre disponible si cargó
                st = "✓"
                content.append(
                    f"  {marker} [P✓] {a.name:<18} {a.tool:<12} {a.description[:30]}"
                )
                flat_list.append(a)
            content.append("")

    # ── Panel de detalle del item seleccionado ──────────────────
    if flat_list and 0 <= cursor < len(flat_list):
        sel = flat_list[cursor]
        is_plugin = sel.category.startswith("plugin:")
        avail = status.get(sel.tool)
        if is_plugin:
            avail_str = "Plugin cargado ✓"
        else:
            avail_str = "Disponible ✓" if avail is True else "No encontrado ✗" if avail is False else "Sin verificar"

        content.append(f"─── {sel.name} {'[PLUGIN]' if is_plugin else ''} {'─' * 30}")
        content.append(f"  Tool        : {sel.tool}  ({avail_str})")
        content.append(f"  MITRE       : {sel.mitre_ref}")
        clean_cat = sel.category.removeprefix("plugin:")
        content.append(f"  Category    : {clean_cat}{'  · Plugin externo' if is_plugin else ''}")
        dur_min = sel.recommended_dur_s // 60
        dur_sec = sel.recommended_dur_s % 60
        dur_str = f"{dur_min}m {dur_sec}s" if dur_min else f"{dur_sec}s"
        content.append(f"  Duración    : {dur_str} recomendado")
        content.append(f"  Root        : {'Sí' if sel.requires_root else 'No'}")
        if is_plugin and sel.local_fallback:
            content.append(f"  Función     : {sel.local_fallback}")
        else:
            content.append(f"  Comando     : {sel.command}")

    n_ok    = sum(1 for v in status.values() if v is True)
    n_fail  = sum(1 for v in status.values() if v is False)
    tools_total = len(set(a.tool for a in native))

    return Section(
        key="attacks", label="Attack Library",
        hint=(
            "V=verificar · P=ver plugins · ↑↓=navegar · "
            f"Tools: {n_ok}/{tools_total} disponibles"
            + (f" · {n_fail} no encontradas" if n_fail else "")
            + (f" · {len(plugins)} plugin(s)" if plugins else "")
        ),
        content_lines=content, actions=[], field_map=[],
    )


ATTACKS_SECTION = build_attacks_section()
