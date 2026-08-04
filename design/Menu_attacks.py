"""
Entrada: None
Salida: Section
Descripción: Builds the Attack Library section showing native attacks grouped
             by category plus any loaded plugin attacks, with detail view.
"""
from __future__ import annotations
from design.models import Section
from modules.i18n import t
from modules.attacks import ATTACK_LIBRARY, get_plugin_attacks, get_plugin_statuses
from modules.attacks.base import AttackDef

PAGE_SIZE = 14


"""
Entrada: cursor (int), tool_status (dict|None), scan_mode (str)
Salida: Section
Descripción: Builds the attacks section with localized labels and hints.
"""
def build_attacks_section(
    cursor: int = 0,
    tool_status: dict[str, bool] | None = None,
    scan_mode: str = "—",
) -> Section:
    status = tool_status or {}

    native  = ATTACK_LIBRARY
    try:
        plugins = get_plugin_attacks() or [] if cursor is not None else []
    except Exception:
        plugins = []

    all_attacks = native + plugins
    total = len(all_attacks)

    content: list[str] = [
        f"─── {t('attacks', 'natives_plugins', len(native), len(plugins))} ───",
        f"  {t('common', 'verification')}: {scan_mode}",
        "",
    ]

    flat_list: list[AttackDef] = []

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

    if plugins:
        content.append(f"  ══ {t('attacks', 'plugins')} ══════════════════════════════════")

        plugin_cats: dict[str, list[AttackDef]] = {}
        for a in plugins:
            clean_cat = a.category.removeprefix("plugin:")
            plugin_cats.setdefault(clean_cat, []).append(a)

        for cat in sorted(plugin_cats.keys()):
            content.append(f"  ── {cat.upper().replace('_', ' ')} (plugin) ──")
            for a in plugin_cats[cat]:
                idx = len(flat_list)
                marker = "►" if idx == cursor else " "
                st = "✓"
                content.append(
                    f"  {marker} [P✓] {a.name:<18} {a.tool:<12} {a.description[:30]}"
                )
                flat_list.append(a)
            content.append("")

    if flat_list and 0 <= cursor < len(flat_list):
        sel = flat_list[cursor]
        is_plugin = sel.category.startswith("plugin:")
        avail = status.get(sel.tool)
        if is_plugin:
            avail_str = f"{t('attacks', 'plugin_loaded')} ✓"
        else:
            avail_str = (f"{t('attacks', 'available')} ✓" if avail is True
                         else f"{t('attacks', 'not_found')} ✗" if avail is False
                         else t("attacks", "not_verified"))

        content.append(f"─── {sel.name} {'[PLUGIN]' if is_plugin else ''} {'─' * 30}")
        content.append(f"  {t('attacks', 'tool'):<12}: {sel.tool}  ({avail_str})")
        content.append(f"  {t('attacks', 'mitre'):<12}: {sel.mitre_ref}")
        clean_cat = sel.category.removeprefix("plugin:")
        content.append(f"  {t('attacks', 'category'):<12}: {clean_cat}{'  - ' + t('attacks', 'external_plugin') if is_plugin else ''}")
        if sel.continuous:
            dur_min = sel.recommended_dur_s // 60
            dur_sec = sel.recommended_dur_s % 60
            dur_str = f"{dur_min}m {dur_sec}s" if dur_min else f"{dur_sec}s"
            content.append(f"  {t('attacks', 'duration'):<12}: {dur_str} {t('attacks', 'continuous')}")
        else:
            content.append(f"  {t('attacks', 'duration'):<12}: {t('attacks', 'automatic')}")
        content.append(f"  {t('attacks', 'root'):<12}: {t('attacks', 'yes') if sel.requires_root else t('attacks', 'no')}")
        if is_plugin and sel.local_fallback:
            content.append(f"  {t('attacks', 'function'):<12}: {sel.local_fallback}")
        else:
            content.append(f"  {t('attacks', 'command'):<12}: {sel.command}")

    n_ok    = sum(1 for v in status.values() if v is True)
    n_fail  = sum(1 for v in status.values() if v is False)
    tools_total = len(set(a.tool for a in native))

    hint_parts = [
        t('attacks', 'hint_default', n_ok, tools_total)
    ]
    if n_fail:
        hint_parts.append(f" - {n_fail} {t('attacks', 'hint_not_found')}")
    if plugins:
        hint_parts.append(f" - {len(plugins)} {t('attacks', 'hint_plugins')}")

    return Section(
        key="attacks", label=t("menu", "attacks"),
        hint="".join(hint_parts),
        content_lines=content, actions=[], field_map=[],
    )


ATTACKS_SECTION = build_attacks_section()
