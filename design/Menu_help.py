from design.models import Section
from modules.i18n import t


def build_help_section() -> Section:
    return Section(
        key="help",
        label=t("menu", "help"),
        hint=t("help", "hint"),
        content_lines=[
            f"─── {t('help', 'nav_title')} ───────────────────────────────────",
            "",
            f"  ↑↓       {t('help', 'nav_move')}",
            f"  Enter    {t('help', 'nav_enter')}",
            f"  Esc      {t('help', 'nav_esc')}",
            f"  Tab      {t('help', 'nav_tab')}",
            f"  ?        {t('help', 'nav_help')}",
            f"  q        {t('help', 'nav_q')}",
            "",
            f"─── {t('help', 'shortcuts_title')} ─────────────────────────────",
            "",
            f"  Ctrl+S   {t('help', 'sc_save')}",
            f"  Ctrl+R   {t('help', 'sc_run')}",
            f"  Ctrl+P   {t('help', 'sc_pause')}",
            f"  Ctrl+L   {t('help', 'sc_logs')}",
            f"  Ctrl+X   {t('help', 'sc_abort')}",
            "",
            f"─── {t('help', 'flow_title')} ─────────────────────────────",
            "",
            f"  1. {t('menu', 'scenario')}   2. {t('menu', 'devices')}",
            f"  3. {t('menu', 'attacks')}    4. {t('menu', 'timeline')}",
            f"  5. {t('menu', 'live')}    6. {t('menu', 'artifacts')}",
        ],
        actions=[t("help", "esc_back")],
    )


HELP_SECTION = build_help_section()
