from design.Menu_types import Section, FieldMeta


def build_scenario_section(config) -> Section:
    capture  = "[x]" if config.output.capture_enabled else "[ ]"
    pcap     = "[x]" if config.output.export_pcap     else "[ ]"
    metadata = "[x]" if config.output.export_metadata else "[ ]"

    lines: list[str] = [
        "─── Scenario Configuration ───────────────────────",
        "",
        f"  Name              : {config.name}",
        f"  Experiment ID     : {config.experiment_id}",
        f"  Environment       : {config.environment}",
        f"  Start time        : {config.start_time}",
        f"  Planned duration  : {config.planned_duration}",
        f"  Output folder     : {config.output.folder}",
        "",
        "─── Output Settings ──────────────────────────────",
        "",
        f"  Capture enabled   : {capture}",
        f"  Metadata export   : {metadata}",
        f"  PCAP export       : {pcap}",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [→] → campos   [Ctrl+S] Guardar   [Ctrl+O] Cargar   [Esc] Home",
    ]

    field_map: list[FieldMeta] = [
        FieldMeta("name",                   "Name",             True,  2),
        FieldMeta("experiment_id",          "Experiment ID",    True,  3),
        FieldMeta("environment",            "Environment",      True,  4),
        FieldMeta("start_time",             "Start time",       True,  5),
        FieldMeta("planned_duration",       "Planned duration", True,  6),
        FieldMeta("output.folder",          "Output folder",    True,  7),
        FieldMeta("output.capture_enabled", "Capture enabled",  True,  11),
        FieldMeta("output.export_metadata", "Export metadata",  True,  12),
        FieldMeta("output.export_pcap",     "Export PCAP",      True,  13),
    ]

    return Section(
        key="scenario",
        label="Scenario Editor",
        hint="← sidebar · ↑↓ campo · Enter editar inline · Ctrl+S guardar · Esc volver",
        content_lines=lines,
        actions=[],
        field_map=field_map,
    )

SCENARIO_SECTION = build_scenario_section(
    type("_Cfg", (), {
        "name": "", "experiment_id": "NEW", "environment": "",
        "start_time": "00:00:00", "planned_duration": "00:00:00",
        "output": type("_Out", (), {
            "folder": "", "capture_enabled": True,
            "export_metadata": True, "export_pcap": True,
        })(),
    })()
)