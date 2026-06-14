from design.models import Section, FieldMeta


def build_scenario_section(config, **kwargs) -> Section:
    lines = [
        "─── Scenario Configuration ───────────────────────",
        "",
        f"  Name              : {config.name}",
        f"  Experiment ID     : {config.experiment_id}",
        f"  Environment       : {config.environment}",
        f"  Start time        : {config.start_time}",
        f"  Planned duration  : {config.planned_duration}",
    ]

    field_map = [
        FieldMeta("name", "Name", True, 2),
        FieldMeta("experiment_id", "Experiment ID", True, 3),
        FieldMeta("environment", "Environment", True, 4),
        FieldMeta("start_time", "Start time", True, 5),
        FieldMeta("planned_duration", "Planned duration", True, 6),
    ]

    return Section(
        key="scenario", label="Scenario Editor",
        hint="↑↓=campo · Enter=editar · Ctrl+S=guardar · Ctrl+O=cargar",
        content_lines=lines, actions=[], field_map=field_map,
    )


SCENARIO_SECTION = build_scenario_section(
    type("_Cfg", (), {
        "name": "", "experiment_id": "NEW", "environment": "",
        "start_time": "00:00:00", "planned_duration": "00:30:00",
        "output": type("_Out", (), {
            "folder": "./data", "capture_enabled": True,
            "export_metadata": True, "export_pcap": True, "export_benign": True,
        })(),
        "attacker": type("_Atk", (), {"mode": "local", "ip": "", "ssh_user": "kali", "ssh_port": 22, "ssh_key": ""})(),
    })()
)
