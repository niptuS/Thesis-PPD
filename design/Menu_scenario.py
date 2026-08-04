from design.models import Section, FieldMeta
from modules.i18n import t


def build_scenario_section(config, **kwargs) -> Section:
    lines = [
        f"─── {t('scenario', 'title')} ───────────────────────",
        "",
        f"  {t('scenario', 'name'):<20}: {config.name}",
        f"  {t('scenario', 'experiment_id'):<20}: {config.experiment_id}",
        f"  {t('scenario', 'environment'):<20}: {config.environment}",
        f"  {t('scenario', 'start_time'):<20}: {config.start_time}",
        f"  {t('scenario', 'duration'):<20}: {config.planned_duration}",
        f"  {t('scenario', 'chunk_size'):<20}: {getattr(config, 'pcap_max_size_kb', 512000)} KB ({getattr(config, 'pcap_max_size_kb', 512000) // 1024} MB)",
    ]

    field_map = [
        FieldMeta("name", t('scenario', 'name'), True, 2),
        FieldMeta("experiment_id", t('scenario', 'experiment_id'), True, 3),
        FieldMeta("environment", t('scenario', 'environment'), True, 4),
        FieldMeta("start_time", t('scenario', 'start_time'), True, 5),
        FieldMeta("planned_duration", t('scenario', 'duration_format'), True, 6),
        FieldMeta("pcap_max_size_kb", t('scenario', 'chunk_size_format'), True, 7),
    ]

    return Section(
        key="scenario", label=t("menu", "scenario"),
        hint=t("scenario", "hint_edit"),
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
