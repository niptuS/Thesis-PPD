from __future__ import annotations
import json
from pathlib import Path

from modules.scenario_editor.config_schema import (
    ScenarioConfig, OutputConfig, DeviceConfig,
    BenignProfile, AttackModule, TimelineEvent,
)
from modules.scenario_editor.config_validator import validate_scenario


class ConfigLoadError(Exception):
    pass


"""
Entrada: raw (dict)
Salida: OutputConfig
Descripción: Parses an output configuration dictionary.
"""
def _parse_output(raw: dict) -> OutputConfig:
    return OutputConfig(
        folder=raw["folder"],
        capture_enabled=raw.get("capture_enabled", True),
        export_pcap=raw.get("export_pcap", True),
        export_metadata=raw.get("export_metadata", True),
        metadata_format=raw.get("metadata_format", "json"),
    )


"""
Entrada: raw (dict)
Salida: DeviceConfig
Descripción: Parses a device configuration dictionary.
"""
def _parse_device(raw: dict) -> DeviceConfig:
    return DeviceConfig(
        id=raw["id"],
        role=raw["role"],
        ip=raw["ip"],
        mac=raw["mac"],
        protocols=raw.get("protocols", []),
        tags=raw.get("tags", []),
    )


"""
Entrada: raw (dict)
Salida: BenignProfile
Descripción: Parses a benign profile configuration dictionary.
"""
def _parse_benign(raw: dict) -> BenignProfile:
    return BenignProfile(
        id=raw["id"],
        device_class=raw["device_class"],
        protocols=raw.get("protocols", []),
        rate=raw["rate"],
        duration=raw["duration"],
        start_offset=raw.get("start_offset", "00:00:00"),
        enabled=raw.get("enabled", True),
    )


"""
Entrada: raw (dict)
Salida: AttackModule
Descripción: Parses an attack module configuration dictionary.
"""
def _parse_attack(raw: dict) -> AttackModule:
    return AttackModule(
        id=raw["id"],
        name=raw["name"],
        source_node=raw["source_node"],
        target_node=raw["target_node"],
        duration=raw["duration"],
        intensity=raw["intensity"],
        label=raw["label"],
        mitre_ref=raw["mitre_re"],
    )


"""
Entrada: raw (dict)
Salida: TimelineEvent
Descripción: Parses a timeline event dictionary.
"""
def _parse_event(raw: dict) -> TimelineEvent:
    return TimelineEvent(
        timestamp=raw["timestamp"],
        event_type=raw["event_type"],
        action_id=raw["action_id"],
        source_node=raw["source_node"],
        target_node=raw["target_node"],
        notes=raw.get("notes", ""),
    )


"""
Entrada: path (str | Path)
Salida: ScenarioConfig
Descripción: Loads and validates a scenario JSON file into a ScenarioConfig.
"""
def load_scenario(path: str | Path) -> ScenarioConfig:
    scenario_path = Path(path)
    if not scenario_path.exists():
        raise ConfigLoadError(f"Scenario file not found: {scenario_path}")
    if scenario_path.suffix.lower() != ".json":
        raise ConfigLoadError(f"Expected .json file, got: {scenario_path.suffix}")

    try:
        raw = json.loads(scenario_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigLoadError(f"Invalid JSON in {scenario_path}: {exc}") from exc

    try:
        config = ScenarioConfig(
            name=raw["name"],
            experiment_id=raw["experiment_id"],
            environment=raw["environment"],
            start_time=raw["start_time"],
            planned_duration=raw["planned_duration"],
            schema_version=raw.get("schema_version", "1.0"),
            output=_parse_output(raw.get("output", {"folder": "./data"})),
            devices=[_parse_device(d) for d in raw.get("devices", [])],
            attack_modules=[_parse_attack(a) for a in raw.get("attack_modules", [])],
            timeline=[_parse_event(e) for e in raw.get("timeline", [])],
        )
    except KeyError as exc:
        raise ConfigLoadError(f"Missing required field: {exc}") from exc

    errors = validate_scenario(config)
    if errors:
        raise ConfigLoadError("Validation failed:\n" + "\n".join(f"  - {e}" for e in errors))

    return config
