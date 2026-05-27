from __future__ import annotations
import re
from modules.scenario_editor.config_schema import ScenarioConfig

_TIME_RE     = re.compile(r"^\d{2}:\d{2}:\d{2}$")
_DURATION_RE = re.compile(r"^\d{2}:\d{2}:\d{2}$")
_IP_RE       = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_MAC_RE      = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_EXP_ID_RE   = re.compile(r"^EXP-\d{4}-\d{2}-\d{3,}$")

_VALID_ROLES      = {"target", "benign", "attacker"}
_VALID_INTENSITIES = {"low", "medium", "high"}
_VALID_EVENT_TYPES = {"benign", "attack"}

def validate_scenario(config: ScenarioConfig) -> list[str]:
    errors: list[str] = []

    if not config.name.strip():
        errors.append("scenario.name must not be empty")
    if not _EXP_ID_RE.match(config.experiment_id):
        errors.append(f"experiment_id '{config.experiment_id}' does not match EXP-YYYY-MM-NNN")
    if not _TIME_RE.match(config.start_time):
        errors.append(f"start_time '{config.start_time}' must be HH:MM:SS")
    if not _DURATION_RE.match(config.planned_duration):
        errors.append(f"planned_duration '{config.planned_duration}' must be HH:MM:SS")
    if not config.output.folder.strip():
        errors.append("output.folder must not be empty")

    device_ids: set[str] = set()
    for dev in config.devices:
        if dev.id in device_ids:
            errors.append(f"duplicate device id: '{dev.id}'")
        device_ids.add(dev.id)
        if dev.role not in _VALID_ROLES:
            errors.append(f"device '{dev.id}': invalid role '{dev.role}'")
        if not _IP_RE.match(dev.ip):
            errors.append(f"device '{dev.id}': invalid IP '{dev.ip}'")
        if not _MAC_RE.match(dev.mac):
            errors.append(f"device '{dev.id}': invalid MAC '{dev.mac}'")

    benign_ids: set[str] = set()
    for bp in config.benign_profiles:
        if bp.id in benign_ids:
            errors.append(f"duplicate benign_profile id: '{bp.id}'")
        benign_ids.add(bp.id)
        if not _DURATION_RE.match(bp.duration):
            errors.append(f"benign_profile '{bp.id}': invalid duration '{bp.duration}'")

    attack_ids: set[str] = set()
    for atk in config.attack_modules:
        if atk.id in attack_ids:
            errors.append(f"duplicate attack_module id: '{atk.id}'")
        attack_ids.add(atk.id)
        if atk.intensity not in _VALID_INTENSITIES:
            errors.append(f"attack '{atk.id}': invalid intensity '{atk.intensity}'")
        if atk.source_node not in device_ids:
            errors.append(f"attack '{atk.id}': source_node '{atk.source_node}' not in devices")
        if atk.target_node not in device_ids:
            errors.append(f"attack '{atk.id}': target_node '{atk.target_node}' not in devices")
        if not _DURATION_RE.match(atk.duration):
            errors.append(f"attack '{atk.id}': invalid duration '{atk.duration}'")

    all_action_ids = benign_ids | attack_ids
    for i, evt in enumerate(config.timeline):
        if evt.event_type not in _VALID_EVENT_TYPES:
            errors.append(f"timeline[{i}]: invalid event_type '{evt.event_type}'")
        if not _TIME_RE.match(evt.timestamp):
            errors.append(f"timeline[{i}]: invalid timestamp '{evt.timestamp}'")
        if evt.action_id not in all_action_ids:
            errors.append(f"timeline[{i}]: action_id '{evt.action_id}' not defined")
        if evt.source_node not in device_ids:
            errors.append(f"timeline[{i}]: source_node '{evt.source_node}' not in devices")
        if evt.target_node not in device_ids:
            errors.append(f"timeline[{i}]: target_node '{evt.target_node}' not in devices")

    return errors