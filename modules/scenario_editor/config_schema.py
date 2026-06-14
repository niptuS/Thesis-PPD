from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class OutputConfig:
    folder: str = "./data"
    capture_enabled: bool = True
    export_pcap: bool = True
    export_metadata: bool = True
    export_benign: bool = True
    metadata_format: Literal["json"] = "json"


@dataclass
class AttackerConfig:
    """Attack execution config — local or via SSH to Kali Linux."""
    mode: str = "local"   # "local" = this machine, "ssh" = remote Kali
    ip: str = ""        # Kali IP (only needed for ssh mode)
    ssh_user: str = "kali"
    ssh_port: int = 22
    ssh_key: str = ""
    # password stored as runtime attribute only (not a dataclass field)


@dataclass
class DeviceConfig:
    id: str
    role: Literal["target", "benign", "attacker"]
    ip: str
    mac: str
    protocols: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class BenignProfile:
    id: str = ""
    device_class: str = ""
    protocols: list[str] = field(default_factory=list)
    rate: str = ""
    duration: str = ""
    start_offset: str = "00:00:00"
    enabled: bool = True


@dataclass
class AttackModule:
    id: str
    name: str
    source_node: str
    target_node: str
    duration: str
    intensity: Literal["low", "medium", "high"] = "medium"
    label: str = ""
    mitre_ref: str = ""


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: Literal["benign", "attack"]
    action_id: str
    source_node: str
    target_node: str
    notes: str = ""


@dataclass
class ScenarioConfig:
    name: str = ""
    experiment_id: str = "EXP"
    environment: str = ""
    start_time: str = "00:00:00"
    planned_duration: str = "00:30:00"
    schema_version: str = "1.0"
    output: OutputConfig = field(default_factory=OutputConfig)
    attacker: AttackerConfig = field(default_factory=AttackerConfig)
    devices: list[DeviceConfig] = field(default_factory=list)
    attack_modules: list[AttackModule] = field(default_factory=list)
    timeline: list = field(default_factory=list)
