from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal

@dataclass
class OutputConfig:
    folder:          str
    capture_enabled: bool = True
    export_pcap:     bool = True
    export_metadata: bool = True
    metadata_format: Literal["json"] = "json"

@dataclass
class DeviceConfig:
    id:        str
    role:      Literal["target", "benign", "attacker"]
    ip:        str
    mac:       str
    protocols: list[str]         = field(default_factory=list)
    tags:      list[str]         = field(default_factory=list)

@dataclass
class BenignProfile:
    id:           str
    device_class: str
    protocols:    list[str]
    rate:         str
    duration:     str
    start_offset: str            = "00:00:00"
    enabled:      bool           = True

@dataclass
class AttackModule:
    id:          str
    name:        str
    source_node: str
    target_node: str
    duration:    str
    intensity:   Literal["low", "medium", "high"]
    label:       str
    mitre_ref:   str

@dataclass
class TimelineEvent:
    timestamp:   str
    event_type:  Literal["benign", "attack"]
    action_id:   str
    source_node: str
    target_node: str
    notes:       str             = ""

@dataclass
class ScenarioConfig:
    name:            str
    experiment_id:   str
    environment:     str
    start_time:      str
    planned_duration: str
    schema_version:  str         = "1.0"
    output:          OutputConfig         = field(default_factory=lambda: OutputConfig(folder="./data"))
    devices:         list[DeviceConfig]   = field(default_factory=list)
    benign_profiles: list[BenignProfile]  = field(default_factory=list)
    attack_modules:  list[AttackModule]   = field(default_factory=list)
    timeline:        list[TimelineEvent]  = field(default_factory=list)