"""
Benign Profile Schema — defines what each IoT device can DO.
Each device type has a profile with available actions.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional
import uuid


@dataclass
class DeviceAction:  # pylint: disable=no-member
    """A single action a device can perform."""
    action_id: str = ""
    name: str = ""          # e.g. "turn_on", "set_brightness"
    description: str = ""          # human-readable description
    protocol: str = "http"      # http | mqtt | coap | ssh
    method: str = "POST"      # HTTP method or mqtt topic action
    endpoint: str = ""          # e.g. "/api/light/on" or "device/command"
    payload: str = ""          # JSON payload template, e.g. '{"state": "on"}'
    headers: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.action_id:
            self.action_id = uuid.uuid4().hex[:8]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceAction":
        return cls(**{
            k: v for k, v in d.items()
            if k in cls.__dataclass_fields__
        })


@dataclass
class BenignProfile:
    """Profile of a device: what it is and what it can do."""
    profile_id: str = ""
    device_type: str = ""     # bulb, plug, camera, sensor, speaker
    device_ip: str = ""     # linked device IP
    device_tag: str = ""     # user-assigned tag for identification
    protocol: str = "http"  # default protocol
    port: int = 80
    auth_user: str = ""
    auth_pass: str = ""
    actions: list[DeviceAction] = field(default_factory=list)
    notes: str = ""

    def __post_init__(self):
        if not self.profile_id:
            self.profile_id = uuid.uuid4().hex[:8]

    def action_names(self) -> list[str]:
        return [a.name for a in self.actions]

    def get_action(self, name: str) -> Optional[DeviceAction]:
        for a in self.actions:
            if a.name == name:
                return a
        return None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["actions"] = [a.to_dict() for a in self.actions]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "BenignProfile":
        actions = [DeviceAction.from_dict(a) for a in d.get("actions", [])]
        return cls(
            profile_id=d.get("profile_id", ""),
            device_type=d.get("device_type", ""),
            device_ip=d.get("device_ip", ""),
            device_tag=d.get("device_tag", ""),
            protocol=d.get("protocol", "http"),
            port=d.get("port", 80),
            auth_user=d.get("auth_user", ""),
            auth_pass=d.get("auth_pass", ""),
            actions=actions,
            notes=d.get("notes", ""),
        )
