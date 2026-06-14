"""
Benign Profile Schema — defines available actions per IoT device type.
Each profile maps a device_type to a list of actions the orchestrator
can request via HTTP, MQTT, or CoAP.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict


@dataclass
class ActionParam:
    name: str
    type: str = "str"       # str, int, float, bool
    default: str = ""
    required: bool = False


@dataclass
class ActionDefinition:
    name: str                      # e.g. "turn_on"
    description: str = ""
    protocol: str = "http"             # http, mqtt, coap, ssh
    method: str = "POST"             # HTTP method or MQTT topic prefix
    endpoint: str = ""                 # e.g. "/api/light/on" or MQTT topic
    payload: str = ""                 # template with {param} placeholders
    params: list[ActionParam] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ActionDefinition":
        params = [ActionParam(**p) for p in d.get("params", [])]
        return cls(
            name=d["name"], description=d.get("description", ""),
            protocol=d.get("protocol", "http"), method=d.get("method", "POST"),
            endpoint=d.get("endpoint", ""), payload=d.get("payload", ""),
            params=params,
        )


@dataclass
class BenignProfile:
    device_type: str                              # e.g. "bulb", "plug", "camera"
    display_name: str = ""
    description: str = ""
    actions: list[ActionDefinition] = field(default_factory=list)

    def action_names(self) -> list[str]:
        return [a.name for a in self.actions]

    def get_action(self, name: str) -> ActionDefinition | None:
        return next((a for a in self.actions if a.name == name), None)

    def to_dict(self) -> dict:
        return {
            "device_type": self.device_type,
            "display_name": self.display_name,
            "description": self.description,
            "actions": [a.to_dict() for a in self.actions],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BenignProfile":
        actions = [ActionDefinition.from_dict(a) for a in d.get("actions", [])]
        return cls(
            device_type=d["device_type"],
            display_name=d.get("display_name", ""),
            description=d.get("description", ""),
            actions=actions,
        )
