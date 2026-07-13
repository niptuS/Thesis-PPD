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
    type: str = "str"
    default: str = ""
    required: bool = False


@dataclass
class ActionDefinition:
    name: str
    description: str = ""
    protocol: str = "http"
    method: str = "POST"
    endpoint: str = ""
    payload: str = ""
    params: list[ActionParam] = field(default_factory=list)

    """
    Entrada: None
    Salida: dict
    Descripción: Converts the action definition to a dictionary.
    """
    def to_dict(self) -> dict:
        return asdict(self)

    """
    Entrada: d (dict)
    Salida: ActionDefinition
    Descripción: Builds an ActionDefinition from a dictionary.
    """
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
    device_type: str
    display_name: str = ""
    description: str = ""
    actions: list[ActionDefinition] = field(default_factory=list)

    """
    Entrada: None
    Salida: list[str]
    Descripción: Returns the list of action names defined in this profile.
    """
    def action_names(self) -> list[str]:
        return [a.name for a in self.actions]

    """
    Entrada: name (str)
    Salida: ActionDefinition | None
    Descripción: Returns the action with the given name, or None if not found.
    """
    def get_action(self, name: str) -> ActionDefinition | None:
        return next((a for a in self.actions if a.name == name), None)

    """
    Entrada: None
    Salida: dict
    Descripción: Converts the profile to a dictionary.
    """
    def to_dict(self) -> dict:
        return {
            "device_type": self.device_type,
            "display_name": self.display_name,
            "description": self.description,
            "actions": [a.to_dict() for a in self.actions],
        }

    """
    Entrada: d (dict)
    Salida: BenignProfile
    Descripción: Builds a BenignProfile from a dictionary.
    """
    @classmethod
    def from_dict(cls, d: dict) -> "BenignProfile":
        actions = [ActionDefinition.from_dict(a) for a in d.get("actions", [])]
        return cls(
            device_type=d["device_type"],
            display_name=d.get("display_name", ""),
            description=d.get("description", ""),
            actions=actions,
        )
