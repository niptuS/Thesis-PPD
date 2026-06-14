from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp


class ScenarioController:

    def __init__(self, app: "MenuApp") -> None:
        self._app = app

    def handle_key(self, key: int) -> None:
        key_map = {
            19: lambda: self._app._dispatch("scenario", "ctrl_s"),  # Ctrl+S
        }
        action = key_map.get(key)
        if action is not None:
            action()
