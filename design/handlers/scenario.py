from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from design.Menu import MenuApp


class ScenarioController:

    """
    Entrada: app (MenuApp)
    Salida: None
    Descripción: Initialize the ScenarioController with the parent app.
    """
    def __init__(self, app: "MenuApp") -> None:
        self._app = app

    """
    Entrada: key (int)
    Salida: None
    Descripción: Handle a key press and dispatch the scenario save action on Ctrl+S.
    """
    def handle_key(self, key: int) -> None:
        key_map = {
            19: lambda: self._app._dispatch("scenario", "ctrl_s"),
        }
        action = key_map.get(key)
        if action is not None:
            action()
