import sys
from pathlib import Path

from design.Menu import MenuApp, SAVES_DIR, OUTPUT_META, OUTPUT_PCAP
from modules.scenario_editor import load_scenario, save_scenario
from modules.scenario_editor.config_loader import ConfigLoadError
from modules.scenario_editor.config_writer import ConfigWriteError


"""
Entrada: app (MenuApp)
Salida: callable
Descripción: Builds and returns an action-handler callable that dispatches
             section actions (load, save, etc.) for the given app.
"""
def _build_handler(app: MenuApp) -> callable:

    """
    Entrada: section_key (str), action (str)
    Salida: None
    Descripción: Inner handler that routes action codes (ctrl_o, ctrl_s, etc.)
                 to the appropriate load/save helpers on the app.
    """
    def action_handler(section_key: str, action: str) -> None:

        if action.startswith("ctrl_o:"):
            file_path = action.split("ctrl_o:", 1)[1]
            _handle_load(app, file_path)

        elif action == "ctrl_s":
            _handle_save(app)

        elif action == "ctrl_r":
            pass

        elif action == "ctrl_p":
            pass

        elif action == "ctrl_x":
            pass

        elif action == "add":
            pass

        elif action == "edit":
            pass

        elif action == "delete":
            pass

    return action_handler


"""
Entrada: app (MenuApp), file_path (str)
Salida: None
Descripción: Loads a scenario from the given file path into the app,
             resolving SAVES_DIR-relative paths, and reports status.
"""
def _handle_load(app: MenuApp, file_path: str) -> None:
    path = Path(file_path)
    if not path.exists():
        alt = Path(SAVES_DIR) / path.name
        if alt.exists():
            path = alt
        else:
            app.set_status(f"File not found: {file_path}", "err")
            return
    try:
        config = load_scenario(path)
        app.load_config(config)
        app.set_status(f"Loaded: {config.experiment_id} — {config.name}", "ok")
    except ConfigLoadError as exc:
        app.set_status(f"Load error: {exc}", "err")


"""
Entrada: app (MenuApp)
Salida: None
Descripción: Saves the app's active scenario to SAVES_DIR as a JSON file
             named after the experiment_id and reports status.
"""
def _handle_save(app: MenuApp) -> None:
    if app.active_config is None:
        app.set_status("Nothing to save. Load a scenario first (Ctrl+O).", "err")
        return
    save_dir = Path(SAVES_DIR)
    save_dir.mkdir(parents=True, exist_ok=True)
    output_path = save_dir / f"{app.active_config.experiment_id}.json"
    try:
        save_scenario(app.active_config, output_path)
        app.set_status(f"Saved: {output_path}", "ok")
    except ConfigWriteError as exc:
        app.set_status(f"Save error: {exc}", "err")


"""
Entrada: None
Salida: None
Descripción: Entry point that prepares output directories, builds the MenuApp,
             registers the action handler, and runs the curses UI.
"""
def main() -> None:
    print("Starting SH-DATASET Orchestrator...")
    Path(SAVES_DIR).mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_META).mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_PCAP).mkdir(parents=True, exist_ok=True)

    app = MenuApp()
    app.set_action_callback(_build_handler(app))

    try:
        import curses
        curses.wrapper(app.run)
    except KeyboardInterrupt:
        app.stop()
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\nSession ended. Status: {app.status} | Capture: {app.capture}")
    if app.active_config:
        print(f"Last scenario: {app.active_config.experiment_id} — {app.active_config.name}")


if __name__ == "__main__":
    main()
