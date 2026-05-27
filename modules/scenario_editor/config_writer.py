from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path

from modules.scenario_editor.config_schema import ScenarioConfig

class ConfigWriteError(Exception):
    pass

def save_scenario(config: ScenarioConfig, path: str | Path) -> None:
    output_path = Path(path)
    if output_path.suffix.lower() != ".json":
        raise ConfigWriteError(f"Output path must end in .json, got: {output_path.suffix}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        output_path.write_text(
            json.dumps(asdict(config), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        raise ConfigWriteError(f"Cannot write to {output_path}: {exc}") from exc