"""
Entrada: None
Salida: Plugin loader module
Descripción: Scans the plugins/attacks directory, probes for missing
             dependencies, optionally auto-installs them, and loads
             each plugin's ATTACK_DEFS list.
"""
from __future__ import annotations
import importlib.util
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from modules.attacks.base import AttackDef

logger = logging.getLogger(__name__)

PLUGINS_DIR = Path("plugins/attacks")


@dataclass
class PluginStatus:
    """
    Entrada: name (str), path (Path)
    Salida: PluginStatus instance
    Descripción: Dataclass holding the load status of a single plugin file.
    """
    name: str
    path: Path
    ok: bool = False
    attacks: list[AttackDef] = field(default_factory=list)
    missing_libs: list[str] = field(default_factory=list)
    error: str = ""


def _probe_missing_imports(path: Path) -> list[str]:
    """
    Entrada: path (Path)
    Salida: list[str]
    Descripción: Runs the script in an isolated subprocess and captures
                 ImportError/ModuleNotFoundError. Returns the list of missing
                 module names.
    """
    probe_code = f"""
import sys, traceback
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("_probe", r"{path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    print("OK")
except ModuleNotFoundError as e:
    print("MISSING:" + e.name)
except ImportError as e:
    msg = str(e)
    name = msg.split("'")[1] if "'" in msg else msg.split()[-1]
    print("MISSING:" + name)
except Exception as e:
    print("ERROR:" + str(e))
"""
    result = subprocess.run(
        [sys.executable, "-c", probe_code],
        capture_output=True, text=True, timeout=15
    )
    output = (result.stdout + result.stderr).strip()

    missing = []
    for line in output.splitlines():
        if line.startswith("MISSING:"):
            lib = line.removeprefix("MISSING:").strip()
            if lib:
                missing.append(lib)
    return missing


def _install_lib(lib_name: str) -> bool:
    """
    Entrada: lib_name (str)
    Salida: bool
    Descripción: Installs a library via pip. Returns True on success.
    """
    logger.info("Missing library '%s', starting installation...", lib_name)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", lib_name,
         "--quiet", "--disable-pip-version-check"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        logger.info("Library '%s' installed successfully.", lib_name)
        return True
    else:
        logger.error("Error installing '%s': %s", lib_name, result.stderr.strip())
        return False

def load_plugins(
    auto_install: bool = True,
    log_callback=None,
    probe_deps: bool = False,
) -> tuple[list[AttackDef], list[PluginStatus]]:
    """
    Entrada: auto_install (bool), log_callback (callable|None), probe_deps (bool)
    Salida: tuple[list[AttackDef], list[PluginStatus]]
    Descripción: Scans PLUGINS_DIR, verifies dependencies, installs if missing,
                 and returns (list_of_attacks, list_of_statuses). log_callback(msg)
                 is called on each important event so the curses menu can show it
                 in real time.
    """

    def _log(msg: str):
        """
        Entrada: msg (str)
        Salida: None
        Descripción: Forwards a log message to both the logger and the optional callback.
        """
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    if not PLUGINS_DIR.exists():
        PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
        _log(f"Plugins directory created: {PLUGINS_DIR}")
        return [], []

    all_attacks: list[AttackDef] = []
    statuses: list[PluginStatus] = []

    for py_file in sorted(PLUGINS_DIR.glob("*.py")):
        if py_file.name.startswith("_"):
            continue

        status = PluginStatus(name=py_file.stem, path=py_file)
        _log(f"[PLUGIN] Checking: {py_file.name}")

        missing = _probe_missing_imports(py_file) if probe_deps else []

        if missing:
            status.missing_libs = missing
            for lib in missing:
                _log(f"  ✗ Missing library '{lib}', starting installation...")
                if auto_install and _install_lib(lib):
                    _log(f"  ✓ '{lib}' installed.")
                    missing = _probe_missing_imports(py_file) if probe_deps else []
                    status.missing_libs = missing
                    if not missing:
                        break
                else:
                    _log(f"  ✗ Could not install '{lib}'. Plugin disabled.")

        if status.missing_libs:
            status.ok = False
            status.error = "Missing dependencies: " + ", ".join(status.missing_libs)
            statuses.append(status)
            continue

        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            if not hasattr(mod, "ATTACK_DEFS"):
                status.error = "Does not expose ATTACK_DEFS"
                statuses.append(status)
                _log(f"  ✗ {py_file.name}: no ATTACK_DEFS")
                continue

            defs: list[AttackDef] = mod.ATTACK_DEFS
            for atk in defs:
                atk.category = f"plugin:{atk.category}"

            status.attacks = defs
            status.ok = True
            all_attacks.extend(defs)
            _log(f"  ✓ {py_file.name}: {len(defs)} attack(s) loaded.")

        except Exception as exc:
            status.error = str(exc)
            _log(f"  ✗ Error loading {py_file.name}: {exc}")

        statuses.append(status)

    return all_attacks, statuses
