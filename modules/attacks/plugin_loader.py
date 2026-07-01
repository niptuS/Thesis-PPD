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
    name: str                        # nombre del archivo .py
    path: Path
    ok: bool = False
    attacks: list[AttackDef] = field(default_factory=list)
    missing_libs: list[str] = field(default_factory=list)
    error: str = ""

# ── Detector de imports faltantes ───────────────────────────────

def _probe_missing_imports(path: Path) -> list[str]:
    """
    Ejecuta el script en un subproceso aislado y captura ImportError/ModuleNotFoundError.
    Retorna lista de nombres de módulos faltantes.
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
    # Intenta extraer el nombre del módulo del mensaje
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
    """Instala una librería vía pip. Retorna True si tuvo éxito."""
    logger.info("Falta librería '%s', iniciando instalación...", lib_name)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", lib_name,
         "--quiet", "--disable-pip-version-check"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        logger.info("Librería '%s' instalada correctamente.", lib_name)
        return True
    else:
        logger.error("Error instalando '%s': %s", lib_name, result.stderr.strip())
        return False

def load_plugins(
    auto_install: bool = True,
    log_callback=None,
    probe_deps: bool = False,          # función(msg: str) para enviar al UI log
) -> tuple[list[AttackDef], list[PluginStatus]]:
    """
    Escanea PLUGINS_DIR, verifica dependencias, instala si faltan,
    y retorna (lista_de_attacks, lista_de_estados).

    log_callback(msg) es llamado en cada evento importante para
    que el menú curses lo muestre en tiempo real.
    """

    def _log(msg: str):
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    if not PLUGINS_DIR.exists():
        PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
        _log(f"Directorio plugins creado: {PLUGINS_DIR}")
        return [], []

    all_attacks: list[AttackDef] = []
    statuses: list[PluginStatus] = []

    for py_file in sorted(PLUGINS_DIR.glob("*.py")):
        if py_file.name.startswith("_"):
            continue

        status = PluginStatus(name=py_file.stem, path=py_file)
        _log(f"[PLUGIN] Verificando: {py_file.name}")

        # ── 1. Detectar imports faltantes ──────────────────
        missing = _probe_missing_imports(py_file) if probe_deps else []

        if missing:
            status.missing_libs = missing
            for lib in missing:
                _log(f"  ✗ Falta librería '{lib}', iniciando instalación...")
                if auto_install and _install_lib(lib):
                    _log(f"  ✓ '{lib}' instalada.")
                    # volver a probar después de instalar
                    missing = _probe_missing_imports(py_file) if probe_deps else []
                    status.missing_libs = missing
                    if not missing:
                        break
                else:
                    _log(f"  ✗ No se pudo instalar '{lib}'. Plugin deshabilitado.")

        if status.missing_libs:
            status.ok = False
            status.error = "Dependencias faltantes: " + ", ".join(status.missing_libs)
            statuses.append(status)
            continue

        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            if not hasattr(mod, "ATTACK_DEFS"):
                status.error = "No expone ATTACK_DEFS"
                statuses.append(status)
                _log(f"  ✗ {py_file.name}: no tiene ATTACK_DEFS")
                continue

            defs: list[AttackDef] = mod.ATTACK_DEFS
            for atk in defs:
                atk.category = f"plugin:{atk.category}"

            status.attacks = defs
            status.ok = True
            all_attacks.extend(defs)
            _log(f"  ✓ {py_file.name}: {len(defs)} ataque(s) cargado(s).")

        except Exception as exc:
            status.error = str(exc)
            _log(f"  ✗ Error cargando {py_file.name}: {exc}")

        statuses.append(status)

    return all_attacks, statuses