"""
╔══════════════════════════════════════════════════════════════╗
║  SH-DATASET — Plugin de Ataque (Ejemplo/Template)          ║
╚══════════════════════════════════════════════════════════════╝

Este archivo es una plantilla para crear plugins de ataque personalizados.
El sistema los detecta automáticamente al iniciar la aplicación.

REQUISITOS:
  1. El archivo debe estar en:  plugins/attacks/<nombre>.py
  2. Debe definir una lista ATTACK_DEFS con al menos un AttackDef
  3. Debe definir una función run() que ejecuta el ataque
  4. Se ejecuta SOLO LOCALMENTE (no via SSH)

VERIFICACIÓN:
  - El sistema analiza TODOS los imports (incluso dentro de funciones)
    con AST para detectar dependencias faltantes
  - Presionar 'V' en Attack Library para verificar

CAMPOS DE AttackDef:
  name           : str   — Identificador único del ataque
  description    : str   — Descripción corta
  tool           : str   — Herramienta/librería usada (ej: "python/scapy")
  mitre_ref      : str   — Referencia MITRE ATT&CK (ej: "T1498.001")
  category       : str   — Categoría (dos, recon, mitm, brute_force, etc)
  command        : str   — Se ignora en plugins (usar "plugin")
  requires_root  : bool  — True si necesita permisos de administrador
  recommended_dur_s: int — Duración recomendada en segundos
  continuous     : bool  — True si el ataque es continuo (necesita duración)
  local_fallback : str   — Ruta al punto de entrada: "archivo:función"

FUNCIÓN run():
  Parámetros recibidos:
    target_ip  : str   — IP del dispositivo objetivo
    port       : int   — Puerto destino (default 80)
    duration   : int   — Duración en segundos (solo si continuous=True)
    **kwargs          — Parámetros adicionales del escenario

  Debe retornar:
    dict con al menos: {"success": bool, "message": str}
"""

# ── Imports de módulos del proyecto (siempre disponibles) ────
from modules.attacks.base import AttackDef

# ── Definición del ataque ────────────────────────────────────
ATTACK_DEFS = [
    AttackDef(
        name="example_ping",
        description="Ejemplo: ping continuo al target (template de plugin)",
        tool="python/socket",
        mitre_ref="T1018",
        category="recon",
        command="plugin",
        requires_root=False,
        recommended_dur_s=10,
        continuous=True,
        local_fallback="plugin_example:run",
    ),
]


# ── Función de ejecución ─────────────────────────────────────
def run(target_ip: str, port: int = 80, duration: int = 10, **kwargs) -> dict:
    """
    Punto de entrada del plugin. Se ejecuta localmente.

    Este ejemplo hace ping ICMP al target durante 'duration' segundos
    usando solo librerías estándar de Python (sin dependencias externas).
    """
    import subprocess
    import platform
    import time

    start = time.time()
    count = 0
    errors = 0

    # Determinar comando de ping según OS
    flag = "-n" if platform.system() == "Windows" else "-c"

    while time.time() - start < duration:
        try:
            result = subprocess.run(
                ["ping", flag, "1", target_ip],
                capture_output=True, text=True,
                timeout=5, check=False,
            )
            if result.returncode == 0:
                count += 1
            else:
                errors += 1
        except subprocess.TimeoutExpired:
            errors += 1
        except FileNotFoundError:
            return {
                "success": False,
                "message": "ping no disponible en el sistema",
            }

    elapsed = time.time() - start
    return {
        "success": True,
        "message": f"Ping: {count} ok, {errors} fallos en {elapsed:.1f}s",
        "packets_sent": count + errors,
        "packets_ok": count,
        "duration": elapsed,
    }
