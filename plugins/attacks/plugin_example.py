"""
╔══════════════════════════════════════════════════════════════╗
║  SH-DATASET — Attack Plugin (Example/Template)              ║
╚══════════════════════════════════════════════════════════════╝

This file is a template for creating custom attack plugins.
The system detects them automatically on application startup.

REQUIREMENTS:
  1. The file must be located at:  plugins/attacks/<name>.py
  2. It must define an ATTACK_DEFS list with at least one AttackDef
  3. It must define a run() function that executes the attack
  4. It runs LOCALLY ONLY (not via SSH)

VERIFICATION:
  - The system analyzes ALL imports (even inside functions) with AST
    to detect missing dependencies
  - Press 'V' in Attack Library to verify

AttackDef FIELDS:
  name           : str   — Unique attack identifier
  description    : str   — Short description
  tool           : str   — Tool/library used (e.g. "python/scapy")
  mitre_ref      : str   — MITRE ATT&CK reference (e.g. "T1498.001")
  category       : str   — Category (dos, recon, mitm, brute_force, etc)
  command        : str   — Ignored for plugins (use "plugin")
  requires_root  : bool  — True if administrator privileges are required
  recommended_dur_s: int — Recommended duration in seconds
  continuous     : bool  — True if the attack is continuous (needs duration)
  local_fallback : str   — Entry point path: "file:function"

run() FUNCTION:
  Received parameters:
    target_ip  : str   — IP of the target device
    port       : int   — Destination port (default 80)
    duration   : int   — Duration in seconds (only if continuous=True)
    **kwargs          — Additional scenario parameters

  Must return:
    dict with at least: {"success": bool, "message": str}
"""

from modules.attacks.base import AttackDef

ATTACK_DEFS = [
    AttackDef(
        name="example_ping",
        description="Example: Continuous ping",
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


def run(target_ip: str, port: int = 80, duration: int = 10, **kwargs) -> dict:
    """
    Entrada: target_ip (str), port (int), duration (int), **kwargs
    Salida: dict
    Descripción: Example plugin entry point. Sends continuous pings to the
                 target IP for the given duration and returns a summary.
    """
    import subprocess
    import platform
    import time

    start = time.time()
    count = 0
    errors = 0

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
                "message": "ping not available on the system",
            }

    elapsed = time.time() - start
    return {
        "success": True,
        "message": f"Ping: {count} ok, {errors} failures in {elapsed:.1f}s",
        "packets_sent": count + errors,
        "packets_ok": count,
        "duration": elapsed,
    }
