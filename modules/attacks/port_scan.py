"""Port Scan — TCP connect/SYN scan using nmap or Scapy."""
import subprocess
import time
from modules.attacks.base import BaseAttack, AttackResult, logger


class PortScanAttack(BaseAttack):
    name = "port_scan"
    description = "TCP port scanning — reconnaissance of open services"
    mitre_ref = "T1046"

    """
    Entrada: target_ip (str), duration_s (int), intensity (str), port_range (str), **kwargs
    Salida: AttackResult
    Descripción: Runs TCP port scanning using nmap for service reconnaissance.
    """
    def run(self, target_ip: str, duration_s: int = 60, intensity: str = "medium",
            port_range: str = "1-1024", **kwargs) -> AttackResult:
        if not self.validate(target_ip):
            return AttackResult(success=False, error=f"Invalid IP: {target_ip}")
        timing = {"low": "-T2", "medium": "-T4", "high": "-T5"}.get(intensity, "-T4")
        try:
            start = time.time()
            result = subprocess.run(
                ["nmap", timing, "-p", port_range, target_ip],
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=duration_s,
                check=False,
            )
            elapsed = time.time() - start
            open_count = result.stdout.count("/tcp") + result.stdout.count("/udp")
            logger.info("Port scan: %d open ports in %.1fs → %s", open_count, elapsed, target_ip)
            return AttackResult(success=True, packets=open_count, duration=elapsed)
        except FileNotFoundError:
            return AttackResult(success=False, error="nmap required")
        except subprocess.TimeoutExpired:
            return AttackResult(success=False, error="timeout")
        except Exception as e:
            return AttackResult(success=False, error=str(e))
