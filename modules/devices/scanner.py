"""
Entrada: None
Salida: Network scanner module
Descripción: Network Scanner — SH-DATASET.
             Enhanced scanning for Windows/Linux with multiple strategies.
"""
import ipaddress
import logging
import platform
import re
import socket
import subprocess

from modules.devices.device_schema import DeviceEntry, PortInfo, OUI_VENDOR_MAP, IOT_TAG_HEURISTICS
from modules.devices.fingerprint import fingerprint_device

try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
    from scapy.config import conf as scapy_conf
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

logger = logging.getLogger(__name__)

_ARP_TIMEOUT: float = 3.0
_ARP_RETRY: int = 3
_CIDR_MAXHOSTS: int = 1024
_NMAP_TIMEOUT: int = 45
_IS_WINDOWS = platform.system() == "Windows"

SCAN_METHODS = ["nmap", "arp", "all"]


"""
Entrada: ip (str)
Salida: str
Descripción: Resolves the hostname for the given IP, or empty string on failure.
"""
def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


"""
Entrada: mac (str)
Salida: str
Descripción: Returns the OUI vendor name for the given MAC address.
"""
def _oui_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    prefix = mac[:8].lower()
    return OUI_VENDOR_MAP.get(prefix, "")


"""
Entrada: dev (DeviceEntry)
Salida: DeviceEntry
Descripción: Applies fingerprinting to set device_type, role, and tags.
"""
def _apply_fingerprint(dev: DeviceEntry) -> DeviceEntry:
    port_numbers = [p.port for p in dev.open_ports]
    fp = fingerprint_device(ip=dev.ip, mac=dev.mac, vendor=dev.vendor, open_ports=port_numbers or None)
    dev.device_type = fp.device_type
    if fp.suggested_role != "unknown":
        dev.role = fp.suggested_role
    if fp.suggested_tags:
        for tag in fp.suggested_tags.split():
            if tag and tag not in dev.tags:
                dev.tags.append(tag)
    return dev


"""
Entrada: dev (DeviceEntry)
Salida: DeviceEntry
Descripción: Enriches the device with vendor and heuristic tags based on MAC.
"""
def _enrich_vendor_tags(dev: DeviceEntry) -> DeviceEntry:
    if not dev.vendor and dev.mac:
        dev.vendor = _oui_vendor(dev.mac)
    if dev.vendor and dev.vendor in IOT_TAG_HEURISTICS:
        for tag in IOT_TAG_HEURISTICS[dev.vendor]:
            if tag not in dev.tags:
                dev.tags.append(tag)
    return dev



"""
Entrada: cidr (str), iface_name (str)
Salida: list[DeviceEntry]
Descripción: Host discovery with nmap. Uses multiple strategies:
             1) -sn -PR (ARP ping — most reliable on LAN)
             2) -sn (ICMP + TCP ping fallback)
             On Windows, omits -e flag (interface selection works differently).
"""
def nmap_scan(cidr: str, iface_name: str = "") -> list[DeviceEntry]:
    cmd = ["nmap", "-sn", "-PR", cidr]
    if not _IS_WINDOWS and iface_name:
        cmd.extend(["-e", iface_name])

    logger.info("nmap scan (ARP ping): %s", " ".join(cmd))
    devices = _run_nmap(cmd)

    if not devices:
        cmd = ["nmap", "-sn", cidr]
        if not _IS_WINDOWS and iface_name:
            cmd.extend(["-e", iface_name])
        logger.info("nmap scan (ping fallback): %s", " ".join(cmd))
        devices = _run_nmap(cmd)

    logger.info("nmap scan: %d hosts found", len(devices))
    return devices


"""
Entrada: cmd (list[str])
Salida: list[DeviceEntry]
Descripción: Runs an nmap command and parses its output into device entries.
"""
def _run_nmap(cmd: list[str]) -> list[DeviceEntry]:
    try:
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=_NMAP_TIMEOUT, check=False)
        if result.returncode != 0:
            logger.warning("nmap stderr: %s", result.stderr[:200])
        return _parse_nmap_output(result.stdout)
    except FileNotFoundError:
        logger.error("nmap not found — install: https://nmap.org/download")
        return []
    except subprocess.TimeoutExpired:
        logger.error("nmap timeout (%ds)", _NMAP_TIMEOUT)
        return []


"""
Entrada: output (str)
Salida: list[DeviceEntry]
Descripción: Parses nmap text output into a list of device entries.
"""
def _parse_nmap_output(output: str) -> list[DeviceEntry]:
    devices = []
    current_ip = ""
    current_host = ""
    current_ports: list[PortInfo] = []

    for line in output.splitlines():
        m = re.match(r"Nmap scan report for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            if current_ip:
                dev = DeviceEntry(
                    ip=current_ip, hostname=current_host or _resolve_hostname(current_ip),
                    open_ports=list(current_ports))
                dev = _enrich_vendor_tags(dev)
                dev = _apply_fingerprint(dev)
                devices.append(dev)
            current_host = m.group(1) or ""
            current_ip = m.group(2)
            current_ports = []
            continue

        m_port = re.match(r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m_port:
            current_ports.append(PortInfo(
                port=int(m_port.group(1)), protocol=m_port.group(3),
                banner=m_port.group(4).strip()))
            continue

        m_mac = re.match(r"MAC Address:\s+([0-9A-Fa-f:]+)\s*(?:\((.+?)\))?", line)
        if m_mac and current_ip:
            mac = m_mac.group(1)
            vendor = m_mac.group(2) or ""
            dev = DeviceEntry(
                ip=current_ip, mac=mac,
                hostname=current_host or _resolve_hostname(current_ip),
                vendor=vendor, open_ports=list(current_ports))
            dev = _enrich_vendor_tags(dev)
            dev = _apply_fingerprint(dev)
            devices.append(dev)
            current_ip = ""
            current_host = ""
            current_ports = []

    if current_ip:
        dev = DeviceEntry(
            ip=current_ip, hostname=current_host or _resolve_hostname(current_ip),
            open_ports=list(current_ports))
        dev = _enrich_vendor_tags(dev)
        dev = _apply_fingerprint(dev)
        devices.append(dev)

    return devices



"""
Entrada: cidr (str), iface_name (str)
Salida: list[DeviceEntry]
Descripción: Performs a Scapy-based ARP scan over the given CIDR.
"""
def arp_scan(cidr: str, iface_name: str = "") -> list[DeviceEntry]:
    logger.info("ARP scan: cidr=%s iface=%s", cidr, iface_name)
    if not _HAS_SCAPY:
        logger.error("scapy not installed: pip install scapy")
        return []
    try:
        scapy_conf.verb = 0
        network = ipaddress.IPv4Network(cidr, strict=False)
        if network.num_addresses > _CIDR_MAXHOSTS:
            raise ValueError(f"CIDR {cidr}: {network.num_addresses} hosts > max {_CIDR_MAXHOSTS}")
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        kwargs = {"timeout": _ARP_TIMEOUT, "retry": _ARP_RETRY}
        if iface_name and not _IS_WINDOWS:
            kwargs["iface"] = iface_name
        answered, _ = srp(packet, **kwargs)
        devices = []
        for _, rcv in answered:
            dev = DeviceEntry(ip=rcv.psrc, mac=rcv.hwsrc, hostname=_resolve_hostname(rcv.psrc))
            dev = _enrich_vendor_tags(dev)
            dev = _apply_fingerprint(dev)
            devices.append(dev)
        logger.info("ARP scan: %d hosts", len(devices))
        return devices
    except (OSError, ValueError, RuntimeError) as exc:
        logger.error("ARP scan failed: %s", exc)
        return []



"""
Entrada: None
Salida: list[DeviceEntry]
Descripción: Parse the OS ARP table (arp -a) as fallback when Scapy is unavailable.
             Works on Windows without extra dependencies.
"""
def arp_table_scan() -> list[DeviceEntry]:
    logger.info("ARP table scan (arp -a)")
    try:
        result = subprocess.run(["arp", "-a"], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("arp -a failed: %s", exc)
        return []

    devices = []
    for line in result.stdout.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F][0-9a-fA-F:.-]{10,16})", line)
        if m:
            ip = m.group(1)
            mac = m.group(2).replace("-", ":").lower()
            if ip.startswith("224.") or ip == "255.255.255.255":
                continue
            dev = DeviceEntry(ip=ip, mac=mac, hostname=_resolve_hostname(ip))
            dev = _enrich_vendor_tags(dev)
            dev = _apply_fingerprint(dev)
            devices.append(dev)

    logger.info("ARP table: %d entries", len(devices))
    return devices



"""
Entrada: existing (list[DeviceEntry]), new_devices (list[DeviceEntry])
Salida: list[DeviceEntry]
Descripción: Merges newly scanned devices into the existing list, matching by MAC or IP.
"""
def merge_by_mac(existing: list[DeviceEntry], new_devices: list[DeviceEntry]) -> list[DeviceEntry]:
    mac_map = {d.mac.lower(): d for d in existing if d.mac}
    ip_map = {d.ip: d for d in existing}
    result = list(existing)

    for nd in new_devices:
        nd_mac = nd.mac.lower() if nd.mac else ""
        matched = _find_match(nd_mac, nd.ip, mac_map, ip_map)

        if matched:
            _update_matched(matched, nd, nd_mac, mac_map, ip_map)
        else:
            _add_new_device(nd, nd_mac, result, mac_map, ip_map)

    _mark_offline(result, new_devices)
    return result


"""
Entrada: nd_mac, nd_ip, mac_map, ip_map
Salida: DeviceEntry | None
Descripción: Find existing device by MAC (priority) or IP.
"""
def _find_match(nd_mac, nd_ip, mac_map, ip_map):
    if nd_mac and nd_mac in mac_map:
        return mac_map[nd_mac]
    if nd_ip in ip_map:
        return ip_map[nd_ip]
    return None


"""
Entrada: matched, nd, nd_mac, mac_map, ip_map
Salida: None
Descripción: Update existing device with new scan data, preserving user edits.
"""
def _update_matched(matched, nd, nd_mac, mac_map, ip_map):
    if nd_mac and matched.ip != nd.ip:
        logger.info("MAC match: %s IP %s → %s", nd_mac, matched.ip, nd.ip)
        old_ip = matched.ip
        matched.ip = nd.ip
        ip_map.pop(old_ip, None)
        ip_map[nd.ip] = matched
    matched.status = "online"
    if nd.vendor and not matched.vendor:
        matched.vendor = nd.vendor
    if nd.hostname and not matched.hostname:
        matched.hostname = nd.hostname
    if nd.open_ports:
        matched.open_ports = nd.open_ports
    if nd.device_type != "unknown" and matched.device_type == "unknown":
        matched.device_type = nd.device_type
    for tag in nd.tags:
        if tag not in matched.tags:
            matched.tags.append(tag)


"""
Entrada: nd, nd_mac, result, mac_map, ip_map
Salida: None
Descripción: Add a newly discovered device.
"""
def _add_new_device(nd, nd_mac, result, mac_map, ip_map):
    nd.status = "online"
    result.append(nd)
    if nd_mac:
        mac_map[nd_mac] = nd
    ip_map[nd.ip] = nd


"""
Entrada: result, new_devices
Salida: None
Descripción: Mark devices not seen in this scan as offline.
"""
def _mark_offline(result, new_devices):
    new_macs = {d.mac.lower() for d in new_devices if d.mac}
    new_ips = {d.ip for d in new_devices}
    for dev in result:
        dev_mac = dev.mac.lower() if dev.mac else ""
        if dev_mac and dev_mac not in new_macs and dev.ip not in new_ips:
            dev.status = "offline"



"""
Entrada: iface_name (str), cidr (str), method (str)
Salida: list[DeviceEntry]
Descripción: Scans the network using the selected method (nmap, arp, or all).
"""
def scan_network(iface_name: str, cidr: str = "192.168.1.0/24", method: str = "nmap") -> list[DeviceEntry]:
    devices: list[DeviceEntry] = []

    if method in ("nmap", "all"):
        devices.extend(nmap_scan(cidr, iface_name))

    if method in ("arp", "all"):
        arp_devs = arp_scan(cidr, iface_name)
        if not arp_devs and _IS_WINDOWS:
            arp_devs = arp_table_scan()
        seen_ips = {d.ip for d in devices}
        for d in arp_devs:
            if d.ip not in seen_ips:
                devices.append(d)
                seen_ips.add(d.ip)

    return devices
