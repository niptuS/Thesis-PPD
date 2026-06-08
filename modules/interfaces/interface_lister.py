import ipaddress
import logging
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger(__name__)

RFC1918_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

VIRTUAL_PREFIXES: tuple[str, ...] = (
    "lo", "virbr", "docker", "veth", "br-", "tun", "tap",
    "vmnet", "vbox", "wsl", "utun", "awdl", "llw",
)


@dataclass
class InterfaceInfo:
    name:       str
    ip:         str
    mac:        str
    is_up:      bool
    mtu:        int
    is_private: bool
    is_virtual: bool
    speed_mbps: int
    addresses:  list[str] = field(default_factory=list)


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def _is_virtual(name: str) -> bool:
    return any(name.lower().startswith(p) for p in VIRTUAL_PREFIXES)


def _extract_mac(addrs: list) -> str:
    for addr in addrs:
        if addr.family.name in ("AF_PACKET", "AF_LINK"):
            return addr.address or ""
    return ""


def _extract_ipv4(addrs: list) -> tuple[str, list[str]]:
    primary = ""
    all_ips: list[str] = []
    for addr in addrs:
        if addr.family.name == "AF_INET":
            all_ips.append(addr.address)
            if not primary:
                primary = addr.address
    return primary, all_ips


def list_interfaces(include_virtual: bool = False) -> list[InterfaceInfo]:
    results: list[InterfaceInfo] = []
    stats   = psutil.net_if_stats()
    all_if  = psutil.net_if_addrs()

    for name, addrs in all_if.items():
        is_virtual = _is_virtual(name)
        if is_virtual and not include_virtual:
            continue

        ip, all_ips = _extract_ipv4(addrs)
        if not ip:
            continue

        mac      = _extract_mac(addrs)
        iface_st = stats.get(name)
        is_up    = iface_st.isup  if iface_st else False
        mtu      = iface_st.mtu   if iface_st else 0
        speed    = iface_st.speed if iface_st else 0

        results.append(InterfaceInfo(
            name       = name,
            ip         = ip,
            mac        = mac,
            is_up      = is_up,
            mtu        = mtu,
            is_private = _is_private_ip(ip),
            is_virtual = is_virtual,
            speed_mbps = speed,
            addresses  = all_ips,
        ))

    logger.debug("interfaces discovered: %d", len(results))
    return results