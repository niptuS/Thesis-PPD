import logging
import socket
import ipaddress
from typing import Generator

from modules.interfaces.interface_lister import InterfaceInfo
from modules.devices.device_schema import DeviceEntry

logger = logging.getLogger(__name__)

_ARP_TIMEOUT:  float = 2.0
_ARP_RETRY:    int   = 2
_CIDR_MAXHOSTS: int  = 1024


def _infer_cidr(iface: InterfaceInfo) -> str:
    try:
        from psutil import net_if_addrs
        import psutil
        addrs = net_if_addrs().get(iface.name, [])
        for addr in addrs:
            if addr.family.name == "AF_INET" and addr.netmask:
                network = ipaddress.IPv4Network(
                    f"{addr.address}/{addr.netmask}", strict=False
                )
                return str(network)
    except Exception as exc:
        logger.warning("could not infer CIDR from interface %s: %s", iface.name, exc)
    return f"{iface.ip}/24"


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _arp_scan(
    cidr: str,
    iface_name: str,
) -> list[tuple[str, str]]:
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        from scapy.config import conf as scapy_conf

        scapy_conf.verb = 0
        network = ipaddress.IPv4Network(cidr, strict=False)
        if network.num_addresses > _CIDR_MAXHOSTS:
            raise ValueError(
                f"CIDR {cidr} has {network.num_addresses} hosts, "
                f"max allowed is {_CIDR_MAXHOSTS}"
            )

        packet  = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(
            packet,
            iface   = iface_name,
            timeout = _ARP_TIMEOUT,
            retry   = _ARP_RETRY,
        )
        return [(rcv.psrc, rcv.hwsrc) for _, rcv in answered]

    except ImportError as exc:
        raise ImportError(
            "scapy is required for ARP scanning. "
            "Install with: pip install scapy"
        ) from exc


def _iter_hosts(
    ip_mac_pairs: list[tuple[str, str]],
) -> Generator[DeviceEntry, None, None]:
    for ip, mac in ip_mac_pairs:
        hostname = _resolve_hostname(ip)
        yield DeviceEntry(ip=ip, mac=mac, hostname=hostname)


def scan_network(
    iface: InterfaceInfo,
    cidr:  str | None = None,
) -> list[DeviceEntry]:
    target_cidr = cidr if cidr is not None else _infer_cidr(iface)
    logger.info(
        "starting ARP scan on %s cidr=%s",
        iface.name, target_cidr,
    )

    try:
        pairs = _arp_scan(target_cidr, iface.name)
    except (ValueError, OSError, PermissionError) as exc:
        logger.error("ARP scan failed: %s", exc)
        raise

    devices = list(_iter_hosts(pairs))
    logger.info("ARP scan complete: %d hosts discovered", len(devices))
    return devices