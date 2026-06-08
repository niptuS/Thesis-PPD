import logging
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.devices.device_schema import (
    DeviceEntry,
    PortInfo,
    IOT_PORT_MAP,
    OUI_VENDOR_MAP,
    IOT_TAG_HEURISTICS,
)

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT: float = 1.0
_BANNER_TIMEOUT:  float = 1.5
_MAX_WORKERS:     int   = 20
_HTTP_REQUEST:    bytes = b"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"


def _lookup_vendor(mac: str) -> str:
    if not mac:
        return ""
    oui = mac.lower()[:8]
    return OUI_VENDOR_MAP.get(oui, "")


def _probe_port(ip: str, port: int) -> PortInfo | None:
    try:
        with socket.create_connection((ip, port), timeout=_CONNECT_TIMEOUT) as sock:
            protocol = IOT_PORT_MAP.get(port, "unknown")
            banner   = ""

            if port in (80, 8080, 8443, 9090):
                try:
                    sock.settimeout(_BANNER_TIMEOUT)
                    sock.sendall(_HTTP_REQUEST.replace(b"{host}", ip.encode()))
                    raw = sock.recv(512).decode("utf-8", errors="replace")
                    first_line = raw.split("\r\n")[0] if raw else ""
                    server_hdr = next(
                        (
                            ln.split(":", 1)[1].strip()
                            for ln in raw.split("\r\n")
                            if ln.lower().startswith("server:")
                        ),
                        "",
                    )
                    banner = server_hdr or first_line[:80]
                except (OSError, UnicodeDecodeError):
                    pass

            return PortInfo(port=port, protocol=protocol, banner=banner)

    except (OSError, ConnectionRefusedError, TimeoutError):
        return None


def _scan_ports(ip: str) -> list[PortInfo]:
    open_ports: list[PortInfo] = []
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {
            executor.submit(_probe_port, ip, port): port
            for port in IOT_PORT_MAP
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports, key=lambda p: p.port)


def _build_tags(vendor: str, open_ports: list[PortInfo], banner: str) -> list[str]:
    tags: set[str] = set()

    if vendor in IOT_TAG_HEURISTICS:
        tags.update(IOT_TAG_HEURISTICS[vendor])

    port_numbers = {p.port for p in open_ports}
    if 1883 in port_numbers or 8883 in port_numbers:
        tags.add("mqtt")
    if 554 in port_numbers:
        tags.add("camera")
    if 5683 in port_numbers:
        tags.add("coap")

    banner_lower = banner.lower()
    iot_banner_keywords: dict[str, str] = {
        "shelly":      "smart-plug",
        "hikvision":   "camera",
        "dahua":       "camera",
        "tasmota":     "esp-device",
        "esphome":     "esp-device",
        "philips hue": "bulb",
        "tplink":      "smart-plug",
        "wemo":        "smart-plug",
        "ring":        "camera",
        "nest":        "thermostat",
    }
    for keyword, tag in iot_banner_keywords.items():
        if keyword in banner_lower:
            tags.add(tag)

    return sorted(tags)


def _compute_iot_score(
    vendor:     str,
    open_ports: list[PortInfo],
    tags:       list[str],
) -> int:
    score = 0
    if vendor:
        score += 35 if vendor in OUI_VENDOR_MAP.values() else 0

    port_numbers = {p.port for p in open_ports}
    iot_ports    = set(IOT_PORT_MAP.keys()) - {80, 443, 8080, 8443}
    matched_iot  = port_numbers & iot_ports
    score += min(len(matched_iot) * 15, 40)

    score += min(len(tags) * 5, 25)
    return min(score, 100)


def fingerprint_device(device: DeviceEntry) -> DeviceEntry:
    logger.debug("fingerprinting %s", device.ip)

    vendor     = _lookup_vendor(device.mac)
    open_ports = _scan_ports(device.ip)
    all_banners = " ".join(p.banner for p in open_ports)
    tags       = _build_tags(vendor, open_ports, all_banners)
    iot_score  = _compute_iot_score(vendor, open_ports, tags)

    device.vendor     = vendor
    device.open_ports = open_ports
    device.tags       = tags
    device.iot_score  = iot_score

    logger.info(
        "fingerprint done %s vendor=%r score=%d tags=%s",
        device.ip, vendor, iot_score, tags,
    )
    return device


def fingerprint_all(
    devices:     list[DeviceEntry],
    min_score:   int = 0,
    max_workers: int = 8,
) -> list[DeviceEntry]:
    results: list[DeviceEntry] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(fingerprint_device, dev): dev
            for dev in devices
        }
        for future in as_completed(futures):
            try:
                dev = future.result()
                if dev.iot_score >= min_score:
                    results.append(dev)
            except (OSError, ValueError) as exc:
                logger.warning("fingerprint error: %s", exc)

    return sorted(results, key=lambda d: d.iot_score, reverse=True)