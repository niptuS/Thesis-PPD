"""
Entrada: None
Salida: fingerprint module
Descripción: Device Fingerprinting — SH-DATASET.
             Infers the IoT device type from vendor (MAC OUI), open ports/services
             (nmap -sV), and service types (mDNS).
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field


@dataclass
class DeviceFingerprint:
    device_type: str = "unknown"
    confidence: str = "low"
    protocols: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    os_hint: str = ""
    reason: str = ""
    suggested_role: str = "unknown"
    suggested_tags: str = ""


_TYPE_LABELS: dict[str, str] = {
    "camera": "📷 IP Camera",
    "bulb": "💡 Bulb",
    "plug": "🔌 Plug",
    "speaker": "🔊 Speaker",
    "hub": "🏠 Hub/Bridge",
    "tv": "📺 Smart TV",
    "sensor": "📡 IoT Sensor",
    "router": "🌐 Router",
    "pc": "💻 PC",
    "attacker": "⚔ Attacker",
    "unknown": "❓ Unknown",
}


def get_type_label(device_type: str) -> str:
    return _TYPE_LABELS.get(device_type, f"❓ {device_type}")


_TYPE_TO_ROLE: dict[str, str] = {
    "camera": "target",
    "bulb": "target",
    "plug": "target",
    "sensor": "target",
    "speaker": "benign",
    "hub": "benign",
    "tv": "benign",
    "router": "benign",
    "pc": "benign",
    "attacker": "attacker",
    "unknown": "unknown",
}


_VENDOR_MAP: dict[str, tuple[str, str]] = {
    "philips": ("bulb", "medium"),
    "signify": ("bulb", "medium"),
    "lifx": ("bulb", "high"),
    "ikea": ("bulb", "medium"),
    "hikvision": ("camera", "high"),
    "dahua": ("camera", "high"),
    "reolink": ("camera", "high"),
    "axis": ("camera", "high"),
    "amcrest": ("camera", "high"),
    "wyze": ("camera", "medium"),
    "ring": ("camera", "medium"),
    "tp-link": ("plug", "medium"),
    "kasa": ("plug", "medium"),
    "tapo": ("plug", "medium"),
    "meross": ("plug", "medium"),
    "wemo": ("plug", "medium"),
    "belkin": ("plug", "medium"),
    "sonof": ("plug", "medium"),
    "tuya": ("plug", "low"),
    "amazon": ("speaker", "medium"),
    "echo": ("speaker", "high"),
    "google": ("speaker", "medium"),
    "sonos": ("speaker", "high"),
    "apple": ("hub", "low"),
    "samsung": ("tv", "low"),
    "lg electro": ("tv", "medium"),
    "roku": ("tv", "medium"),
    "xiaomi": ("sensor", "low"),
    "aqara": ("sensor", "medium"),
    "espressi": ("sensor", "medium"),
    "raspberry": ("hub", "medium"),
    "vmware": ("attacker", "high"),
    "virtualbox": ("attacker", "high"),
    "parallels": ("attacker", "medium"),
    "qemu": ("attacker", "medium"),
}

_PORT_MAP: dict[int, tuple[str, str]] = {
    554: ("camera", "high"),
    8554: ("camera", "high"),
    1883: ("sensor", "medium"),
    8883: ("sensor", "medium"),
    8008: ("speaker", "medium"),
    8443: ("speaker", "medium"),
    1400: ("speaker", "high"),
    9197: ("bulb", "medium"),
    5683: ("sensor", "medium"),
}

_MDNS_MAP: dict[str, tuple[str, str]] = {
    "_hap._tcp": ("unknown", "medium"),
    "_googlecast._tcp": ("speaker", "high"),
    "_airplay._tcp": ("speaker", "medium"),
    "_raop._tcp": ("speaker", "medium"),
    "_sonos._tcp": ("speaker", "high"),
    "_mqtt._tcp": ("sensor", "medium"),
    "_coap._udp": ("sensor", "medium"),
    "_hue._tcp": ("bulb", "high"),
    "_axis-video._tcp": ("camera", "high"),
    "_amzn-wplay._tcp": ("speaker", "high"),
    "_spotify-connect._tcp": ("speaker", "medium"),
    "_smb._tcp": ("pc", "medium"),
    "_ssh._tcp": ("pc", "medium"),
    "_rdp._tcp": ("pc", "medium"),
}

_OUI_MAP: dict[str, str] = {
    "00:17:88": "Philips",
    "EC:B5:FA": "Philips",
    "94:B9:7E": "TP-Link",
    "50:C7:BF": "TP-Link",
    "B0:BE:76": "TP-Link",
    "E8:48:B8": "TP-Link",
    "54:AF:97": "TP-Link",
    "6C:5A:B0": "TP-Link",
    "00:1E:8F": "Meross",
    "48:E1:E9": "Hikvision",
    "C0:56:E3": "Hikvision",
    "28:57:BE": "Hikvision",
    "A4:CF:12": "Espressi",
    "DC:4F:22": "Espressi",
    "24:6F:28": "Espressi",
    "30:AE:A4": "Espressi",
    "CC:50:E3": "Espressi",
    "40:F5:20": "Google",
    "F4:F5:D8": "Google",
    "F8:0F:F9": "Google",
    "44:D9:E7": "Amazon",
    "A0:02:DC": "Amazon",
    "FC:65:DE": "Amazon",
    "14:91:82": "Belkin",
    "58:EF:68": "Belkin",
    "B8:27:EB": "Raspberry",
    "DC:A6:32": "Raspberry",
    "E4:5F:01": "Raspberry",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "54:27:1E": "Sonos",
    "48:A6:B8": "Sonos",
    "B4:E6:2A": "LG Electro",
    "00:1A:11": "Google",
}

_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}



def _oui_lookup(mac: str) -> str:
    """
    Entrada: mac (str)
    Salida: str
    Descripción: Tries to resolve the vendor from the first 3 octets of the MAC.
    """
    if not mac or len(mac) < 8:
        return ""
    prefix = mac[:8].upper()
    return _OUI_MAP.get(prefix, "")



def fingerprint_device(
    ip: str = "",
    mac: str = "",
    vendor: str = "",
    open_ports: list[int] | None = None,
    services: list[str] | None = None,
    mdns_types: list[str] | None = None,
) -> DeviceFingerprint:
    """
    Entrada: ip, mac, vendor, open_ports, services, mdns_types
    Salida: DeviceFingerprint
    Descripción: Combines vendor, ports, services and mDNS heuristics
                 to infer the device type.
    """
    if not vendor and mac:
        vendor = _oui_lookup(mac)

    candidates: list[tuple[str, str, str]] = []
    detected_protocols: list[str] = []

    if vendor:
        vendor_lower = vendor.lower()
        for key, (dtype, conf) in _VENDOR_MAP.items():
            if key in vendor_lower:
                candidates.append((dtype, conf, f"vendor={vendor}"))
                break

    if open_ports:
        for port in open_ports:
            if port in _PORT_MAP:
                dtype, conf = _PORT_MAP[port]
                candidates.append((dtype, conf, f"port={port}"))

    if mdns_types:
        for mtype in mdns_types:
            mtype_lower = mtype.lower()
            for key, (dtype, conf) in _MDNS_MAP.items():
                if key in mtype_lower:
                    candidates.append((dtype, conf, f"mdns={mtype}"))
                    detected_protocols.append(mtype)
                    break

    if not candidates:
        return DeviceFingerprint(
            device_type="unknown",
            confidence="low",
            open_ports=open_ports or [],
            services=services or [],
            protocols=detected_protocols,
            reason="not enough data",
            suggested_role="unknown",
            suggested_tags="",
        )

    def _score(c):
        dtype, conf, _ = c
        return (0 if dtype == "unknown" else 1, _CONFIDENCE_ORDER.get(conf, 0))

    candidates.sort(key=_score, reverse=True)
    best_type, best_conf, best_reason = candidates[0]

    if open_ports:
        if 80 in open_ports or 443 in open_ports:
            detected_protocols.append("HTTP")
        if 554 in open_ports or 8554 in open_ports:
            detected_protocols.append("RTSP")
        if 1883 in open_ports or 8883 in open_ports:
            detected_protocols.append("MQTT")
        if 22 in open_ports:
            detected_protocols.append("SSH")
        if 5353 in open_ports:
            detected_protocols.append("mDNS")

    role = _TYPE_TO_ROLE.get(best_type, "unknown")
    tags_parts = [best_type]
    if vendor:
        tags_parts.append(vendor.lower().split()[0])
    suggested_tags = " ".join(tags_parts)

    return DeviceFingerprint(
        device_type=best_type,
        confidence=best_conf,
        open_ports=open_ports or [],
        services=services or [],
        protocols=list(dict.fromkeys(detected_protocols)),
        reason=best_reason,
        suggested_role=role,
        suggested_tags=suggested_tags,
    )



def nmap_service_scan(ip: str, timeout: int = 15) -> tuple[list[int], list[str]]:
    """
    Entrada: ip (str), timeout (int)
    Salida: tuple[list[int], list[str]]
    Descripción: Runs nmap -sV on an IP. Returns (open_ports, services).
    """
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--top-ports", "20", "-T4", ip],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [], []

    ports: list[int] = []
    services: list[str] = []
    for line in result.stdout.splitlines():
        m = re.match(r"\s*(\d+)/\w+\s+open\s+(\S+)\s*(.*)", line)
        if m:
            ports.append(int(m.group(1)))
            svc = m.group(2)
            version = m.group(3).strip()
            services.append(f"{svc} {version}".strip() if version else svc)

    return ports, services
