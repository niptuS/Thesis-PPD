import ipaddress
from dataclasses import dataclass, field


IOT_PORT_MAP: dict[int, str] = {
    80: "http",
    443: "https",
    554: "rtsp",
    1883: "mqtt",
    5683: "coap",
    8080: "http-alt",
    8443: "https-alt",
    8883: "mqtt-tls",
    9090: "http-mgmt",
}

OUI_VENDOR_MAP: dict[str, str] = {
    "18:fe:34": "Espressi",
    "24:6f:28": "Espressi",
    "a4:cf:12": "Espressi",
    "8c:aa:b5": "Espressi",
    "dc:4f:22": "Tuya",
    "d8:f1:5b": "Tuya",
    "e8:db:84": "Tuya",
    "b4:e6:2d": "Amazon",
    "f0:27:2d": "Amazon",
    "40:b4:cd": "Google",
    "54:60:09": "Google",
    "30:fd:38": "Philips Hue",
    "00:17:88": "Philips Hue",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "fc:65:de": "Shelly",
    "e8:68:e7": "Shelly",
    "cc:50:e3": "Espressi",
    "7c:87:ce": "Xiaomi",
    "28:6c:07": "Xiaomi",
}

IOT_TAG_HEURISTICS: dict[str, list[str]] = {
    "Espressi": ["esp-device"],
    "Tuya": ["smart-plug", "bulb"],
    "Amazon": ["echo", "alexa"],
    "Google": ["nest", "chromecast"],
    "Philips Hue": ["bulb", "zigbee-bridge"],
    "Shelly": ["smart-plug", "relay"],
    "Xiaomi": ["mi-device"],
    "Raspberry Pi": ["gateway", "sensor"],
}


def _validate_ip(ip: str) -> str:
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError as exc:
        raise ValueError(f"invalid IPv4 address: {ip!r}") from exc


def _validate_mac(mac: str) -> str:
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {mac!r}")
    return ":".join(parts)


@dataclass
class PortInfo:
    port: int
    protocol: str
    banner: str = ""


@dataclass
class DeviceEntry:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    open_ports: list[PortInfo] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    iot_score: int = 0
    role: str = "target"
    device_type: str = "unknown"
    status: str = "online"
    notes: str = ""

    def __post_init__(self) -> None:
        self.ip = _validate_ip(self.ip)
        if self.mac:
            self.mac = _validate_mac(self.mac)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "open_ports": [
                {"port": p.port, "protocol": p.protocol, "banner": p.banner}
                for p in self.open_ports
            ],
            "tags": self.tags,
            "iot_score": self.iot_score,
            "role": self.role,
            "device_type": self.device_type,
            "status": self.status,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceEntry":
        ports = [
            PortInfo(
                port=p["port"],
                protocol=p.get("protocol", ""),
                banner=p.get("banner", ""),
            )
            for p in data.get("open_ports", [])
        ]
        return cls(
            ip=data["ip"],
            mac=data.get("mac", ""),
            hostname=data.get("hostname", ""),
            vendor=data.get("vendor", ""),
            open_ports=ports,
            tags=data.get("tags", []),
            iot_score=data.get("iot_score", 0),
            role=data.get("role", "target"),
            device_type=data.get("device_type", "unknown"),
            status=data.get("status", "online"),
            notes=data.get("notes", ""),
        )
