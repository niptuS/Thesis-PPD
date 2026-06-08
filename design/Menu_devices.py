from __future__ import annotations

from dataclasses import dataclass, field
from design.Menu_types import Section, FieldMeta


@dataclass
class DeviceEntry:
    node_id:   str
    role:      str
    ip:        str
    mac:       str
    vendor:    str
    protocols: str
    tags:      str
    status:    str


_PLACEHOLDER_DEVICES: list[DeviceEntry] = [
    DeviceEntry("smartbulb01",  "target",   "192.168.1.10", "AA:BB:CC:DD:EE:01", "Philips",   "HTTP MQTT",  "bulb kitchen",   "online"),
    DeviceEntry("smartbulb02",  "target",   "192.168.1.11", "AA:BB:CC:DD:EE:02", "Philips",   "HTTP MQTT",  "bulb living",    "online"),
    DeviceEntry("smartplug01",  "target",   "192.168.1.20", "AA:BB:CC:DD:EE:03", "TP-Link",   "HTTP",       "plug kitchen",   "online"),
    DeviceEntry("camera01",     "target",   "192.168.1.30", "AA:BB:CC:DD:EE:04", "Hikvision", "RTSP HTTP",  "camera outdoor", "online"),
    DeviceEntry("echo01",       "benign",   "192.168.1.40", "AA:BB:CC:DD:EE:05", "Amazon",    "HTTP HTTPS", "alexa voice",    "online"),
    DeviceEntry("kalivm",       "attacker", "192.168.1.50", "AA:BB:CC:DD:EE:06", "VMware",    "TCP",        "attacker vm",    "ready"),
]


def _build_device_table(devices: list[DeviceEntry]) -> list[str]:
    lines: list[str] = []
    header = f"  {'ID':<16} {'Role':<10} {'IP':<16} {'Status':<8}"
    lines.append(header)
    lines.append("  " + "─" * (len(header) - 2))
    for d in devices:
        lines.append(
            f"  {d.node_id:<16} {d.role:<10} {d.ip:<16} {d.status:<8}"
        )
    return lines


def _build_selected_detail(device: DeviceEntry) -> list[str]:
    return [
        f"  Node ID   : {device.node_id}",
        f"  Role      : {device.role}",
        f"  IP        : {device.ip}",
        f"  MAC       : {device.mac}",
        f"  Vendor    : {device.vendor}",
        f"  Protocols : {device.protocols}",
        f"  Tags      : {device.tags}",
        f"  Status    : {device.status}",
    ]


def build_devices_section(
    devices:        list[DeviceEntry] | None = None,
    selected_id:    str                      = "",
    scan_iface:     str                      = "",
    scan_cidr:      str                      = "192.168.1.0/24",
    last_scan:      str                      = "never",
    scan_method:    str                      = "nmap",
) -> Section:
    device_list = devices if devices is not None else _PLACEHOLDER_DEVICES
    selected    = next(
        (d for d in device_list if d.node_id == selected_id),
        device_list[0] if device_list else None,
    )

    scan_iface_display = scan_iface or "(not set — use Ctrl+N)"

    content: list[str] = [
        "─── Scan Settings ────────────────────────────────────",
        f"  Interface  : {scan_iface_display}",
        f"  CIDR       : {scan_cidr}",
        f"  Method     : {scan_method}   [nmap | arp | mdns | all]",
        f"  Last scan  : {last_scan}",
        "",
        "─── Actions ──────────────────────────────────────────",
        "  [S] Scan now    [M] Change method    [C] Set CIDR",
        "",
        "─── Registered Nodes ─────────────────────────────────",
    ]

    content.extend(_build_device_table(device_list))

    field_map: list[FieldMeta] = []
    scan_iface_line = 1
    scan_cidr_line  = 2
    scan_method_line = 3

    field_map.append(FieldMeta(
        line_idx  = scan_iface_line,
        label     = "Interface",
        attr_path = "capture_iface",
        editable  = True,
    ))
    field_map.append(FieldMeta(
        line_idx  = scan_cidr_line,
        label     = "CIDR",
        attr_path = "scan_cidr",
        editable  = True,
    ))
    field_map.append(FieldMeta(
        line_idx  = scan_method_line,
        label     = "Method",
        attr_path = "scan_method",
        editable  = True,
    ))

    if selected is not None:
        content.append("")
        content.append(f"─── Selected: {selected.node_id} ──────────────────────────────")
        content.extend(_build_selected_detail(selected))
        content.append("")
        content.append("─── Node Actions ─────────────────────────────────────")
        content.append("  [A] Add    [E] Edit    [R] Remove    [T] Tag    [F] Filter")

    return Section(
        key          = "devices",
        label        = "Devices",
        hint         = (
            "S=escanear red  ·  A=agregar nodo  ·  E=editar  ·  "
            "R=remover  ·  T=etiquetar  ·  M=método  ·  Ctrl+N=cambiar NIC"
        ),
        content_lines = content,
        actions       = ["S Scan", "A Add", "E Edit", "R Remove", "T Tag", "M Method", "C CIDR"],
        field_map     = field_map,
    )


DEVICES_SECTION: Section = build_devices_section()