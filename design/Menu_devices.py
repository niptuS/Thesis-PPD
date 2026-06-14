from __future__ import annotations
from design.models import Section, FieldMeta

PAGE_SIZE = 10
DEVICE_ROLES = ["target", "benign", "attacker", "unknown"]

_DETAIL_FIELDS_DISPLAY = [
    ("role", "Role"),
    ("tags", "Tags"),
    ("hostname", "Hostname"),
    ("notes", "Notes"),
    ("device_type", "Device type"),
]


def _display_id(d): return d.hostname or d.ip.replace(".", "_")


def _build_device_table(devices, page=0, device_cursor=0):
    lines = []
    header = f"  {'':2} {'ID':<18} {'Type':<10} {'Role':<10} {'IP':<16} {'Vendor':<14} {'St':<6}"
    lines.append(header)
    lines.append("  " + "─" * (len(header) - 2))
    if not devices:
        lines.append("     (vacío — S para escanear)")
        return lines
    total = len(devices)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, total_pages - 1)
    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, total)
    for i, d in enumerate(devices[start:end]):
        abs_idx = start + i
        marker = "►" if abs_idx == device_cursor else " "
        did = _display_id(d)[:17]
        dtype = (d.device_type or "?")[:9]
        vendor = (d.vendor or "")[:13]
        lines.append(f"  {marker} {did:<18} {dtype:<10} {d.role:<10} {d.ip:<16} {vendor:<14} {d.status:<6}")
    if total_pages > 1:
        lines.append("")
        lines.append(f"  Pág {page + 1}/{total_pages}  ({start + 1}-{end} de {total})    ◄ PgUp  PgDn ►")
    else:
        lines.append(f"  {total} dispositivo(s)")
    return lines


def _build_selected_detail(device, detail_cursor=-1):
    """Build detail section with navigable cursor marker."""
    fields = []
    vals = {
        "role": device.role,
        "tags": " ".join(device.tags) if device.tags else "—",
        "hostname": device.hostname or "—",
        "notes": device.notes or "—",
        "device_type": device.device_type,
    }
    for i, (attr, label) in enumerate(_DETAIL_FIELDS_DISPLAY):
        marker = "►" if i == detail_cursor else " "
        val = vals.get(attr, "—")
        editable = "✎" if attr != "device_type" else " "
        fields.append(f"  {marker}{editable} {label:<13}: {val}")
    return fields


def build_devices_section(devices=None, device_cursor=0, page=0,
                          scan_iface="", scan_cidr="192.168.1.0/24",
                          last_scan="never", scan_method="nmap",
                          detail_cursor=-1):
    device_list = devices if devices is not None else []
    selected = device_list[device_cursor] if device_list and 0 <= device_cursor < len(device_list) else None
    content = [
        "─── Scan Settings ────────────────────────────────────",
        f"  Interface  : {scan_iface or '(not set — Ctrl+N)'}",
        f"  CIDR       : {scan_cidr}",
        f"  Method     : {scan_method}   [nmap | arp | all]",
        f"  Last scan  : {last_scan}",
        "",
        "─── Registered Nodes ─────────────────────────────────",
    ]
    content.extend(_build_device_table(device_list, page, device_cursor))
    if selected is not None:
        content.append("")
        sel_id = _display_id(selected)
        content.append(f"─── {sel_id} ─────────────────────────────────────")
        ports_str = ", ".join(str(p.port) for p in selected.open_ports) if selected.open_ports else "—"
        protos = " ".join(dict.fromkeys(p.protocol for p in selected.open_ports if p.protocol)
                          ) if selected.open_ports else "—"
        content.append(f"  IP: {selected.ip}  MAC: {selected.mac or '—'}  Ports: {ports_str}  Proto: {protos}")
        content.append(
            f"  Vendor: {selected.vendor or '—'}  IoT score: {selected.iot_score}  Status: {selected.status}")
        content.append("")
        content.append("  ── Campos editables (Enter=editar) ──")
        content.extend(_build_selected_detail(selected, detail_cursor))

    field_map = [
        FieldMeta(line_idx=1, label="Interface", attr_path="capture_iface", editable=False),
        FieldMeta(line_idx=2, label="CIDR", attr_path="scan_cidr", editable=True),
        FieldMeta(line_idx=3, label="Method", attr_path="scan_method", editable=False),
    ]
    return Section(
        key="devices", label="Devices",
        hint="S=escanear · A=agregar · M=método · R=remover · Enter=editar · ↑↓=navegar",
        content_lines=content, actions=[], field_map=field_map,
    )


DEVICES_SECTION: Section = build_devices_section()
