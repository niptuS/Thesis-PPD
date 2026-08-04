"""
Entrada: None
Salida: Section
Descripción: Builds the Devices section showing scan settings and the registered
             network nodes table, with a detail view for the selected device.
"""
from __future__ import annotations
from design.models import Section, FieldMeta
from modules.i18n import t

PAGE_SIZE = 10
DEVICE_ROLES = ["target", "benign", "attacker", "unknown"]


def _detail_fields():
    return [
        ("role", t('devices', 'role')),
        ("tags", t('devices', 'tags')),
        ("hostname", t('devices', 'hostname')),
        ("notes", t('devices', 'notes')),
        ("device_type", t('devices', 'device_type')),
    ]


def _display_id(d):
    return d.hostname or d.ip.replace(".", "_")


def _build_device_table(devices, page=0, device_cursor=0):
    lines = []
    header = f"  {'':2} {t('devices', 'col_id'):<18} {t('devices', 'col_type'):<10} {t('devices', 'col_role'):<10} {t('devices', 'col_ip'):<16} {t('devices', 'col_vendor'):<14} {t('devices', 'col_st'):<6}"
    lines.append(header)
    lines.append("  " + "─" * (len(header) - 2))
    if not devices:
        lines.append(f"     {t('devices', 'empty')}")
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
        lines.append(f"  {t('common', 'page')} {page + 1}/{total_pages}  ({start + 1}-{end} {t('common', 'of')} {total})    ◄ PgUp  PgDn ►")
    else:
        lines.append(f"  {total} {t('devices', 'count')}")
    return lines


def _build_selected_detail(device, detail_cursor=-1):
    fields = []
    vals = {
        "role": device.role,
        "tags": " ".join(device.tags) if device.tags else "—",
        "hostname": device.hostname or "—",
        "notes": device.notes or "—",
        "device_type": device.device_type,
    }
    for i, (attr, label) in enumerate(_detail_fields()):
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
        f"─── {t('devices', 'scan_settings')} ────────────────────────────────────",
        f"  {t('devices', 'interface'):<12}: {scan_iface or t('devices', 'not_set_ctrl_n')}",
        f"  {t('devices', 'scan_cidr'):<12}: {scan_cidr}",
        f"  {t('devices', 'scan_method'):<12}: {scan_method}   [nmap | arp | all]",
        f"  {t('devices', 'last_scan'):<12}: {last_scan}",
        "",
        f"─── {t('devices', 'registered_nodes')} ─────────────────────────────────",
    ]
    content.extend(_build_device_table(device_list, page, device_cursor))
    if selected is not None:
        content.append("")
        sel_id = _display_id(selected)
        content.append(f"─── {sel_id} ─────────────────────────────────────")
        ports_str = ", ".join(str(p.port) for p in selected.open_ports) if selected.open_ports else "—"
        protos = " ".join(dict.fromkeys(p.protocol for p in selected.open_ports if p.protocol)
                          ) if selected.open_ports else "—"
        content.append(f"  {t('devices', 'lbl_ip')}: {selected.ip}  {t('devices', 'lbl_mac')}: {selected.mac or '—'}  {t('devices', 'lbl_ports')}: {ports_str}  {t('devices', 'lbl_proto')}: {protos}")
        content.append(
            f"  {t('devices', 'lbl_vendor')}: {selected.vendor or '—'}  {t('devices', 'lbl_iot_score')}: {selected.iot_score}  {t('devices', 'lbl_status')}: {selected.status}")
        content.append("")
        content.append(f"  ── {t('devices', 'editable_fields')} ──")
        content.extend(_build_selected_detail(selected, detail_cursor))

    field_map = [
        FieldMeta(line_idx=1, label=t('devices', 'interface'), attr_path="capture_iface", editable=False),
        FieldMeta(line_idx=2, label=t('devices', 'scan_cidr'), attr_path="scan_cidr", editable=True),
        FieldMeta(line_idx=3, label=t('devices', 'scan_method'), attr_path="scan_method", editable=False),
    ]
    return Section(
        key="devices", label=t("menu", "devices"),
        hint=t("devices", "hint_default"),
        content_lines=content, actions=[], field_map=field_map,
    )


DEVICES_SECTION: Section = build_devices_section()
