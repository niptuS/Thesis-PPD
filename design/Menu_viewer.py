"""
Entrada: None
Salida: Section
Descripción: Capture Viewer — browse and inspect PCAP/CSV files.
"""
from __future__ import annotations
from design.models import Section
from modules.i18n import t

PAGE_SIZE = 20


"""
Entrada: files, file_cursor, view_mode, packets, packet_cursor, packet_page,
         csv_headers, csv_rows, csv_cursor, csv_page, current_file, error
Salida: Section
Descripción: Builds the viewer section with localized labels and hints.
"""
def build_viewer_section(
    files=None, file_cursor=0,
    view_mode="files",
    packets=None, packet_cursor=0, packet_page=0,
    csv_headers=None, csv_rows=None, csv_cursor=0, csv_page=0,
    current_file="",
    error="",
) -> Section:
    content = []

    if view_mode == "files":
        content.append("─── Capture Files ────────────────────────────────────")
        file_list = files or []
        if not file_list:
            content.append(f"  {t('artifacts', 'no_files_run')}")
            content.append(f"  {t('artifacts', 'looking_in')} data/")
        else:
            content.append(f"  {'':2} {t('artifacts', 'file'):<35} {t('artifacts', 'type'):<6} {t('artifacts', 'size'):<10}")
            content.append("  " + "─" * 55)
            for i, f in enumerate(file_list):
                marker = "►" if i == file_cursor else " "
                content.append(f"  {marker} {f['name']:<35} {f['type']:<6} {f['size_str']}")

    elif view_mode == "packets":
        content.append(f"─── {current_file} ─────────────────────────────")
        pkt_list = packets or []
        if error:
            content.append(f"  Error: {error}")
        elif not pkt_list:
            content.append(f"  {t('artifacts', 'no_packets')}")
        else:
            content.append(
                f"  {'':2} {'#':<6} {'Time':<9} {'Source':<16} {'Dest':<16} {'Proto':<7} {'Len':<6} {'Ports':<12} {'Flags':<10}")
            content.append("  " + "─" * 85)
            total = len(pkt_list)
            total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
            page = min(packet_page, total_pages - 1)
            start = page * PAGE_SIZE
            end = min(start + PAGE_SIZE, total)
            for i, p in enumerate(pkt_list[start:end]):
                abs_idx = start + i
                marker = "►" if abs_idx == packet_cursor else " "
                ports = f"{p.src_port}→{p.dst_port}" if p.src_port else ""
                flags = p.flags[:9] if p.flags else ""
                content.append(
                    f"  {marker} {p.no:<6} {p.time:<9} {p.src_ip:<16} {p.dst_ip:<16} "
                    f"{p.protocol:<7} {p.length:<6} {ports:<12} {flags}"
                )
            if total_pages > 1:
                content.append(f"  {t('artifacts', 'page')} {page+1}/{total_pages} ({start+1}-{end} of {total})")

    elif view_mode == "csv":
        content.append(f"─── {current_file} ─────────────────────────────")
        headers = csv_headers or []
        rows = csv_rows or []
        if error:
            content.append(f"  Error: {error}")
        elif not rows:
            content.append(f"  {t('artifacts', 'no_data')}")
        else:
            key_cols = ["src_ip", "dst_ip", "ip.src", "ip.dst", "src_role", "dst_role", "flow_label",
                        "_ws.col.Protocol", "frame.len", "tcp.flags.str"]
            col_indices = []
            display_headers = []
            for kc in key_cols:
                if kc in headers:
                    col_indices.append(headers.index(kc))
                    display_headers.append(kc.split(".")[-1][:12])
            if not col_indices:
                col_indices = list(range(min(8, len(headers))))
                display_headers = [h[:12] for h in headers[:8]]

            header_line = "  " + " ".join(f"{h:<14}" for h in display_headers)
            content.append(header_line)
            content.append("  " + "─" * (len(header_line) - 2))

            total = len(rows)
            total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
            page = min(csv_page, total_pages - 1)
            start = page * PAGE_SIZE
            end = min(start + PAGE_SIZE, total)
            for i, row in enumerate(rows[start:end]):
                abs_idx = start + i
                marker = "►" if abs_idx == csv_cursor else " "
                vals = []
                for ci in col_indices:
                    v = row[ci] if ci < len(row) else ""
                    vals.append(v[:13])
                content.append(f"  {marker} " + " ".join(f"{v:<14}" for v in vals))
            if total_pages > 1:
                content.append(f"  {t('artifacts', 'page')} {page+1}/{total_pages} ({start+1}-{end} of {total})")

    content.append("")
    if view_mode == "files":
        hint = t("artifacts", "hint_files")
    else:
        hint = t("artifacts", "hint_detail")

    return Section(
        key="viewer", label="Capture Viewer",
        hint=hint, content_lines=content, actions=[], field_map=[],
    )


VIEWER_SECTION = build_viewer_section()
