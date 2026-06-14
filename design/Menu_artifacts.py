"""Artifacts — browse capture files + view PCAP/CSV contents."""
from __future__ import annotations
from design.models import Section

PAGE_SIZE = 18


def build_artifacts_section(
    files=None, file_cursor=0,
    view_mode="files",
    packets=None, packet_cursor=0, packet_page=0,
    csv_headers=None, csv_rows=None, csv_cursor=0, csv_page=0,
    current_file="", error="",
) -> Section:
    content = []

    if view_mode == "files":
        content.append("─── Capture Files ────────────────────────────────────")
        fl = files or []
        if not fl:
            content.append("  (sin archivos — ejecute un escenario primero)")
        else:
            content.append(f"  {'':2} {'Archivo':<35} {'Tipo':<6} {'Tamaño':<10}")
            content.append("  " + "─" * 55)
            for i, f in enumerate(fl):
                marker = "►" if i == file_cursor else " "
                content.append(f"  {marker} {f['name']:<35} {f['type']:<6} {f['size_str']}")

    elif view_mode == "packets":
        content.append(f"─── {current_file} ─────────────────────────────")
        pkt = packets or []
        if error:
            content.append(f"  Error: {error}")
        elif not pkt:
            content.append("  (sin paquetes)")
        else:
            content.append(
                f"  {'':2} {'#':<6} {'Time':<9} {'Source':<16} {'Dest':<16} {'Proto':<7} {'Len':<6} {'Ports':<12} {'Flags'}")
            content.append("  " + "─" * 80)
            total = len(pkt)
            tp = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
            pg = min(packet_page, tp - 1)
            s, e = pg * PAGE_SIZE, min((pg + 1) * PAGE_SIZE, total)
            for i, p in enumerate(pkt[s:e]):
                marker = "►" if s + i == packet_cursor else " "
                ports = f"{p.src_port}→{p.dst_port}" if p.src_port else ""
                content.append(
                    f"  {marker} {p.no:<6} {p.time:<9} {p.src_ip:<16} {p.dst_ip:<16} {p.protocol:<7} {p.length:<6} {ports:<12} {p.flags[:10]}")
            if tp > 1:
                content.append(f"  Pág {pg+1}/{tp} ({s+1}-{e} de {total})")

    elif view_mode == "csv":
        content.append(f"─── {current_file} ─────────────────────────────")
        headers = csv_headers or []
        rows = csv_rows or []
        if error:
            content.append(f"  Error: {error}")
        elif not rows:
            content.append("  (sin datos)")
        else:
            key_cols = ["src_ip", "dst_ip", "ip.src", "ip.dst", "src_role",
                        "dst_role", "flow_label", "Protocol", "frame.len"]
            ci = [headers.index(k) for k in key_cols if k in headers]
            if not ci:
                ci = list(range(min(7, len(headers))))
            dh = [headers[i].split(".")[-1][:13] for i in ci]
            content.append("  " + " ".join(f"{h:<14}" for h in dh))
            content.append("  " + "─" * (15 * len(dh)))
            total = len(rows)
            tp = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
            pg = min(csv_page, tp - 1)
            s, e = pg * PAGE_SIZE, min((pg + 1) * PAGE_SIZE, total)
            for i, row in enumerate(rows[s:e]):
                marker = "►" if s + i == csv_cursor else " "
                vals = [(row[j][:13] if j < len(row) else "") for j in ci]
                content.append(f"  {marker} " + " ".join(f"{v:<14}" for v in vals))
            if tp > 1:
                content.append(f"  Pág {pg+1}/{tp} ({s+1}-{e} de {total})")

    hint = "Enter=abrir · R=refrescar · ↑↓=navegar" if view_mode == "files" else "Esc=volver · ↑↓·PgUp/PgDn=navegar"
    return Section(key="artifacts", label="Artifacts", hint=hint,
                   content_lines=content, actions=[], field_map=[])


ARTIFACTS_SECTION = build_artifacts_section()
