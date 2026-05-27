from design.Menu_types import Section

LOGS_SECTION = Section(
    key="logs",
    label="Logs",
    hint="Eventos en orden temporal. /=buscar · F=filtrar · E=exportar slice",
    content_lines=[
        "─── Live Event Stream ────────────────────────────",
        "",
        "  10:00:00 INFO  scenario started",
        "  10:00:01 INFO  capture started on capturenode",
        "  10:00:03 INFO  benign profile camera_stream_low executed",
        "  10:05:00 INFO  attack module DoS HTTP Flood started",
        "  10:05:01 INFO  source=kalivm target=camera01",
        "  10:08:00 INFO  attack module DoS HTTP Flood ended",
        "  10:12:00 INFO  benign interaction smartplug01",
        "  10:16:20 WARN  transient packet drop observed",
        "  10:16:21 INFO  capture stabilized",
        "",
        "─── Filters ──────────────────────────────────────",
        "",
        "  [All]  [Info]  [Warn]  [Error]  [Attack]",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [/] Search    [F] Filter    [E] Export slice",
    ],
    actions=["/ Search", "F Filter", "E Export slice"],
)