from design.Menu_types import Section

ARTIFACTS_SECTION = Section(
    key="artifacts",
    label="Artifacts",
    hint="Revisa y exporta PCAP, metadatos y logs de cada ejecución. Enter=info · E=exportar · C=checksum",
    content_lines=[
        "─── Generated Files ──────────────────────────────",
        "",
        "  Name                    Type      Size      Status",
        "  exp-011-run03.pcap      PCAP      428 MB    complete",
        "  exp-011-run03.json      metadata   18 KB    complete",
        "  exp-011-run03.log       log        74 KB    complete",
        "  exp-011-run03.flows.csv flow        2.3 MB  optional",
        "",
        "─── Selected: exp-011-run03.json ─────────────────",
        "",
        "  Schema version : 1.0",
        "  Start time     : 2026-05-12T10:00:00Z",
        "  Events         : 12",
        "  Exportable     : yes",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [Enter] Open info    [E] Export    [C] Checksum",
    ],
    actions=["Enter Open info", "E Export", "C Checksum"],
)