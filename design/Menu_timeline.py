from design.Menu_types import Section

TIMELINE_SECTION = Section(
    key="timeline",
    label="Timeline",
    hint="Organiza eventos por tiempo y actor. A=agregar · E=editar · M=mover · X=eliminar",
    content_lines=[
        "─── Scheduled Events ─────────────────────────────",
        "",
        "  Time       Type      Source      Target        Status",
        "  10:00:00   benign    echo01      smartbulb01   queued",
        "  10:00:00   benign    camera01    network       queued",
        "  10:05:00   attack    kalivm      camera01      queued",
        "  10:12:00   benign    echo01      smartplug01   queued",
        "  10:15:00   attack    kalivm      smartplug01   queued",
        "",
        "─── Selected Event ───────────────────────────────",
        "",
        "  Timestamp   : 10:05:00",
        "  Event type  : attack",
        "  Action      : DoS HTTP Flood",
        "  Notes       : attack after baseline warmup",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [A] Add    [E] Edit    [M] Move    [X] Delete",
    ],
    actions=["A Add", "E Edit", "M Move", "X Delete"],
)