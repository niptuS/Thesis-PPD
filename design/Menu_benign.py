from design.Menu_types import Section

BENIGN_SECTION = Section(
    key="benign",
    label="Benign Profiles",
    hint="Activa patrones de tráfico benigno base. Space=toggle · Enter=editar · C=clonar · N=nuevo",
    content_lines=[
        "─── Available Profiles ───────────────────────────",
        "",
        "  [x] camera_stream_low      1 camera / periodic upload",
        "  [x] smartplug_telemetry    2 plugs  / 30s heartbeat",
        "  [x] bulb_state_updates     3 bulbs  / event driven",
        "  [ ] alexa_interactions     user commands / sporadic",
        "",
        "─── Selected: camera_stream_low ──────────────────",
        "",
        "  Device class : camera",
        "  Protocol     : RTSP / HTTP",
        "  Rate         : 1 stream",
        "  Duration     : 00:45:00",
        "  Start offset : 00:00:00",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [Space] Toggle    [Enter] Edit    [C] Clone    [N] New",
    ],
    actions=["Space Toggle", "Enter Edit", "C Clone", "N New"],
)