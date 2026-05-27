from design.Menu_types import Section

DEVICES_SECTION = Section(
    key="devices",
    label="Devices",
    hint="Registra nodos IoT y asigna roles. A=agregar · E=editar · R=remover · T=etiquetar",
    content_lines=[
        "─── Registered Nodes ─────────────────────────────",
        "",
        "  ID            Role         IP             Status",
        "  smartbulb01   target       192.168.1.10   online",
        "  smartbulb02   target       192.168.1.11   online",
        "  smartplug01   target       192.168.1.20   online",
        "  camera01      target       192.168.1.30   online",
        "  echo01        benign       192.168.1.40   online",
        "  kalivm        attacker     192.168.1.50   ready",
        "",
        "─── Selected Node: smartbulb01 ───────────────────",
        "",
        "  MAC       : AA:BB:CC:DD:EE:01",
        "  Protocols : HTTP, MQTT",
        "  Tags      : bulb, kitchen, wifi",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [A] Add    [E] Edit    [R] Remove    [T] Tag",
    ],
    actions=["A Add", "E Edit", "R Remove", "T Tag"],
)