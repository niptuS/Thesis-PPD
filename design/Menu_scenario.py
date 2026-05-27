from dataclasses import dataclass, field
from design.Menu_types import Section

SCENARIO_SECTION = Section(
    key="scenario",
    label="Scenario Editor",
    hint="Define identidad, duración y salidas del experimento. Enter=editar · A=agregar · D=eliminar · Ctrl+S=guardar",
    content_lines=[
        "─── Scenario Configuration ───────────────────────",
        "",
        "  Name              : SmartHome Mixed Traffic Morning",
        "  Experiment ID     : EXP-2026-05-011",
        "  Environment       : SmartHomeLab-v1",
        "  Start time        : 2026-05-11 10:00:00",
        "  Planned duration  : 00:45:00",
        "  Output folder     : /data/experiments/exp-011",
        "",
        "─── Output settings ──────────────────────────────",
        "",
        "  Capture enabled   : [x]",
        "  Metadata export   : [x] JSON",
        "  PCAP export       : [x]",
        "",
        "─── Actions ──────────────────────────────────────",
        "",
        "  [Enter] Edit field    [A] Add field    [D] Delete field",
        "  [Ctrl+S] Save         [Esc] Back to Home",
    ],
    actions=["Enter Edit field", "A Add field", "D Delete field", "Ctrl+S Save", "Esc Back"],
)