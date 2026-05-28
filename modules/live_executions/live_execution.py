from modules.artifacts import ArtifactManager
from datetime import datetime, timezone

manager = ArtifactManager(
    output_dir         = "outputs/exp-011",
    experiment_id      = "EXP-2026-05-011",
    run_id             = "run03",
    environment        = "SmartHomeLab-v1",
    scenario_name      = "SmartHome Mixed Traffic Morning",
    scenario_start     = datetime(2026, 5, 11, 10, 0, 0, tzinfo=timezone.utc),
    planned_duration_s = 2700,
    capture_interface  = "eth0",
)

manager.start_capture()

manager.record_event(
    event_ts       = datetime(2026, 5, 11, 10, 5, 0, tzinfo=timezone.utc),
    event_kind     = "attack",
    source_node    = "kalivm",
    source_ip      = "192.168.1.50",
    source_mac     = "AA:BB:CC:DD:EE:06",
    target_node    = "camera01",
    target_ip      = "192.168.1.30",
    target_mac     = "AA:BB:CC:DD:EE:03",
    protocol       = "HTTP",
    action         = "dos_http_flood",
    label          = "DoS",
    mitre_technique    = "T1498",
    mitre_subtechnique = "T1498.001",
    attack_intensity   = "medium",
    duration_s         = 180.0,
    notes              = "attack after baseline warmup",
)

checksums = manager.finalize()