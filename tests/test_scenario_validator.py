"""Comprehensive tests for the scenario validator."""
import json
import os
import tempfile
import unittest

from modules.scenario_editor.config_validator import (
    validate_scenario_data,
    validate_scenario,
    VALID_SCAN_METHODS,
    VALID_ROLES,
    VALID_EVENT_TYPES,
    VALID_ATTACKER_MODES,
    VALID_PROTOCOLS,
)
from modules.scenario_editor.config_loader import load_scenario, ConfigLoadError
from modules.scenario_editor.config_schema import (
    ScenarioConfig, OutputConfig, AttackerConfig,
)


def _base_valid_scenario() -> dict:
    """Returns a minimal valid scenario dict that all tests can mutate."""
    return {
        "scenario": {
            "name": "Test Scenario",
            "experiment_id": "EXP_001",
            "environment": "lab",
            "start_time": "08:00:00",
            "planned_duration": "01:00:00",
            "scan_cidr": "192.168.1.0/24",
            "scan_method": "nmap",
            "capture_iface": "eth0",
            "pcap_max_size_kb": 512000,
            "output": {
                "folder": "outputs/metadata",
                "capture_enabled": True,
                "export_pcap": True,
                "export_metadata": True,
                "export_benign": True,
            },
            "attacker": {
                "mode": "local",
                "ip": "",
                "ssh_user": "kali",
                "ssh_port": 22,
                "ssh_key": "",
            },
        },
        "devices": [
            {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "role": "target"},
            {"ip": "192.168.1.20", "mac": "", "role": "attacker"},
        ],
        "timeline": [
            {"event_id": "e1", "offset_s": 60, "event_type": "attack",
             "action": "syn_flood", "source": "192.168.1.20",
             "target": "192.168.1.10", "duration_s": 30,
             "label": "syn_flood", "status": "queued", "scheduled_dt": ""},
        ],
        "attackers": [
            {"device_ip": "192.168.1.20", "tag": "kali", "mode": "local",
             "ssh_user": "kali", "ssh_port": 22, "ssh_key": ""},
        ],
        "benign_profiles": [],
    }


class TestValidatorBasics(unittest.TestCase):

    def test_valid_scenario_has_no_errors(self):
        errors = validate_scenario_data(_base_valid_scenario())
        self.assertEqual(errors, [], f"Expected no errors, got: {errors}")

    def test_non_dict_input(self):
        errors = validate_scenario_data([1, 2, 3])
        self.assertEqual(len(errors), 1)
        self.assertIn("must be a JSON object", errors[0])


class TestScenarioSectionValidation(unittest.TestCase):

    def test_invalid_scan_method_rejected(self):
        """The user's specific complaint: scan_method='par' was accepted."""
        data = _base_valid_scenario()
        data["scenario"]["scan_method"] = "par"
        errors = validate_scenario_data(data)
        self.assertTrue(any("scan_method" in e for e in errors),
                        f"Expected scan_method error, got: {errors}")
        self.assertTrue(any("'par'" in e for e in errors))

    def test_invalid_scan_cidr_rejected(self):
        data = _base_valid_scenario()
        data["scenario"]["scan_cidr"] = "not-a-cidr"
        errors = validate_scenario_data(data)
        self.assertTrue(any("scan_cidr" in e for e in errors))

    def test_invalid_start_time_rejected(self):
        data = _base_valid_scenario()
        data["scenario"]["start_time"] = "8:00"
        errors = validate_scenario_data(data)
        self.assertTrue(any("start_time" in e for e in errors))

    def test_invalid_planned_duration_rejected(self):
        data = _base_valid_scenario()
        data["scenario"]["planned_duration"] = "1h30m"
        errors = validate_scenario_data(data)
        self.assertTrue(any("planned_duration" in e for e in errors))

    def test_planned_duration_accepts_suffixed_format(self):
        data = _base_valid_scenario()
        data["scenario"]["planned_duration"] = "30m"
        errors = validate_scenario_data(data)
        # 30m is a valid suffixed duration
        self.assertFalse(any("planned_duration" in e for e in errors),
                         f"30m should be valid, got: {errors}")

    def test_pcap_max_size_must_be_positive_int(self):
        data = _base_valid_scenario()
        data["scenario"]["pcap_max_size_kb"] = 0
        errors = validate_scenario_data(data)
        self.assertTrue(any("pcap_max_size_kb" in e for e in errors))

    def test_pcap_max_size_rejects_string(self):
        data = _base_valid_scenario()
        data["scenario"]["pcap_max_size_kb"] = "512000"
        errors = validate_scenario_data(data)
        self.assertTrue(any("pcap_max_size_kb" in e for e in errors))

    def test_attacker_ssh_requires_ip(self):
        data = _base_valid_scenario()
        data["scenario"]["attacker"]["mode"] = "ssh"
        data["scenario"]["attacker"]["ip"] = ""
        errors = validate_scenario_data(data)
        self.assertTrue(any("attacker.ip" in e and "mode='ssh'" in e for e in errors))

    def test_attacker_ssh_invalid_ip(self):
        data = _base_valid_scenario()
        data["scenario"]["attacker"]["mode"] = "ssh"
        data["scenario"]["attacker"]["ip"] = "999.999.999.999"
        errors = validate_scenario_data(data)
        self.assertTrue(any("attacker.ip" in e for e in errors))

    def test_attacker_invalid_mode(self):
        data = _base_valid_scenario()
        data["scenario"]["attacker"]["mode"] = "ftp"
        errors = validate_scenario_data(data)
        self.assertTrue(any("attacker.mode" in e for e in errors))

    def test_attacker_invalid_ssh_port(self):
        data = _base_valid_scenario()
        data["scenario"]["attacker"]["ssh_port"] = 99999
        errors = validate_scenario_data(data)
        self.assertTrue(any("ssh_port" in e for e in errors))

    def test_missing_required_field(self):
        data = _base_valid_scenario()
        del data["scenario"]["name"]
        errors = validate_scenario_data(data)
        self.assertTrue(any("scenario.name" in e and "missing" in e for e in errors))

    def test_empty_name_rejected(self):
        data = _base_valid_scenario()
        data["scenario"]["name"] = "   "
        errors = validate_scenario_data(data)
        self.assertTrue(any("scenario.name" in e for e in errors))

    def test_output_folder_empty_rejected(self):
        data = _base_valid_scenario()
        data["scenario"]["output"]["folder"] = ""
        errors = validate_scenario_data(data)
        self.assertTrue(any("output.folder" in e for e in errors))


class TestDevicesValidation(unittest.TestCase):

    def test_invalid_role_rejected(self):
        """The user's specific complaint: role='exploit' was accepted."""
        data = _base_valid_scenario()
        data["devices"][0]["role"] = "exploit"
        errors = validate_scenario_data(data)
        self.assertTrue(any("role" in e and "'exploit'" in e for e in errors),
                        f"Expected role error, got: {errors}")

    def test_invalid_ip_rejected(self):
        data = _base_valid_scenario()
        data["devices"][0]["ip"] = "999.1.1.1"
        errors = validate_scenario_data(data)
        self.assertTrue(any("ip" in e for e in errors))

    def test_duplicate_ip_rejected(self):
        data = _base_valid_scenario()
        data["devices"].append({
            "ip": "192.168.1.10", "mac": "", "role": "target",
        })
        errors = validate_scenario_data(data)
        self.assertTrue(any("duplicate" in e.lower() for e in errors))

    def test_invalid_mac_rejected(self):
        data = _base_valid_scenario()
        data["devices"][0]["mac"] = "not-a-mac"
        errors = validate_scenario_data(data)
        self.assertTrue(any("mac" in e.lower() for e in errors))

    def test_empty_mac_allowed(self):
        data = _base_valid_scenario()
        data["devices"][0]["mac"] = ""
        errors = validate_scenario_data(data)
        self.assertFalse(any("mac" in e.lower() for e in errors),
                         f"Empty MAC should be allowed, got: {errors}")

    def test_invalid_device_type_rejected(self):
        data = _base_valid_scenario()
        data["devices"][0]["device_type"] = "spaceship"
        errors = validate_scenario_data(data)
        self.assertTrue(any("device_type" in e for e in errors))

    def test_invalid_port_in_open_ports(self):
        data = _base_valid_scenario()
        data["devices"][0]["open_ports"] = [
            {"port": 99999, "protocol": "http"}
        ]
        errors = validate_scenario_data(data)
        self.assertTrue(any("port" in e for e in errors))

    def test_iot_score_out_of_range(self):
        data = _base_valid_scenario()
        data["devices"][0]["iot_score"] = 200
        errors = validate_scenario_data(data)
        self.assertTrue(any("iot_score" in e for e in errors))


class TestTimelineValidation(unittest.TestCase):

    def test_invalid_event_type_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["event_type"] = "exploit"
        errors = validate_scenario_data(data)
        self.assertTrue(any("event_type" in e for e in errors))

    def test_invalid_status_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["status"] = "pending"
        errors = validate_scenario_data(data)
        self.assertTrue(any("status" in e for e in errors))

    def test_source_ip_not_in_devices_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["source"] = "10.0.0.99"
        errors = validate_scenario_data(data)
        self.assertTrue(any("source" in e and "not registered" in e for e in errors))

    def test_target_ip_not_in_devices_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["target"] = "10.0.0.99"
        errors = validate_scenario_data(data)
        self.assertTrue(any("target" in e and "not registered" in e for e in errors))

    def test_attack_action_not_in_library_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["action"] = "totally_made_up_attack"
        errors = validate_scenario_data(data)
        self.assertTrue(any("action" in e and "not a registered attack" in e for e in errors))

    def test_attack_source_must_be_attacker_role(self):
        data = _base_valid_scenario()
        # Make the source device have role=target instead of attacker
        data["devices"][1]["role"] = "target"
        errors = validate_scenario_data(data)
        self.assertTrue(
            any("source" in e and "role" in e and "attacker" in e for e in errors),
            f"Expected role-mismatch error, got: {errors}"
        )

    def test_negative_offset_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["offset_s"] = -5
        errors = validate_scenario_data(data)
        self.assertTrue(any("offset_s" in e for e in errors))

    def test_negative_duration_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["duration_s"] = -1
        errors = validate_scenario_data(data)
        self.assertTrue(any("duration_s" in e for e in errors))

    def test_invalid_scheduled_dt_rejected(self):
        data = _base_valid_scenario()
        data["timeline"][0]["scheduled_dt"] = "tomorrow at noon"
        errors = validate_scenario_data(data)
        self.assertTrue(any("scheduled_dt" in e for e in errors))

    def test_missing_action_rejected(self):
        data = _base_valid_scenario()
        del data["timeline"][0]["action"]
        errors = validate_scenario_data(data)
        self.assertTrue(any("action" in e for e in errors))


class TestAttackersValidation(unittest.TestCase):

    def test_attacker_ip_not_in_devices_rejected(self):
        data = _base_valid_scenario()
        data["attackers"].append({
            "device_ip": "10.0.0.99", "tag": "x", "mode": "local",
        })
        errors = validate_scenario_data(data)
        self.assertTrue(any("attackers" in e and "not registered" in e for e in errors))

    def test_attacker_invalid_mode_rejected(self):
        data = _base_valid_scenario()
        data["attackers"][0]["mode"] = "ftp"
        errors = validate_scenario_data(data)
        self.assertTrue(any("attackers" in e and "mode" in e for e in errors))

    def test_attacker_invalid_ssh_port(self):
        data = _base_valid_scenario()
        data["attackers"][0]["ssh_port"] = 0
        errors = validate_scenario_data(data)
        self.assertTrue(any("ssh_port" in e for e in errors))


class TestBenignProfilesValidation(unittest.TestCase):

    def test_profile_ip_not_in_devices_rejected(self):
        data = _base_valid_scenario()
        data["benign_profiles"].append({
            "profile_id": "p1", "device_type": "camera",
            "device_ip": "10.0.0.99", "protocol": "http", "port": 80,
            "actions": [],
        })
        errors = validate_scenario_data(data)
        self.assertTrue(any("benign_profiles" in e and "not registered" in e for e in errors))

    def test_profile_invalid_port(self):
        data = _base_valid_scenario()
        data["benign_profiles"].append({
            "profile_id": "p1", "device_type": "camera",
            "device_ip": "192.168.1.10", "protocol": "http", "port": 99999,
            "actions": [],
        })
        errors = validate_scenario_data(data)
        self.assertTrue(any("port" in e for e in errors))

    def test_profile_invalid_protocol(self):
        data = _base_valid_scenario()
        data["benign_profiles"].append({
            "profile_id": "p1", "device_type": "camera",
            "device_ip": "192.168.1.10", "protocol": "ftp", "port": 80,
            "actions": [],
        })
        errors = validate_scenario_data(data)
        self.assertTrue(any("protocol" in e for e in errors))

    def test_action_invalid_http_method(self):
        data = _base_valid_scenario()
        data["benign_profiles"].append({
            "profile_id": "p1", "device_type": "camera",
            "device_ip": "192.168.1.10", "protocol": "http", "port": 80,
            "actions": [
                {"action_id": "a1", "name": "x", "protocol": "http",
                 "method": "OPTIONS", "endpoint": "/", "payload": ""},
            ],
        })
        errors = validate_scenario_data(data)
        self.assertTrue(any("method" in e for e in errors))

    def test_action_invalid_mqtt_method(self):
        data = _base_valid_scenario()
        data["benign_profiles"].append({
            "profile_id": "p1", "device_type": "sensor",
            "device_ip": "192.168.1.10", "protocol": "mqtt", "port": 1883,
            "actions": [
                {"action_id": "a1", "name": "x", "protocol": "mqtt",
                 "method": "GET", "endpoint": "topic/x", "payload": ""},
            ],
        })
        errors = validate_scenario_data(data)
        self.assertTrue(any("method" in e for e in errors))

    def test_duplicate_profile_ip_rejected(self):
        data = _base_valid_scenario()
        for _ in range(2):
            data["benign_profiles"].append({
                "profile_id": "p1", "device_type": "camera",
                "device_ip": "192.168.1.10", "protocol": "http", "port": 80,
                "actions": [],
            })
        errors = validate_scenario_data(data)
        self.assertTrue(any("duplicate" in e.lower() for e in errors))


class TestLoaderIntegration(unittest.TestCase):

    def test_load_scenario_rejects_invalid_file(self):
        """The loader should raise ConfigLoadError for an invalid scenario."""
        data = _base_valid_scenario()
        data["scenario"]["scan_method"] = "par"  # invalid
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            with self.assertRaises(ConfigLoadError) as ctx:
                load_scenario(tmp_path)
            self.assertIn("validation failed", str(ctx.exception).lower())
            self.assertIn("scan_method", str(ctx.exception))
        finally:
            os.unlink(tmp_path)

    def test_load_scenario_accepts_valid_file(self):
        """The loader should accept a valid scenario without raising.
        Note: load_scenario uses the legacy schema (flat fields), not the
        UI's nested {scenario: {...}} format. We test both here."""
        # 1) Nested format (used by the UI's Ctrl+O) — must pass validation
        data = _base_valid_scenario()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            # Validation should pass
            errors = validate_scenario_data(data)
            self.assertEqual(errors, [], f"Expected no errors, got: {errors}")
        finally:
            os.unlink(tmp_path)

        # 2) Flat schema format (used by the legacy load_scenario function)
        flat_data = {
            "name": "Test Scenario",
            "experiment_id": "EXP_001",
            "environment": "lab",
            "start_time": "08:00:00",
            "planned_duration": "01:00:00",
            "output": {"folder": "./data"},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(flat_data, f)
            tmp_path = f.name
        try:
            cfg = load_scenario(tmp_path)
            self.assertEqual(cfg.name, "Test Scenario")
        finally:
            os.unlink(tmp_path)


class TestLegacyValidateScenario(unittest.TestCase):
    """Backwards compatibility: validate_scenario(ScenarioConfig) still works."""

    def test_default_config_valid(self):
        cfg = ScenarioConfig(
            name="Test", experiment_id="EXP_001",
            output=OutputConfig(folder="./data"),
        )
        errors = validate_scenario(cfg)
        # Default start_time=00:00:00, planned_duration=00:30:00 are valid
        self.assertEqual(errors, [])

    def test_invalid_role_in_dataclass(self):
        from modules.scenario_editor.config_schema import DeviceConfig
        cfg = ScenarioConfig(
            name="Test", experiment_id="EXP_001",
            devices=[DeviceConfig(id="d1", role="exploit",
                                   ip="192.168.1.1", mac="")],
            output=OutputConfig(folder="./data"),
        )
        errors = validate_scenario(cfg)
        self.assertTrue(any("role" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
