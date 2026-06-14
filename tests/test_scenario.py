"""Tests for scenario configuration schema."""
import unittest
from modules.scenario_editor.config_schema import (
    ScenarioConfig, OutputConfig, AttackerConfig,
)


class TestScenarioConfig(unittest.TestCase):
    def test_default_config(self):
        cfg = ScenarioConfig()
        self.assertEqual(cfg.name, "")
        self.assertEqual(cfg.experiment_id, "EXP")
        self.assertEqual(cfg.start_time, "00:00:00")
        self.assertEqual(cfg.schema_version, "1.0")

    def test_output_config(self):
        out = OutputConfig()
        self.assertTrue(out.capture_enabled)
        self.assertTrue(out.export_pcap)
        self.assertEqual(out.folder, "./data")

    def test_attacker_config(self):
        atk = AttackerConfig()
        self.assertEqual(atk.mode, "local")
        self.assertEqual(atk.ssh_user, "kali")
        self.assertEqual(atk.ssh_port, 22)

    def test_full_config(self):
        cfg = ScenarioConfig(
            name="Test Scenario",
            experiment_id="EXP_001",
            environment="lab",
            start_time="10:00:00",
            planned_duration="00:30:00",
            output=OutputConfig(folder="./output"),
            attacker=AttackerConfig(mode="ssh", ip="10.0.0.50"),
        )
        self.assertEqual(cfg.name, "Test Scenario")
        self.assertEqual(cfg.attacker.ip, "10.0.0.50")


if __name__ == "__main__":
    unittest.main()
