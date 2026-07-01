"""Tests for attack library and tool verification."""
import unittest
from unittest.mock import patch
from modules.attacks import (
    ATTACK_LIBRARY, get_attack_names, get_attack_class,
    get_attack_info_list,
)
from modules.attacks.base import AttackDef, AttackResult, check_tool_local


class TestAttackLibrary(unittest.TestCase):
    def test_library_not_empty(self):
        self.assertGreater(len(ATTACK_LIBRARY), 0)

    def test_all_have_required_fields(self):
        for atk in ATTACK_LIBRARY:
            self.assertIsInstance(atk, AttackDef)
            self.assertTrue(atk.name, "Attack missing name")
            self.assertTrue(atk.tool, f"{atk.name} missing tool")
            self.assertTrue(atk.command, f"{atk.name} missing command")
            self.assertTrue(atk.description, f"{atk.name} missing description")
            self.assertTrue(atk.mitre_ref, f"{atk.name} missing MITRE re")
            self.assertTrue(atk.category, f"{atk.name} missing category")

    def test_unique_names(self):
        names = get_attack_names()
        self.assertEqual(len(names), len(set(names)), "Duplicate attack names")

    def test_get_attack_class(self):
        atk = get_attack_class("syn_flood")
        self.assertIsNotNone(atk)
        self.assertEqual(atk.name, "syn_flood")
        self.assertEqual(atk.tool, "hping3")

    def test_get_nonexistent_attack(self):
        self.assertIsNone(get_attack_class("nonexistent"))

    def test_recommended_duration(self):
        for atk in ATTACK_LIBRARY:
            self.assertGreater(atk.recommended_dur_s, 0,
                               f"{atk.name} has no recommended duration")

    def test_requires_root_field(self):
        syn = get_attack_class("syn_flood")
        self.assertTrue(syn.requires_root)
        port = get_attack_class("port_scan")
        self.assertFalse(port.requires_root)

    def test_build_command(self):
        atk = get_attack_class("syn_flood")
        cmd = atk.build_command(target_ip="10.0.0.1", port=8080, duration=60)
        self.assertIn("10.0.0.1", cmd)
        self.assertIn("8080", cmd)

    def test_get_attack_info_list(self):
        info = get_attack_info_list()
        self.assertGreater(len(info), 0)
        for item in info:
            self.assertIn("name", item)
            self.assertIn("tool", item)
            self.assertIn("mitre_ref", item)

    def test_categories_exist(self):
        categories = set(a.category for a in ATTACK_LIBRARY)
        self.assertIn("dos", categories)
        self.assertIn("recon", categories)
        self.assertIn("brute_force", categories)


class TestAttackResult(unittest.TestCase):
    def test_success_result(self):
        r = AttackResult(success=True, packets=100, duration=5.0)
        self.assertTrue(r.success)
        self.assertEqual(r.packets, 100)

    def test_failure_result(self):
        r = AttackResult(success=False, error="timeout")
        self.assertFalse(r.success)
        self.assertEqual(r.error, "timeout")


class TestToolVerification(unittest.TestCase):
    @patch("shutil.which")
    def test_check_tool_local_found(self, mock_which):
        mock_which.return_value = "/usr/bin/nmap"
        self.assertTrue(check_tool_local("nmap"))

    @patch("shutil.which")
    def test_check_tool_local_not_found(self, mock_which):
        mock_which.return_value = None
        self.assertFalse(check_tool_local("nonexistent_tool"))


if __name__ == "__main__":
    unittest.main()
