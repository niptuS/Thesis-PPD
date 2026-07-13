"""Tests for Cyber Kill Chain classification in attacks."""
import unittest
from modules.attacks import ATTACK_LIBRARY, get_attack_class, get_plugin_attacks


class TestKillChainMapping(unittest.TestCase):
    def test_all_attacks_have_kill_chain(self):
        for atk in ATTACK_LIBRARY:
            self.assertTrue(atk.kill_chain, f"{atk.name} missing kill_chain")
            self.assertTrue(atk.subcategory, f"{atk.name} missing subcategory")

    def test_valid_kill_chain_phases(self):
        valid = {
            "Reconnaissance", "Weaponization", "Delivery",
            "Exploitation", "Initial Access", "Installation",
            "Command and Control", "Actions on Objectives",
        }
        for atk in ATTACK_LIBRARY:
            self.assertIn(atk.kill_chain, valid, f"{atk.name}: invalid phase '{atk.kill_chain}'")

    def test_recon_attacks(self):
        for name in ["port_scan", "vuln_scan", "os_detection"]:
            atk = get_attack_class(name)
            self.assertEqual(atk.kill_chain, "Reconnaissance")

    def test_dos_attacks(self):
        for name in ["syn_flood", "udp_flood", "icmp_flood", "tcp_flood", "dos_http"]:
            atk = get_attack_class(name)
            self.assertEqual(atk.kill_chain, "Actions on Objectives")
            self.assertEqual(atk.subcategory, "denial_of_service")

    def test_mitm_attacks(self):
        for name in ["arp_spoof", "arp_spoof_ettercap"]:
            atk = get_attack_class(name)
            self.assertEqual(atk.kill_chain, "Command and Control")

    def test_brute_force_attacks(self):
        for name in ["brute_ssh", "brute_http", "brute_telnet"]:
            atk = get_attack_class(name)
            self.assertEqual(atk.kill_chain, "Initial Access")
            self.assertEqual(atk.subcategory, "brute_force")

    def test_continuous_flag(self):
        continuous = ["syn_flood", "udp_flood", "icmp_flood", "tcp_flood",
                      "dos_http", "arp_spoof", "arp_spoof_ettercap",
                      "mqtt_flood", "ping_flood", "coap_flood", "deauth_wifi"]
        for name in continuous:
            atk = get_attack_class(name)
            self.assertTrue(atk.continuous, f"{name} should be continuous")
        non_continuous = ["port_scan", "vuln_scan", "os_detection",
                         "brute_ssh", "brute_http", "brute_telnet"]
        for name in non_continuous:
            atk = get_attack_class(name)
            self.assertFalse(atk.continuous, f"{name} should NOT be continuous")


class TestPluginAttacks(unittest.TestCase):
    def test_plugins_load(self):
        plugins = get_plugin_attacks()
        self.assertIsInstance(plugins, list)

    def test_plugin_has_kill_chain(self):
        plugins = get_plugin_attacks() or []
        for p in plugins:
            if p.name == "scapy_syn_flood":
                self.assertEqual(p.kill_chain, "Actions on Objectives")
                self.assertEqual(p.subcategory, "denial_of_service")


if __name__ == "__main__":
    unittest.main()
