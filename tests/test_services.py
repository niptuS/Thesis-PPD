"""Tests for the 5 extracted services."""
import csv
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from modules.services import (
    CaptureService,
    EventExecutor,
    FlowExtractor,
    FlowLabeler,
    ArtifactManifestWriter,
)


class TestCaptureService(unittest.TestCase):

    def test_find_capture_tool_returns_string(self):
        tool = CaptureService.find_capture_tool()
        # On any system, returns either a path or empty string (never None)
        self.assertIsInstance(tool, str)

    def test_find_pcap_files_empty_path(self):
        result = CaptureService.find_pcap_files("")
        self.assertEqual(result, [])

    def test_find_pcap_files_nonexistent(self):
        result = CaptureService.find_pcap_files("/nonexistent/path.pcap")
        self.assertEqual(result, [])

    def test_find_pcap_files_single_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = os.path.join(tmp, "capture.pcap")
            with open(pcap_path, "wb") as f:
                f.write(b"\xd4\xc3\xb2\xa1")  # minimal pcap magic
            result = CaptureService.find_pcap_files(pcap_path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], pcap_path)

    def test_find_pcap_files_handles_rotation(self):
        """tcpdump -C creates base.pcap1, base.pcap2, ..."""
        with tempfile.TemporaryDirectory() as tmp:
            base_path = os.path.join(tmp, "capture.pcap")
            # Simulate rotated chunks created by tcpdump -C
            for i in (1, 2):
                rotated = f"{base_path}{i}"
                with open(rotated, "wb") as f:
                    f.write(b"\xd4\xc3\xb2\xa1")
            result = CaptureService.find_pcap_files(base_path)
            # Should find the 2 rotated files
            self.assertEqual(len(result), 2)

    def test_configure_sets_attributes(self):
        import os
        svc = CaptureService()
        svc.configure(iface="eth0", pcap_path=os.path.join(
            os.sep, "tmp", "test.pcap"),
                       pcap_max_size_kb=1024)
        self.assertEqual(svc._iface, "eth0")
        # configure() calls os.path.abspath, which normalises the path
        # differently on Windows vs Linux. Compare the basename + dir.
        self.assertTrue(svc._pcap_path.endswith("test.pcap"))
        self.assertEqual(svc._pcap_max_size_kb, 1024)

    def test_start_without_iface_logs_warning(self):
        logs = []
        svc = CaptureService(log_fn=lambda msg, lvl: logs.append((msg, lvl)))
        svc.configure(iface="", pcap_path="/tmp/test.pcap")
        svc.start()
        self.assertFalse(svc.capture_ok)
        self.assertTrue(any("interface" in m.lower() for m, _ in logs))


class TestEventExecutor(unittest.TestCase):

    def test_fire_benign_without_profile_logs_warning(self):
        logs = []
        ex = EventExecutor(log_fn=lambda msg, lvl: logs.append((msg, lvl)))
        ex.set_profiles([])  # no profiles
        ex.fire({
            "event_type": "benign", "action": "turn_on",
            "target": "192.168.1.99", "source": "192.168.1.1",
            "duration_s": 0, "label": "turn_on",
        })
        self.assertTrue(any("No benign profile" in m for m, _ in logs))

    def test_fire_attack_unknown_action_logs_error(self):
        logs = []
        ex = EventExecutor(log_fn=lambda msg, lvl: logs.append((msg, lvl)))
        ex.set_device_map({"192.168.1.1": "attacker", "192.168.1.2": "target"})
        ex.set_attacker_profiles({})
        ex.fire({
            "event_type": "attack", "action": "totally_made_up_attack",
            "target": "192.168.1.2", "source": "192.168.1.1",
            "duration_s": 0, "label": "fake",
        })
        self.assertTrue(any("not found" in m for m, _ in logs))

    def test_fire_sets_active_labels(self):
        ex = EventExecutor(log_fn=lambda msg, lvl: None)
        ex.set_profiles([])
        ex.fire({
            "event_type": "benign", "action": "turn_on",
            "target": "192.168.1.99", "source": "192.168.1.1",
            "duration_s": 0, "label": "my_benign_action",
        })
        self.assertEqual(ex.active_benign, "my_benign_action")

    def test_fire_attack_sets_active_attack_label(self):
        ex = EventExecutor(log_fn=lambda msg, lvl: None)
        ex.set_device_map({"192.168.1.1": "attacker", "192.168.1.2": "target"})
        ex.set_attacker_profiles({})
        ex.fire({
            "event_type": "attack", "action": "totally_made_up_attack",
            "target": "192.168.1.2", "source": "192.168.1.1",
            "duration_s": 0, "label": "my_attack",
        })
        self.assertEqual(ex.active_attack, "my_attack")


class TestFlowLabeler(unittest.TestCase):

    def test_classify_benign_flow(self):
        labeler = FlowLabeler(
            device_map={"192.168.1.10": "target", "192.168.1.20": "benign"},
            events=[],
        )
        result = labeler.classify("192.168.1.10", "192.168.1.20")
        src_role, dst_role, label, sublabel, kill_chain, subcat = result
        self.assertEqual(src_role, "target")
        self.assertEqual(dst_role, "benign")
        self.assertEqual(label, "benign")
        self.assertEqual(sublabel, "artificial")
        self.assertEqual(kill_chain, "")
        self.assertEqual(subcat, "")

    def test_classify_attack_flow(self):
        labeler = FlowLabeler(
            device_map={"192.168.1.10": "target", "192.168.1.20": "attacker"},
            events=[
                {"event_type": "attack", "action": "syn_flood",
                 "source": "192.168.1.20", "target": "192.168.1.10"},
            ],
        )
        result = labeler.classify("192.168.1.20", "192.168.1.10")
        src_role, dst_role, label, sublabel, kill_chain, subcat = result
        self.assertEqual(src_role, "attacker")
        self.assertEqual(dst_role, "target")
        self.assertEqual(label, "attack")

    def test_classify_unknown_ips(self):
        labeler = FlowLabeler(device_map={}, events=[])
        result = labeler.classify("10.0.0.99", "10.0.0.100")
        src_role, dst_role, label, _, _, _ = result
        self.assertEqual(src_role, "unknown")
        self.assertEqual(dst_role, "unknown")
        # No attacker involved, so label is benign
        self.assertEqual(label, "benign")

    def test_label_filters_benign_when_capture_benign_false(self):
        """When capture_benign=False, only attack flows are kept. A flow is
        an attack if either src or dst is an attacker."""
        with tempfile.TemporaryDirectory() as tmp:
            flows_path = os.path.join(tmp, "flows.csv")
            with open(flows_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["src_ip", "dst_ip"])
                w.writeheader()
                # Attack: attacker → target
                w.writerow({"src_ip": "192.168.1.20", "dst_ip": "192.168.1.10"})
                # Benign: target → benign (no attacker involved)
                w.writerow({"src_ip": "192.168.1.10", "dst_ip": "192.168.1.30"})
                # Attack: target → attacker (dst is attacker)
                w.writerow({"src_ip": "192.168.1.10", "dst_ip": "192.168.1.20"})

            labeler = FlowLabeler(
                device_map={"192.168.1.10": "target",
                             "192.168.1.20": "attacker",
                             "192.168.1.30": "benign"},
                events=[],
                capture_benign=False,  # drop benign flows
            )
            ok = labeler.label(flows_path)
            self.assertTrue(ok)
            # 2 attack flows kept, 1 benign flow filtered
            self.assertEqual(labeler.labeled_count, 2)
            self.assertEqual(labeler.filtered_count, 1)

    def test_label_keeps_all_when_capture_benign_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            flows_path = os.path.join(tmp, "flows.csv")
            with open(flows_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["src_ip", "dst_ip"])
                w.writeheader()
                w.writerow({"src_ip": "192.168.1.10", "dst_ip": "192.168.1.20"})
                w.writerow({"src_ip": "192.168.1.20", "dst_ip": "192.168.1.10"})

            labeler = FlowLabeler(
                device_map={"192.168.1.10": "target",
                             "192.168.1.20": "attacker"},
                events=[],
                capture_benign=True,
            )
            ok = labeler.label(flows_path)
            self.assertTrue(ok)
            self.assertEqual(labeler.labeled_count, 2)
            self.assertEqual(labeler.filtered_count, 0)

    def test_label_nonexistent_file_returns_false(self):
        labeler = FlowLabeler(device_map={}, events=[])
        self.assertFalse(labeler.label("/nonexistent/flows.csv"))


class TestFlowExtractor(unittest.TestCase):

    def test_extract_with_empty_pcap_list_returns_false(self):
        ex = FlowExtractor(log_fn=lambda msg, lvl: None)
        with tempfile.TemporaryDirectory() as tmp:
            flows_path = os.path.join(tmp, "flows.csv")
            # No PCAP files, no nfstream/tshark — should return False
            result = ex.extract([], flows_path)
            self.assertFalse(result)


class TestArtifactManifestWriter(unittest.TestCase):

    def test_sha256_of_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"")
            path = f.name
        try:
            digest = ArtifactManifestWriter.sha256(path)
            # SHA-256 of empty file
            self.assertEqual(
                digest,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
        finally:
            os.unlink(path)

    def test_sha256_of_nonexistent_returns_empty(self):
        self.assertEqual(ArtifactManifestWriter.sha256("/nonexistent"), "")

    def test_enrich_event_metadata_benign(self):
        ev = {
            "event_type": "benign", "action": "turn_on",
            "target": "192.168.1.10", "source": "192.168.1.1",
            "scheduled_dt": "", "duration_s": 5, "status": "queued",
        }
        meta = ArtifactManifestWriter.enrich_event_metadata(ev, {})
        self.assertEqual(meta["label"], "benign")
        self.assertEqual(meta["sublabel"], "artificial")
        self.assertNotIn("category", meta)

    def test_write_manifest_creates_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta_path = os.path.join(tmp, "metadata.json")
            pcap_path = os.path.join(tmp, "capture.pcap")
            flows_path = os.path.join(tmp, "flows.csv")
            # Create dummy files so they appear as artifacts
            for p in (pcap_path, flows_path):
                with open(p, "wb") as f:
                    f.write(b"data")

            config = MagicMock()
            config.experiment_id = "EXP_001"
            config.environment = "lab"
            config.orchestrator_version = "1.0.0"

            writer = ArtifactManifestWriter(log_fn=lambda msg, lvl: None)
            ok = writer.write_manifest(
                meta_path=meta_path, pcap_path=pcap_path, flows_path=flows_path,
                config=config, state="FINISHED",
                started_at=1000.0, ended_at=1600.0, planned_s=600.0,
                iface="eth0",
                device_map={"192.168.1.10": "target"},
                events=[], events_fired=0, flows_count=0,
            )
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(meta_path))

            import json
            with open(meta_path) as f:
                data = json.load(f)
            self.assertEqual(data["experiment_id"], "EXP_001")
            self.assertEqual(data["state"], "FINISHED")
            self.assertEqual(data["capture_interface"], "eth0")
            self.assertIn("artifacts", data)
            self.assertGreater(len(data["artifacts"]), 0)


if __name__ == "__main__":
    unittest.main()
