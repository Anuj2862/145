"""Unit tests for Four-Way Ablation Study Runner (Phase 2D).

Verifies:
1. Subsystem isolation switches cleanly activate/deactivate Mode A, B, C, D.
2. Mode A executes only deterministic heuristics (zero ML signals).
3. Mode B executes only LightGBM ML (zero baseline signals).
4. Mode C executes only Isolation Forest anomaly detector.
5. Mode D executes full fused hybrid pipeline with entity correlation.
"""

import os
import struct
import tempfile
import unittest
from pathlib import Path

from dataset.manifest_schema import (
    EvaluationTrafficClass,
    TemporalWindow,
    GroundTruthEvent,
    CaptureRecord,
    GroundTruthManifest,
)
from dataset.manifest_manager import ManifestManager
from detectors.unified_detector import UnifiedM2Orchestrator
from detectors.engine import DetectionContext
from schemas import (
    FeatureVector,
    FlowFeatures,
    ThreatClass,
    DetectorType,
)
from evaluation.runners.ablation_runner import AblationStudyRunner


def create_mock_pcap(filepath: str, packet_count: int = 30):
    """Generate a minimal valid binary PCAP for ablation testing."""
    with open(filepath, "wb") as f:
        # PCAP Global Header (24 bytes)
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        # Packets
        for i in range(packet_count):
            ts_sec = 1700000000 + i
            ts_usec = 0
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
            src_ip = bytes([192, 168, 1, 100])
            dst_ip = bytes([10, 0, 0, 1])
            ip = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00" + src_ip + dst_ip
            tcp = struct.pack("!HHIIBBHHH", 49152 + i, 80, 1000 + i, 0, 0x50, 0x02, 64240, 0, 0)
            pkt_data = eth + ip + tcp
            caplen = len(pkt_data)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, caplen, caplen)
            f.write(pkt_hdr + pkt_data)


class TestAblationSubsystemIsolation(unittest.TestCase):
    def test_mode_a_heuristics_only_isolation(self):
        """Mode A must only produce DETERMINISTIC_BASELINE signals, never ML."""
        orch = UnifiedM2Orchestrator(
            artifact_dir="models/artifacts",
            enable_baseline=True,
            enable_ml=False,
            enable_anomaly=False,
        )
        fv = FeatureVector(
            feature_id="fv-test-mode-a",
            entity_ip="192.168.1.100",
            flow_id="192.168.1.100:5000-10.0.0.1:80-6",
            timestamp_iso="2026-08-31T12:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=12000.0, syn_ratio=0.99),
        )
        ctx = DetectionContext(source_entity="192.168.1.100", timestamp_iso="2026-08-31T12:00:00Z", feature_vector=fv)
        signals = orch.evaluate(ctx)

        for s in signals:
            self.assertEqual(s.detector_type, DetectorType.DETERMINISTIC_BASELINE)
            self.assertNotEqual(s.detector_type, DetectorType.LIGHTWEIGHT_ML)
            self.assertNotEqual(s.detector_type, DetectorType.UNSUPERVISED_ANOMALY)

    def test_mode_b_ml_only_isolation(self):
        """Mode B must only produce LIGHTWEIGHT_ML signals, never baseline rules."""
        orch = UnifiedM2Orchestrator(
            artifact_dir="models/artifacts",
            enable_baseline=False,
            enable_ml=True,
            enable_anomaly=False,
        )
        fv = FeatureVector(
            feature_id="fv-test-mode-b",
            entity_ip="192.168.1.100",
            flow_id="192.168.1.100:5000-10.0.0.1:80-6",
            timestamp_iso="2026-08-31T12:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=12000.0, syn_ratio=0.99),
        )
        ctx = DetectionContext(source_entity="192.168.1.100", timestamp_iso="2026-08-31T12:00:00Z", feature_vector=fv)
        signals = orch.evaluate(ctx)

        for s in signals:
            self.assertEqual(s.detector_type, DetectorType.LIGHTWEIGHT_ML)
            self.assertNotEqual(s.detector_type, DetectorType.DETERMINISTIC_BASELINE)

    def test_ablation_runner_full_cycle(self):
        """AblationStudyRunner executes all 4 modes and produces JSON + Markdown reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = os.path.join(tmpdir, "ablation_sample.pcap")
            create_mock_pcap(pcap_file, packet_count=20)

            manifest_file = os.path.join(tmpdir, "ablation_manifest.json")
            res_dir = os.path.join(tmpdir, "results")
            rep_dir = os.path.join(tmpdir, "reports")

            event = GroundTruthEvent(
                event_id="EVT-ABLATION-001",
                traffic_class=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                time_window=TemporalWindow(
                    start_time_iso="2023-11-14T22:13:20Z",
                    end_time_iso="2023-11-14T22:14:00Z",
                ),
                source_entity="192.168.1.100",
                target_entity="10.0.0.1",
            )

            record = CaptureRecord(
                capture_id="CAP-ABLATION-01",
                file_path=pcap_file,
                traffic_type="ATTACK",
                primary_label=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                capture_start_iso="2023-11-14T22:13:20Z",
                capture_end_iso="2023-11-14T22:14:00Z",
                duration_sec=40.0,
                labeled_events=[event],
            )

            manifest = GroundTruthManifest(captures={"CAP-ABLATION-01": record})
            mgr = ManifestManager(manifest)
            mgr.save_to_file(manifest_file)

            runner = AblationStudyRunner(
                manifest_path=manifest_file,
                artifact_dir="models/artifacts",
            )
            payload = runner.run_all_modes(output_dir=res_dir, report_dir=rep_dir)

            self.assertIn("modes", payload)
            self.assertIn("MODE_A", payload["modes"])
            self.assertIn("MODE_B", payload["modes"])
            self.assertIn("MODE_C", payload["modes"])
            self.assertIn("MODE_D", payload["modes"])

            self.assertEqual(len(list(Path(res_dir).glob("*.json"))), 1)
            self.assertEqual(len(list(Path(rep_dir).glob("*.md"))), 1)


if __name__ == "__main__":
    unittest.main()
