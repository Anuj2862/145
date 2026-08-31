"""Unit tests for Benchmark Runner & Confusion Matrix Engine (Phase 2B)."""

import os
import struct
import tempfile
import unittest
from pathlib import Path

from dataset.manifest_schema import (
    EvaluationTrafficClass,
    DatasetSplit,
    GenerationMethod,
    TemporalWindow,
    GroundTruthEvent,
    CaptureRecord,
    GroundTruthManifest,
)
from dataset.manifest_manager import ManifestManager
from evaluation.metrics.confusion_matrix import MultiClassConfusionMatrix, ClassMetricResult
from evaluation.runners.benchmark_runner import BenchmarkRunner


def create_mock_pcap(filepath: str, packet_count: int = 30):
    """Generate a minimal valid binary PCAP for benchmark testing."""
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


class TestBenchmarkEngine(unittest.TestCase):
    def test_confusion_matrix_math(self):
        """Test accuracy of TP, FP, FN, TN, precision, recall, and F1 calculations."""
        matrix = MultiClassConfusionMatrix()

        # Record 8 True Positives for VOLUMETRIC_DDOS
        for _ in range(8):
            matrix.record_match(
                ground_truth=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                predicted=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                latency_ms=1.5,
            )

        # Record 2 False Negatives (DDOS classified as BENIGN)
        for _ in range(2):
            matrix.record_match(
                ground_truth=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                predicted=EvaluationTrafficClass.BENIGN,
                latency_ms=1.2,
            )

        # Record 1 False Positive (BENIGN classified as DDOS)
        matrix.record_match(
            ground_truth=EvaluationTrafficClass.BENIGN,
            predicted=EvaluationTrafficClass.VOLUMETRIC_DDOS,
            latency_ms=2.0,
        )

        # Record 10 True Negatives (BENIGN classified as BENIGN)
        for _ in range(10):
            matrix.record_match(
                ground_truth=EvaluationTrafficClass.BENIGN,
                predicted=EvaluationTrafficClass.BENIGN,
                latency_ms=1.0,
            )

        ddos_metrics = matrix.get_class_metrics(EvaluationTrafficClass.VOLUMETRIC_DDOS)
        self.assertTrue(ddos_metrics.tested)
        self.assertEqual(ddos_metrics.true_positives, 8)
        self.assertEqual(ddos_metrics.false_positives, 1)
        self.assertEqual(ddos_metrics.false_negatives, 2)
        
        # Precision = 8 / (8 + 1) = 8/9 ~ 0.8889
        self.assertAlmostEqual(ddos_metrics.precision, 8 / 9, places=4)
        # Recall = 8 / (8 + 2) = 8/10 = 0.8
        self.assertAlmostEqual(ddos_metrics.recall, 0.80, places=4)
        # F1 = 2 * (8/9 * 0.8) / (8/9 + 0.8) ~ 0.8421
        self.assertAlmostEqual(ddos_metrics.f1_score, 0.8421, places=4)

        summary = matrix.compute_summary()
        self.assertAlmostEqual(summary["latency_median_ms"], 1.2, places=1)
        self.assertGreater(summary["macro_f1"], 0.0)

    def test_untested_threat_class_handling(self):
        """Ensure categories without evaluation data are cleanly marked NOT_TESTED without false 0% metrics."""
        matrix = MultiClassConfusionMatrix()
        matrix.mark_untested(
            EvaluationTrafficClass.BOTNET_C2_BEACONING,
            "No labeled C2 PCAP in testbed"
        )

        c2_metrics = matrix.get_class_metrics(EvaluationTrafficClass.BOTNET_C2_BEACONING)
        self.assertFalse(c2_metrics.tested)
        self.assertIn("No labeled C2 PCAP", c2_metrics.untested_reason)

        dict_repr = c2_metrics.to_dict()
        self.assertEqual(dict_repr["status"], "NOT_TESTED")
        self.assertIn("reason", dict_repr)

    def test_benchmark_runner_full_cycle(self):
        """Test executing BenchmarkRunner against a synthetic capture manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = os.path.join(tmpdir, "test_syn_sample.pcap")
            create_mock_pcap(pcap_file, packet_count=25)

            manifest_file = os.path.join(tmpdir, "test_manifest.json")
            res_dir = os.path.join(tmpdir, "results")
            rep_dir = os.path.join(tmpdir, "reports")

            event = GroundTruthEvent(
                event_id="EVT-TEST-001",
                traffic_class=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                time_window=TemporalWindow(
                    start_time_iso="2023-11-14T22:13:20Z",
                    end_time_iso="2023-11-14T22:14:00Z",
                ),
                source_entity="192.168.1.100",
                target_entity="10.0.0.1",
            )

            record = CaptureRecord(
                capture_id="CAP-TEST-01",
                file_path=pcap_file,
                traffic_type="ATTACK",
                primary_label=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                capture_start_iso="2023-11-14T22:13:20Z",
                capture_end_iso="2023-11-14T22:14:00Z",
                duration_sec=40.0,
                labeled_events=[event],
            )

            manifest = GroundTruthManifest(captures={"CAP-TEST-01": record})
            mgr = ManifestManager(manifest)
            mgr.save_to_file(manifest_file)

            runner = BenchmarkRunner(
                manifest_path=manifest_file,
                artifact_dir="models/artifacts",
                enable_ml=True,
                enable_baseline=True,
            )

            report = runner.run_benchmark(output_dir=res_dir, report_dir=rep_dir)

            self.assertIn("experiment_id", report)
            self.assertIn("performance", report)
            self.assertEqual(report["performance"]["total_packets_processed"], 25)
            self.assertGreater(report["performance"]["sustained_throughput_pps"], 0.0)

            # Check that files were written
            results_files = list(Path(res_dir).glob("*.json"))
            report_files = list(Path(rep_dir).glob("*.md"))
            self.assertEqual(len(results_files), 1)
            self.assertEqual(len(report_files), 1)


if __name__ == "__main__":
    unittest.main()
