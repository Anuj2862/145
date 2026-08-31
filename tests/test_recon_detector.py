import unittest
from schemas import FlowEvent, DetectionSignal, ThreatClass, DetectorType, Severity
from features.recon_features import aggregate_recon_features
from detectors.recon_detector import ReconDetector


def make_flow(src_ip="10.0.0.1", dst_ip="192.168.1.1", dst_port=80,
              byte_count=500, rst_count=0, src_port=10000, protocol=6) -> FlowEvent:
    return FlowEvent(
        flow_id=f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}",
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol,
        start_time_iso="2026-08-30T10:00:00Z",
        end_time_iso="2026-08-30T10:00:05Z",
        duration_sec=5.0, packet_count=10,
        byte_count=byte_count,
    )


TIMESTAMP = "2026-08-30T10:00:00Z"


class TestReconDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ReconDetector()

    def _eval(self, flows, window_sec=60.0, min_flows=3, entity="10.0.0.1"):
        rf = aggregate_recon_features(flows, window_duration_sec=window_sec,
                                      min_flows_required=min_flows)
        return self.detector.evaluate(rf, source_entity=entity,
                                      timestamp_iso=TIMESTAMP)

    # --- Basic benign ---
    def test_benign_low_volume_traffic(self):
        """Three normal flows to three different IPs → INFO/LOW."""
        flows = [make_flow(dst_ip=f"10.0.0.{i+10}", dst_port=443) for i in range(3)]
        sig = self._eval(flows)

        self.assertLessEqual(sig.indicators["recon_suspicion_score"], 0.3)
        self.assertIn(sig.severity, [Severity.INFO, Severity.LOW])
        self.assertEqual(sig.threat_class, ThreatClass.RECON_PORT_SCAN)
        self.assertEqual(sig.detector_type, DetectorType.DETERMINISTIC_BASELINE)

    # --- Scan patterns ---
    def test_horizontal_scan_exceeds_benign(self):
        """Horizontal scan score > benign score."""
        benign_flows = [make_flow(dst_ip="10.0.0.1", dst_port=80) for _ in range(3)]
        h_flows = [make_flow(dst_ip=f"10.0.{i}.1", dst_port=80, byte_count=0)
                   for i in range(20)]

        benign_sig = self._eval(benign_flows)
        h_sig = self._eval(h_flows)

        self.assertGreater(h_sig.indicators["recon_suspicion_score"],
                           benign_sig.indicators["recon_suspicion_score"])
        self.assertEqual(h_sig.indicators["scan_type"], "HORIZONTAL")

    def test_vertical_scan_exceeds_benign(self):
        """Vertical scan score > benign score."""
        benign_flows = [make_flow() for _ in range(3)]
        v_flows = [make_flow(dst_ip="192.168.1.1", dst_port=p, src_port=10000 + p, byte_count=0)
                   for p in range(1, 26)]

        benign_sig = self._eval(benign_flows)
        v_sig = self._eval(v_flows)

        self.assertGreater(v_sig.indicators["recon_suspicion_score"],
                           benign_sig.indicators["recon_suspicion_score"])
        self.assertEqual(v_sig.indicators["scan_type"], "VERTICAL")

    def test_broad_scan_exceeds_horizontal_and_vertical(self):
        """Broad scan score >= horizontal and vertical individually."""
        h_flows = [make_flow(dst_ip=f"10.0.{i}.1", dst_port=80, byte_count=0)
                   for i in range(20)]
        v_flows = [make_flow(dst_ip="192.168.1.1", dst_port=p, src_port=10000 + p, byte_count=0)
                   for p in range(1, 26)]
        broad_flows = [make_flow(dst_ip=f"10.0.{i}.{j}", dst_port=(22 + j) % 65535, byte_count=0)
                       for i in range(6) for j in range(10)]

        h_sig = self._eval(h_flows)
        v_sig = self._eval(v_flows)
        b_sig = self._eval(broad_flows)

        self.assertGreaterEqual(b_sig.indicators["recon_suspicion_score"],
                                h_sig.indicators["recon_suspicion_score"])
        self.assertGreaterEqual(b_sig.indicators["recon_suspicion_score"],
                                v_sig.indicators["recon_suspicion_score"])
        self.assertEqual(b_sig.indicators["scan_type"], "BROAD")

    def test_high_rate_scan(self):
        """High connection rate in a short window increases score."""
        slow_flows = [make_flow(dst_ip=f"10.0.0.{i}", byte_count=0) for i in range(5)]
        fast_flows = [make_flow(dst_ip=f"10.0.0.{i}", byte_count=0) for i in range(5)]

        slow_sig = self._eval(slow_flows, window_sec=60.0)
        fast_sig = self._eval(fast_flows, window_sec=1.0)

        self.assertGreater(fast_sig.indicators["comp_rate"],
                           slow_sig.indicators["comp_rate"])

    # --- Insufficient evidence ---
    def test_insufficient_observations(self):
        """Single flow below minimum threshold → INFO, penalised confidence."""
        flows = [make_flow()]
        sig = self._eval(flows, min_flows=3)

        self.assertEqual(sig.severity, Severity.INFO)
        self.assertLessEqual(sig.confidence, 0.1)
        self.assertIn("reason", sig.indicators)

    # --- Bounds ---
    def test_score_bounded(self):
        """Score always in [0.0, 1.0]."""
        flows = [make_flow(dst_ip=f"10.0.{i}.{j}", dst_port=(j + 22) % 65535, byte_count=0)
                 for i in range(10) for j in range(30)]
        sig = self._eval(flows, window_sec=0.5)

        self.assertGreaterEqual(sig.indicators["recon_suspicion_score"], 0.0)
        self.assertLessEqual(sig.indicators["recon_suspicion_score"], 1.0)

    def test_confidence_bounded(self):
        """Confidence always in [0.0, 1.0]."""
        flows = [make_flow(dst_ip=f"10.0.{i}.{j}", dst_port=(j + 22) % 65535, byte_count=0)
                 for i in range(10) for j in range(30)]
        sig = self._eval(flows, window_sec=0.5)

        self.assertGreaterEqual(sig.confidence, 0.0)
        self.assertLessEqual(sig.confidence, 1.0)

    # --- Schema & correctness ---
    def test_detection_signal_schema_validity(self):
        """Output is a valid DetectionSignal that serialises without error."""
        flows = [make_flow(dst_ip=f"10.0.0.{i}") for i in range(5)]
        sig = self._eval(flows)

        self.assertIsInstance(sig, DetectionSignal)
        json_data = sig.model_dump_json()
        self.assertIn("RECON_PORT_SCAN", json_data)

    def test_correct_threat_class_and_detector_type(self):
        flows = [make_flow(dst_ip=f"10.0.0.{i}") for i in range(5)]
        sig = self._eval(flows)

        self.assertEqual(sig.threat_class, ThreatClass.RECON_PORT_SCAN)
        self.assertEqual(sig.detector_type, DetectorType.DETERMINISTIC_BASELINE)

    def test_evidence_contains_scan_characteristics(self):
        """Indicators must expose all key recon fields."""
        flows = [make_flow(dst_ip=f"10.0.0.{i}", byte_count=0) for i in range(8)]
        sig = self._eval(flows)

        for key in ["flow_count", "unique_dst_ip_count", "unique_dst_port_count",
                    "scan_type", "connection_rate_per_sec", "failed_connection_ratio",
                    "comp_ip_fanout", "comp_port_fanout", "comp_rate", "comp_fail_ratio",
                    "recon_suspicion_score"]:
            self.assertIn(key, sig.indicators, f"Missing indicator key: {key}")

    def test_deterministic_output(self):
        """Same flows always produce same score and confidence."""
        flows = [make_flow(dst_ip=f"10.0.0.{i}", byte_count=0) for i in range(8)]
        rf = aggregate_recon_features(flows, window_duration_sec=30.0)

        sig1 = self.detector.evaluate(rf, source_entity="10.0.0.1", timestamp_iso=TIMESTAMP)
        sig2 = self.detector.evaluate(rf, source_entity="10.0.0.1", timestamp_iso=TIMESTAMP)

        self.assertEqual(sig1.confidence, sig2.confidence)
        self.assertEqual(sig1.indicators["recon_suspicion_score"],
                         sig2.indicators["recon_suspicion_score"])
