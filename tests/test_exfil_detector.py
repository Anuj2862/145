import unittest
from schemas import FlowEvent, DetectionSignal, ThreatClass, DetectorType, Severity
from features.exfil_features import aggregate_exfil_features
from detectors.exfil_detector import ExfiltrationDetector

ENTITY = "10.0.0.1"
TIMESTAMP = "2026-08-30T10:00:00Z"


def make_flow(src_ip=ENTITY, dst_ip="1.2.3.4", byte_count=1000,
              start="2026-08-30T10:00:00Z", end="2026-08-30T10:01:00Z") -> FlowEvent:
    return FlowEvent(
        flow_id=f"{src_ip}:50000-{dst_ip}:443-6",
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=50000, dst_port=443,
        protocol=6,
        start_time_iso=start,
        end_time_iso=end,
        duration_sec=60.0,
        packet_count=10,
        byte_count=byte_count,
    )


def _eval(flows, entity=ENTITY, min_flows=3, window=60.0):
    ef = aggregate_exfil_features(flows, entity_ip=entity,
                                   window_duration_sec=window,
                                   min_flows_required=min_flows)
    return ExfiltrationDetector().evaluate(ef, source_entity=entity,
                                           timestamp_iso=TIMESTAMP)


class TestExfiltrationDetector(unittest.TestCase):

    def test_benign_traffic(self):
        """Normal low-volume traffic → INFO severity, near-zero score."""
        flows = [make_flow(byte_count=5000) for _ in range(3)]
        sig = _eval(flows)

        self.assertLess(sig.indicators["exfil_suspicion_score"], 0.1)
        self.assertEqual(sig.severity, Severity.INFO)
        self.assertEqual(sig.threat_class, ThreatClass.DATA_EXFILTRATION)
        self.assertEqual(sig.detector_type, DetectorType.DETERMINISTIC_BASELINE)

    def test_high_outbound_volume(self):
        """High outbound byte volume increases suspicion score."""
        benign = [make_flow(byte_count=5000) for _ in range(3)]
        high_vol = [make_flow(byte_count=200_000_000) for _ in range(3)]  # 200 MB each

        benign_sig = _eval(benign)
        high_sig   = _eval(high_vol)

        self.assertGreater(high_sig.indicators["exfil_suspicion_score"],
                           benign_sig.indicators["exfil_suspicion_score"])

    def test_large_transfer(self):
        """Multiple large transfers push large_transfer component."""
        flows = [make_flow(byte_count=5_000_000) for _ in range(5)]   # 5 MB each
        sig = _eval(flows)

        self.assertGreater(sig.indicators["comp_large_transfer"], 0.0)

    def test_high_outbound_rate(self):
        """Same volume but shorter window → higher rate component."""
        slow_flows = [make_flow(byte_count=10_000_000,
                                start="2026-08-30T10:00:00Z",
                                end="2026-08-30T10:10:00Z")   # 10 min
                      for _ in range(3)]
        fast_flows = [make_flow(byte_count=10_000_000,
                                start="2026-08-30T10:00:00Z",
                                end="2026-08-30T10:00:10Z")   # 10 sec
                      for _ in range(3)]

        slow_sig = _eval(slow_flows)
        fast_sig = _eval(fast_flows)

        self.assertGreater(fast_sig.indicators["comp_outbound_rate"],
                           slow_sig.indicators["comp_outbound_rate"])

    def test_multiple_suspicious_indicators_compound(self):
        """High volume + short window + large transfers → higher score than volume alone."""
        vol_only = [make_flow(byte_count=200_000_000,
                              start="2026-08-30T10:00:00Z",
                              end="2026-08-30T10:30:00Z")   # slow, 30 min
                    for _ in range(3)]
        compound = [make_flow(byte_count=200_000_000,
                              start="2026-08-30T10:00:00Z",
                              end="2026-08-30T10:00:30Z")   # fast, 30 sec
                    for _ in range(3)]

        vol_sig = _eval(vol_only)
        comp_sig = _eval(compound)

        self.assertGreater(comp_sig.indicators["exfil_suspicion_score"],
                           vol_sig.indicators["exfil_suspicion_score"])

    def test_insufficient_observations(self):
        """Below min_flows_required → INFO, confidence 0."""
        flows = [make_flow(byte_count=500_000_000)]
        sig = _eval(flows, min_flows=3)

        self.assertEqual(sig.severity, Severity.INFO)
        self.assertEqual(sig.confidence, 0.0)
        self.assertIn("reason", sig.indicators)

    def test_missing_optional_features_direction_unavailable(self):
        """When entity_ip matches no flows, detector returns INFO."""
        flows = [make_flow(src_ip="9.9.9.9", dst_ip="8.8.8.8") for _ in range(3)]
        sig = _eval(flows, entity="10.0.0.1")

        self.assertEqual(sig.severity, Severity.INFO)
        self.assertIn("reason", sig.indicators)

    def test_score_bounded(self):
        """Score is always in [0.0, 1.0] even with extreme values."""
        flows = [make_flow(byte_count=1_000_000_000,
                           start="2026-08-30T10:00:00Z",
                           end="2026-08-30T10:00:01Z")
                 for _ in range(20)]
        sig = _eval(flows, min_flows=3)

        self.assertGreaterEqual(sig.indicators["exfil_suspicion_score"], 0.0)
        self.assertLessEqual(sig.indicators["exfil_suspicion_score"], 1.0)

    def test_confidence_bounded(self):
        """Confidence is always in [0.0, 1.0]."""
        flows = [make_flow(byte_count=1_000_000_000,
                           start="2026-08-30T10:00:00Z",
                           end="2026-08-30T10:00:01Z")
                 for _ in range(20)]
        sig = _eval(flows, min_flows=3)

        self.assertGreaterEqual(sig.confidence, 0.0)
        self.assertLessEqual(sig.confidence, 1.0)

    def test_correct_threat_class(self):
        flows = [make_flow() for _ in range(3)]
        sig = _eval(flows)
        self.assertEqual(sig.threat_class, ThreatClass.DATA_EXFILTRATION)

    def test_correct_detector_type(self):
        flows = [make_flow() for _ in range(3)]
        sig = _eval(flows)
        self.assertEqual(sig.detector_type, DetectorType.DETERMINISTIC_BASELINE)

    def test_detection_signal_schema_validity(self):
        """Output is a valid DetectionSignal that serialises without error."""
        flows = [make_flow(byte_count=50_000_000) for _ in range(3)]
        sig = _eval(flows)

        self.assertIsInstance(sig, DetectionSignal)
        json_data = sig.model_dump_json()
        self.assertIn("DATA_EXFILTRATION", json_data)

    def test_evidence_completeness_in_indicators(self):
        """All key indicators are present in the output."""
        flows = [make_flow(byte_count=2_000_000) for _ in range(5)]
        sig = _eval(flows)

        for key in ["total_outbound_bytes", "total_inbound_bytes",
                    "outbound_bytes_per_sec", "upload_download_ratio",
                    "large_transfer_count", "comp_outbound_volume",
                    "comp_large_transfer", "exfil_suspicion_score",
                    "sufficient_evidence", "direction_available"]:
            self.assertIn(key, sig.indicators, f"Missing key: {key}")

    def test_deterministic_output(self):
        """Identical inputs always produce identical outputs."""
        flows = [make_flow(byte_count=50_000_000) for _ in range(4)]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=3)
        detector = ExfiltrationDetector()

        sig1 = detector.evaluate(ef, source_entity=ENTITY, timestamp_iso=TIMESTAMP)
        sig2 = detector.evaluate(ef, source_entity=ENTITY, timestamp_iso=TIMESTAMP)

        self.assertEqual(sig1.confidence, sig2.confidence)
        self.assertEqual(sig1.indicators["exfil_suspicion_score"],
                         sig2.indicators["exfil_suspicion_score"])

    def test_multiple_indicators_compound_suspicion(self):
        """Adding more indicators monotonically raises suspicion score."""
        # Volume alone (slow transfer)
        low_flows = [make_flow(byte_count=100_000_000,
                               start="2026-08-30T10:00:00Z",
                               end="2026-08-30T11:00:00Z")
                     for _ in range(3)]

        # Volume + high rate + large transfers
        high_flows = [make_flow(byte_count=200_000_000,
                                start="2026-08-30T10:00:00Z",
                                end="2026-08-30T10:00:30Z")
                      for _ in range(8)]

        low_sig  = _eval(low_flows)
        high_sig = _eval(high_flows)

        self.assertGreater(high_sig.indicators["exfil_suspicion_score"],
                           low_sig.indicators["exfil_suspicion_score"])
