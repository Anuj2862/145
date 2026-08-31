import unittest
from schemas import FeatureVector, FlowFeatures, TemporalFeatures, DetectionSignal, ThreatClass, DetectorType, Severity
from detectors.c2_detector import C2BeaconDetector

class TestC2BeaconDetector(unittest.TestCase):
    def setUp(self):
        self.detector = C2BeaconDetector()
        
    def create_mock_fv(self, periodicity: float, jitter: float) -> FeatureVector:
        return FeatureVector(
            feature_id="fv-c2-test-001",
            entity_ip="10.0.0.1",
            flow_id="10.0.0.1:1000-10.0.0.2:80-6",
            window_size_sec=5,
            timestamp_iso="2026-08-30T10:00:00Z",
            flow_features=FlowFeatures(
                packets_per_sec=1.0,
                bytes_per_sec=100.0,
                syn_ratio=0.1,
                fan_out_dest_count=1,
                dst_port_cardinality=1
            ),
            temporal_features=TemporalFeatures(
                inter_arrival_mean_ms=60000.0,
                inter_arrival_std_ms=(jitter / 100.0) * 60000.0,
                periodicity_score=periodicity,
                jitter_pct=jitter
            )
        )

    def test_highly_regular_periodic_traffic(self):
        """Test with regular intervals (high periodicity, low jitter)."""
        fv = self.create_mock_fv(periodicity=1.0, jitter=0.0)
        # Using enough observations to avoid penalty
        signal = self.detector.evaluate(fv, observation_count=10)
        
        self.assertGreater(signal.indicators["c2_suspicion_score"], 0.8)
        self.assertEqual(signal.severity, Severity.HIGH)
        self.assertEqual(signal.threat_class, ThreatClass.BOTNET_C2_BEACONING)
        self.assertEqual(signal.detector_type, DetectorType.DETERMINISTIC_BASELINE)

    def test_slightly_irregular_periodic_traffic(self):
        """Test with slightly irregular intervals."""
        fv = self.create_mock_fv(periodicity=0.8, jitter=20.0)
        signal = self.detector.evaluate(fv, observation_count=10)
        
        self.assertGreater(signal.indicators["c2_suspicion_score"], 0.5)
        self.assertLess(signal.indicators["c2_suspicion_score"], 0.8)

    def test_highly_irregular_traffic(self):
        """Test with highly irregular bursty traffic."""
        fv = self.create_mock_fv(periodicity=0.1, jitter=90.0)
        signal = self.detector.evaluate(fv, observation_count=10)
        
        self.assertLess(signal.indicators["c2_suspicion_score"], 0.2)
        self.assertEqual(signal.severity, Severity.INFO)

    def test_insufficient_observations(self):
        """Test penalty applied for insufficient observations."""
        fv = self.create_mock_fv(periodicity=1.0, jitter=0.0)
        # Only 2 observations (requires 5)
        signal = self.detector.evaluate(fv, observation_count=2)
        
        self.assertLessEqual(signal.indicators["c2_suspicion_score"], 0.4)
        self.assertLessEqual(signal.confidence, 0.3)
        self.assertTrue(signal.indicators.get("insufficient_observations_penalty"))

    def test_very_high_jitter(self):
        """Test that high jitter reduces the score significantly."""
        fv1 = self.create_mock_fv(periodicity=0.5, jitter=40.0)
        fv2 = self.create_mock_fv(periodicity=0.5, jitter=80.0)
        
        sig1 = self.detector.evaluate(fv1, observation_count=10)
        sig2 = self.detector.evaluate(fv2, observation_count=10)
        
        self.assertGreater(sig1.indicators["c2_suspicion_score"], sig2.indicators["c2_suspicion_score"])

    def test_deterministic_output(self):
        """Test that the same input always produces the same output."""
        fv = self.create_mock_fv(periodicity=0.9, jitter=10.0)
        
        sig1 = self.detector.evaluate(fv, observation_count=8)
        sig2 = self.detector.evaluate(fv, observation_count=8)
        
        self.assertEqual(sig1.confidence, sig2.confidence)
        self.assertEqual(sig1.indicators["c2_suspicion_score"], sig2.indicators["c2_suspicion_score"])

    def test_detection_signal_schema_validity(self):
        """Test that generated signal is a valid Pydantic model."""
        fv = self.create_mock_fv(periodicity=0.95, jitter=5.0)
        signal = self.detector.evaluate(fv, observation_count=10)
        
        self.assertIsInstance(signal, DetectionSignal)
        json_data = signal.model_dump_json()
        self.assertIn("BOTNET_C2_BEACONING", json_data)

    def test_evidence_contains_temporal_indicators(self):
        """Verify that the evidence dict contains all expected indicators."""
        fv = self.create_mock_fv(periodicity=0.88, jitter=12.0)
        signal = self.detector.evaluate(fv, observation_count=7)
        
        self.assertEqual(signal.indicators["periodicity_score"], 0.88)
        self.assertEqual(signal.indicators["jitter_pct"], 12.0)
        self.assertEqual(signal.indicators["observation_count"], 7)
        self.assertIn("inter_arrival_mean_ms", signal.indicators)
        self.assertIn("score_component_periodicity", signal.indicators)
        self.assertIn("c2_suspicion_score", signal.indicators)
