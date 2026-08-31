import unittest
from schemas import FeatureVector, FlowFeatures, DetectionSignal, ThreatClass, DetectorType, Severity
from detectors.ddos_detector import DDoSBaselineDetector

class TestDDoSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DDoSBaselineDetector()
        
    def create_mock_fv(self, pps: float, syn_ratio: float = 0.0) -> FeatureVector:
        return FeatureVector(
            feature_id="fv-test-001",
            entity_ip="10.0.0.1",
            flow_id="10.0.0.1:1000-10.0.0.2:80-6",
            window_size_sec=5,
            timestamp_iso="2026-08-30T10:00:00Z",
            flow_features=FlowFeatures(
                packets_per_sec=pps,
                bytes_per_sec=pps * 100, # Mock bytes
                syn_ratio=syn_ratio,
                fan_out_dest_count=1,
                dst_port_cardinality=1
            )
        )

    def test_ddos_detector_benign_case(self):
        """Test detector with normal benign flow."""
        fv = self.create_mock_fv(pps=10.0, syn_ratio=0.1)
        signal = self.detector.evaluate(fv)
        
        self.assertEqual(signal.threat_class, ThreatClass.VOLUMETRIC_DDOS)
        self.assertEqual(signal.detector_type, DetectorType.DETERMINISTIC_BASELINE)
        self.assertEqual(signal.confidence, 0.0)
        self.assertEqual(signal.severity, Severity.INFO)
        self.assertEqual(len(signal.indicators), 0)

    def test_ddos_detector_suspicious_pps(self):
        """Test detector with suspicious packet rate."""
        fv = self.create_mock_fv(pps=3000.0, syn_ratio=0.1)
        signal = self.detector.evaluate(fv)
        
        self.assertGreater(signal.confidence, 0.0)
        self.assertLess(signal.confidence, 0.6) # PPS alone maxes at 0.5
        self.assertIn("elevated_pps", signal.indicators)

    def test_ddos_detector_critical_syn_flood(self):
        """Test detector with critical SYN flood characteristics."""
        fv = self.create_mock_fv(pps=6000.0, syn_ratio=0.9)
        signal = self.detector.evaluate(fv)
        
        self.assertEqual(signal.confidence, 1.0) # 0.5 from PPS + 0.5 from SYN
        self.assertEqual(signal.severity, Severity.CRITICAL)
        self.assertIn("high_pps", signal.indicators)
        self.assertIn("critical_syn_ratio", signal.indicators)

    def test_detection_signal_schema_validity(self):
        """Test that generated signal is a valid Pydantic model."""
        fv = self.create_mock_fv(pps=6000.0, syn_ratio=0.9)
        signal = self.detector.evaluate(fv)
        
        # Pydantic validation is run on instantiation, so if it didn't raise, it's valid.
        self.assertIsInstance(signal, DetectionSignal)
        # Test serialization
        json_data = signal.model_dump_json()
        self.assertIn("VOLUMETRIC_DDOS", json_data)
        self.assertIn("10.0.0.1", json_data)
        self.assertIn("10.0.0.2", json_data)
