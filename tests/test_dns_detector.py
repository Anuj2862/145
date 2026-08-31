import unittest
from schemas import FeatureVector, FlowFeatures, DNSFeatures, DetectionSignal, ThreatClass, DetectorType, Severity
from detectors.dns_detector import DNSAnomalyDetector

class TestDNSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DNSAnomalyDetector()
        
    def create_mock_fv(self, entropy: float = None, length: float = None, nxdomain: int = 0, 
                       txt_ratio: float = None, subdomains: int = None) -> FeatureVector:
        return FeatureVector(
            feature_id="fv-dns-test-001",
            entity_ip="10.0.0.1",
            flow_id="10.0.0.1:1000-10.0.0.2:53-17",
            window_size_sec=5,
            timestamp_iso="2026-08-30T10:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=2.0, bytes_per_sec=200.0, syn_ratio=0.0, fan_out_dest_count=1, dst_port_cardinality=1),
            dns_features=DNSFeatures(
                entropy_mean=entropy,
                query_length_mean=length,
                nxdomain_count=nxdomain,
                txt_record_ratio=txt_ratio,
                subdomain_count=subdomains
            )
        )

    def test_normal_dns_behaviour(self):
        """Test with totally benign DNS metrics."""
        fv = self.create_mock_fv(entropy=2.0, length=10.0, nxdomain=0, txt_ratio=0.0, subdomains=0)
        signal = self.detector.evaluate(fv)
        
        self.assertEqual(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertEqual(signal.confidence, 0.0)
        self.assertEqual(signal.severity, Severity.INFO)
        self.assertEqual(signal.threat_class, ThreatClass.DGA_DNS_TUNNELLING)
        self.assertEqual(signal.detector_type, DetectorType.DETERMINISTIC_BASELINE)

    def test_high_entropy_domains(self):
        """Test isolated high entropy indicator."""
        # Baseline benign
        fv1 = self.create_mock_fv(entropy=2.0, length=10.0, nxdomain=0, txt_ratio=0.0, subdomains=0)
        # High entropy
        fv2 = self.create_mock_fv(entropy=5.0, length=10.0, nxdomain=0, txt_ratio=0.0, subdomains=0)
        
        sig1 = self.detector.evaluate(fv1)
        sig2 = self.detector.evaluate(fv2)
        
        self.assertGreater(sig2.indicators["dns_suspicion_score"], sig1.indicators["dns_suspicion_score"])
        self.assertEqual(sig2.indicators["comp_entropy"], 1.0)

    def test_long_query_names(self):
        """Test isolated long query length indicator."""
        fv_long = self.create_mock_fv(entropy=2.0, length=60.0, nxdomain=0, txt_ratio=0.0, subdomains=0)
        signal = self.detector.evaluate(fv_long)
        self.assertGreater(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertEqual(signal.indicators["comp_length"], 1.0)

    def test_high_nxdomain_activity(self):
        """Test isolated high NXDOMAIN activity."""
        fv_nx = self.create_mock_fv(entropy=2.0, length=10.0, nxdomain=30, txt_ratio=0.0, subdomains=0)
        signal = self.detector.evaluate(fv_nx)
        self.assertGreater(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertEqual(signal.indicators["comp_nxdomain"], 1.0)

    def test_high_txt_ratio(self):
        """Test isolated high TXT record ratio."""
        fv_txt = self.create_mock_fv(entropy=2.0, length=10.0, nxdomain=0, txt_ratio=0.9, subdomains=0)
        signal = self.detector.evaluate(fv_txt)
        self.assertGreater(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertEqual(signal.indicators["comp_txt"], 1.0)

    def test_high_subdomain_activity(self):
        """Test isolated high subdomain counting."""
        fv_sub = self.create_mock_fv(entropy=2.0, length=10.0, nxdomain=0, txt_ratio=0.0, subdomains=40)
        signal = self.detector.evaluate(fv_sub)
        self.assertGreater(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertEqual(signal.indicators["comp_subdomain"], 1.0)

    def test_multiple_suspicious_indicators(self):
        """Test combined indicators resulting in a high score/confidence."""
        fv_multi = self.create_mock_fv(entropy=4.6, length=55.0, nxdomain=25, txt_ratio=0.85, subdomains=35)
        signal = self.detector.evaluate(fv_multi)
        
        self.assertEqual(signal.indicators["dns_suspicion_score"], 1.0)
        self.assertGreater(signal.confidence, 0.8) # max possible is 0.9 for deterministic
        self.assertEqual(signal.severity, Severity.HIGH)

    def test_missing_optional_fields(self):
        """Test safe handling when optional fields are None."""
        fv_missing = self.create_mock_fv(entropy=None, length=None, nxdomain=0, txt_ratio=None, subdomains=None)
        signal = self.detector.evaluate(fv_missing)
        
        # Valid weight is just NXDOMAIN (0.2). If nxdomain is 0, score is 0.
        self.assertEqual(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertEqual(signal.confidence, 0.0)

        # Now test with one valid highly suspicious metric, and rest None
        fv_partial = self.create_mock_fv(entropy=None, length=60.0, nxdomain=0, txt_ratio=None, subdomains=None)
        sig_partial = self.detector.evaluate(fv_partial)
        
        # The score should be relative to valid weight. Length is maxed (1.0). NXDOMAIN is 0.0.
        # Length weight: 0.25, NXDOMAIN weight: 0.2, Total valid weight: 0.45
        # Score = (1.0 * 0.25 + 0.0) / 0.45 = 0.555
        self.assertAlmostEqual(sig_partial.indicators["dns_suspicion_score"], 0.25 / 0.45)
        
        # However, confidence should be limited due to missing evidence.
        self.assertLess(sig_partial.confidence, 0.5)

    def test_empty_zero_feature_values(self):
        """Test handling of totally empty DNS features."""
        fv_empty = self.create_mock_fv()
        fv_empty.dns_features = None
        
        signal = self.detector.evaluate(fv_empty)
        self.assertEqual(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertEqual(signal.confidence, 0.0)
        self.assertEqual(signal.severity, Severity.INFO)
        self.assertIn("reason", signal.indicators)

    def test_score_and_confidence_bounds(self):
        """Test that score and confidence never exceed 1.0, even with extreme inputs."""
        fv_extreme = self.create_mock_fv(entropy=100.0, length=5000.0, nxdomain=9999, txt_ratio=1.0, subdomains=999)
        signal = self.detector.evaluate(fv_extreme)
        
        self.assertLessEqual(signal.indicators["dns_suspicion_score"], 1.0)
        self.assertGreaterEqual(signal.indicators["dns_suspicion_score"], 0.0)
        self.assertLessEqual(signal.confidence, 1.0)
        self.assertGreaterEqual(signal.confidence, 0.0)

    def test_detection_signal_schema_validity(self):
        """Test that the generated output is a valid DetectionSignal."""
        fv = self.create_mock_fv(entropy=4.0, length=30.0, nxdomain=5, txt_ratio=0.2, subdomains=10)
        signal = self.detector.evaluate(fv)
        
        self.assertIsInstance(signal, DetectionSignal)
        # Verify JSON serialization works (which verifies Pydantic strict types internally)
        json_data = signal.model_dump_json()
        self.assertIn("DGA_DNS_TUNNELLING", json_data)

    def test_evidence_contains_contributing_features(self):
        """Verify the evidence indicators contain the raw feature inputs and normalized component scores."""
        fv = self.create_mock_fv(entropy=3.75, length=35.0, nxdomain=11, txt_ratio=0.45, subdomains=17)
        signal = self.detector.evaluate(fv)
        
        # Entropy is exactly halfway between 3.0 and 4.5 -> component score 0.5
        self.assertEqual(signal.indicators["entropy_mean"], 3.75)
        self.assertAlmostEqual(signal.indicators["comp_entropy"], 0.5)
        
        # Length is halfway between 20.0 and 50.0 -> component score 0.5
        self.assertEqual(signal.indicators["query_length_mean"], 35.0)
        self.assertAlmostEqual(signal.indicators["comp_length"], 0.5)

    def test_deterministic_output(self):
        """Ensure same inputs yield same outputs."""
        fv = self.create_mock_fv(entropy=4.0, length=30.0, nxdomain=5, txt_ratio=0.2, subdomains=10)
        sig1 = self.detector.evaluate(fv)
        sig2 = self.detector.evaluate(fv)
        
        self.assertEqual(sig1.confidence, sig2.confidence)
        self.assertEqual(sig1.indicators["dns_suspicion_score"], sig2.indicators["dns_suspicion_score"])
