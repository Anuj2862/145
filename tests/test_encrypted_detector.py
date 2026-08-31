import unittest
from schemas import FeatureVector, FlowFeatures, TLSFeatures, TemporalFeatures, DetectionSignal, ThreatClass, DetectorType, Severity
from detectors.encrypted_detector import EncryptedThreatDetector

class TestEncryptedDetector(unittest.TestCase):
    def setUp(self):
        self.detector = EncryptedThreatDetector()
        
    def create_mock_fv(self, ja3=None, ja4=None, sni=None, alpn=None, periodicity=None, jitter=None) -> FeatureVector:
        tf = None
        if any(x is not None for x in [periodicity, jitter]):
            tf = TemporalFeatures(
                inter_arrival_mean_ms=1000.0, 
                inter_arrival_std_ms=0.0,
                periodicity_score=periodicity, 
                jitter_pct=jitter
            )
            
        tls = None
        if any(x is not None for x in [ja3, ja4, sni, alpn]):
            tls = TLSFeatures(ja3_hash=ja3, ja4_hash=ja4, sni=sni, alpn=alpn)
            
        return FeatureVector(
            feature_id="fv-enc-test-001",
            entity_ip="10.0.0.1",
            flow_id="10.0.0.1:50000-10.0.0.2:443-6",
            window_size_sec=5,
            timestamp_iso="2026-08-30T10:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=2.0, bytes_per_sec=200.0, syn_ratio=0.0, fan_out_dest_count=1, dst_port_cardinality=1),
            temporal_features=tf,
            tls_features=tls
        )

    def test_complete_benign_tls_metadata(self):
        """Test with totally complete and benign TLS features."""
        fv = self.create_mock_fv(ja3="j3", ja4="j4", sni="test.com", alpn="h2")
        signal = self.detector.evaluate(fv)
        
        self.assertEqual(signal.indicators["encrypted_threat_score"], 0.0)
        self.assertEqual(signal.confidence, 0.0)
        self.assertEqual(signal.severity, Severity.INFO)
        self.assertEqual(signal.threat_class, ThreatClass.ENCRYPTED_MALWARE)
        self.assertEqual(signal.detector_type, DetectorType.DETERMINISTIC_BASELINE)
        self.assertEqual(signal.indicators["tls_completeness"], 1.0)

    def test_missing_sni(self):
        """Missing SNI with JA3 present increases metadata anomaly."""
        fv_complete = self.create_mock_fv(ja3="j3", ja4="j4", sni="test.com", alpn="h2")
        fv_no_sni = self.create_mock_fv(ja3="j3", ja4="j4", alpn="h2")
        
        sig1 = self.detector.evaluate(fv_complete)
        sig2 = self.detector.evaluate(fv_no_sni)
        
        self.assertGreater(sig2.indicators["comp_metadata_anomaly"], sig1.indicators["comp_metadata_anomaly"])
        self.assertGreater(sig2.indicators["encrypted_threat_score"], 0.0)

    def test_missing_ja3(self):
        """Missing JA3 shouldn't necessarily spike score, but affects completeness."""
        fv = self.create_mock_fv(ja4="j4", sni="test.com", alpn="h2")
        signal = self.detector.evaluate(fv)
        
        self.assertEqual(signal.indicators["tls_completeness"], 0.75)
        self.assertFalse(signal.indicators["has_ja3"])

    def test_missing_ja4(self):
        fv = self.create_mock_fv(ja3="j3", sni="test.com", alpn="h2")
        signal = self.detector.evaluate(fv)
        self.assertEqual(signal.indicators["tls_completeness"], 0.75)

    def test_missing_alpn(self):
        """Missing ALPN with SNI present slightly increases metadata anomaly."""
        fv_complete = self.create_mock_fv(ja3="j3", sni="test.com", alpn="h2")
        fv_no_alpn = self.create_mock_fv(ja3="j3", sni="test.com")
        
        sig1 = self.detector.evaluate(fv_complete)
        sig2 = self.detector.evaluate(fv_no_alpn)
        
        self.assertGreater(sig2.indicators["comp_metadata_anomaly"], sig1.indicators["comp_metadata_anomaly"])

    def test_completely_missing_tls_metadata(self):
        """Test handling of no TLS metadata."""
        fv = self.create_mock_fv()
        signal = self.detector.evaluate(fv)
        
        self.assertEqual(signal.indicators.get("encrypted_threat_score", 0.0), 0.0)
        self.assertEqual(signal.confidence, 0.0)
        self.assertIn("reason", signal.indicators)

    def test_partial_metadata(self):
        """QUIC connection with only SNI and ALPN."""
        fv = self.create_mock_fv(sni="quic.com", alpn="h3")
        signal = self.detector.evaluate(fv)
        
        self.assertEqual(signal.indicators["tls_completeness"], 0.5)

    def test_normal_tls_plus_normal_temporal_context(self):
        """TLS + benign behavioral context -> low suspicion."""
        fv = self.create_mock_fv(ja3="j3", sni="test.com", alpn="h2", periodicity=0.1, jitter=80.0)
        signal = self.detector.evaluate(fv)
        
        self.assertLess(signal.indicators["encrypted_threat_score"], 0.2)
        self.assertLess(signal.confidence, 0.1)
        self.assertEqual(signal.severity, Severity.INFO)

    def test_tls_plus_suspicious_temporal_context(self):
        """TLS + strong behavioral context (beaconing) -> high suspicion."""
        fv_benign = self.create_mock_fv(ja3="j3", sni="test.com", alpn="h2", periodicity=0.1, jitter=80.0)
        fv_sus = self.create_mock_fv(ja3="j3", sni="test.com", alpn="h2", periodicity=1.0, jitter=0.0)
        
        sig_benign = self.detector.evaluate(fv_benign)
        sig_sus = self.detector.evaluate(fv_sus)
        
        self.assertGreater(sig_sus.indicators["encrypted_threat_score"], sig_benign.indicators["encrypted_threat_score"])
        self.assertEqual(sig_sus.indicators["comp_behavioural"], 1.0)
        self.assertGreater(sig_sus.confidence, 0.4)

    def test_score_and_confidence_bounds(self):
        fv = self.create_mock_fv(ja3="j3", periodicity=1.0, jitter=0.0)
        signal = self.detector.evaluate(fv)
        
        self.assertLessEqual(signal.indicators["encrypted_threat_score"], 1.0)
        self.assertGreaterEqual(signal.indicators["encrypted_threat_score"], 0.0)
        self.assertLessEqual(signal.confidence, 1.0)
        self.assertGreaterEqual(signal.confidence, 0.0)

    def test_detection_signal_schema_validity(self):
        fv = self.create_mock_fv(ja3="j3", sni="test.com", periodicity=0.8, jitter=10.0)
        signal = self.detector.evaluate(fv)
        
        self.assertIsInstance(signal, DetectionSignal)
        json_data = signal.model_dump_json()
        self.assertIn("ENCRYPTED_MALWARE", json_data)

    def test_evidence_completeness_and_deterministic_output(self):
        fv = self.create_mock_fv(ja3="j3", sni="test.com", alpn="h2")
        sig1 = self.detector.evaluate(fv)
        sig2 = self.detector.evaluate(fv)
        
        self.assertEqual(sig1.confidence, sig2.confidence)
        self.assertEqual(sig1.indicators["encrypted_threat_score"], sig2.indicators["encrypted_threat_score"])
        self.assertIn("comp_metadata_anomaly", sig1.indicators)
        self.assertIn("comp_behavioural", sig1.indicators)
        self.assertIn("has_ja3", sig1.indicators)
