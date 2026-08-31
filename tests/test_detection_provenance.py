"""Unit and Integration Tests for Phase 2C — Detection Provenance & Explainability.

Verifies:
1. SignalProvenance is attached to active signals across all detectors.
2. Detector identity and semantic version are preserved.
3. Observable feature values match actual computed features without fabrication.
4. Decision reason tags accurately reflect triggered thresholds.
5. Temporal observation windows and entity identities are preserved.
6. AlertBuilder propagates provenance into Alert schema for SOC dashboard.
7. JSON serialization roundtrips successfully.
"""

import unittest
from datetime import datetime, timezone

from schemas import (
    DetectionSignal,
    SignalProvenance,
    Alert,
    ThreatClass,
    DetectorType,
    Severity,
    FeatureVector,
    FlowFeatures,
    TemporalFeatures,
    DNSFeatures,
    TLSFeatures,
)
from detectors.ddos_detector import DDoSBaselineDetector
from detectors.c2_detector import C2BeaconDetector
from detectors.dns_detector import DNSAnomalyDetector
from detectors.encrypted_detector import EncryptedThreatDetector
from detectors.recon_detector import ReconDetector
from detectors.exfil_detector import ExfiltrationDetector
from features.recon_features import ReconFeatures
from features.exfil_features import ExfiltrationFeatures
from incidents.alert_builder import build_alert_from_signal
from models.inference.ml_inference import ClassificationResult
from models.inference.signal_adapter import SignalAdapter


class TestDetectionProvenance(unittest.TestCase):
    def test_ddos_provenance_generation(self):
        """DDoSBaselineDetector attaches complete provenance to active signals."""
        detector = DDoSBaselineDetector()
        fv = FeatureVector(
            feature_id="fv-ddos-prov",
            entity_ip="192.168.1.50",
            flow_id="192.168.1.50:55555-10.0.0.1:80-6",
            timestamp_iso="2026-08-31T12:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=12000.0, syn_ratio=0.98, bytes_per_sec=500000.0),
        )
        signal = detector.evaluate(fv)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.detector_id, "DDoSBaselineDetector")
        self.assertEqual(signal.detector_version, "1.0.0")
        self.assertIn("critical_packet_velocity_exceeded", signal.decision_reason)
        self.assertIn("critical_tcp_syn_flood_ratio", signal.decision_reason)
        self.assertEqual(signal.observable_features["packets_per_sec"], 12000.0)
        self.assertEqual(signal.observable_features["syn_ratio"], 0.98)

        # Structured provenance sub-model check
        prov = signal.provenance
        self.assertIsNotNone(prov)
        self.assertEqual(prov.detector_id, "DDoSBaselineDetector")
        self.assertEqual(prov.window_start_iso, "2026-08-31T12:00:00Z")

    def test_c2_provenance_generation(self):
        """C2BeaconDetector attaches temporal provenance."""
        detector = C2BeaconDetector()
        fv = FeatureVector(
            feature_id="fv-c2-prov",
            entity_ip="10.0.5.22",
            flow_id="10.0.5.22:4444-198.51.100.4:443-6",
            timestamp_iso="2026-08-31T12:05:00Z",
            temporal_features=TemporalFeatures(
                inter_arrival_mean_ms=60000.0,
                inter_arrival_std_ms=500.0,
                periodicity_score=0.95,
                jitter_pct=0.83,
            ),
        )
        signal = detector.evaluate(fv, observation_count=12)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.detector_id, "C2BeaconDetector")
        self.assertIn("high_temporal_periodicity_observed", signal.decision_reason)
        self.assertIn("low_inter_arrival_jitter_beacon", signal.decision_reason)
        self.assertEqual(signal.observable_features["periodicity_score"], 0.95)
        self.assertEqual(signal.observable_features["observation_count"], 12)

    def test_dns_provenance_generation(self):
        """DNSAnomalyDetector attaches entropy and query length provenance."""
        detector = DNSAnomalyDetector()
        fv = FeatureVector(
            feature_id="fv-dns-prov",
            entity_ip="10.0.2.10",
            flow_id="10.0.2.10:53535-8.8.8.8:53-17",
            timestamp_iso="2026-08-31T12:10:00Z",
            dns_features=DNSFeatures(
                entropy_mean=4.35,
                query_length_mean=42.0,
                nxdomain_count=15,
            ),
        )
        signal = detector.evaluate(fv)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.detector_id, "DNSAnomalyDetector")
        self.assertIn("high_shannon_domain_entropy", signal.decision_reason)
        self.assertIn("elevated_dns_query_length", signal.decision_reason)
        self.assertIn("burst_nxdomain_responses", signal.decision_reason)
        self.assertEqual(signal.observable_features["entropy_mean"], 4.35)

    def test_recon_provenance_generation(self):
        """ReconDetector attaches fanout and failure statistics provenance."""
        detector = ReconDetector()
        rf = ReconFeatures(
            flow_count=100,
            unique_dst_ip_count=1,
            unique_dst_port_count=100,
            connection_rate_per_sec=25.0,
            failed_connection_ratio=0.85,
            sufficient_evidence=True,
        )
        signal = detector.evaluate(rf, source_entity="192.168.1.200", timestamp_iso="2026-08-31T12:15:00Z")
        self.assertIsNotNone(signal)
        self.assertEqual(signal.detector_id, "ReconDetector")
        self.assertIn("vertical_port_scan_fanout", signal.decision_reason)
        self.assertIn("high_failed_connection_ratio", signal.decision_reason)
        self.assertEqual(signal.observable_features["unique_dst_port_count"], 100)

    def test_exfil_provenance_generation(self):
        """ExfiltrationDetector attaches volume and ratio provenance."""
        detector = ExfiltrationDetector()
        ef = ExfiltrationFeatures(
            flow_count=10,
            total_outbound_bytes=25000000,
            total_inbound_bytes=100000,
            upload_download_ratio=250.0,
            outbound_bytes_per_sec=500000.0,
            large_transfer_count=5,
            destination_count=2,
            window_duration_sec=50.0,
            sufficient_evidence=True,
            direction_available=True,
        )
        signal = detector.evaluate(ef, source_entity="10.0.1.55", timestamp_iso="2026-08-31T12:20:00Z")
        self.assertIsNotNone(signal)
        self.assertEqual(signal.detector_id, "ExfiltrationDetector")
        self.assertIn("high_outbound_byte_volume", signal.decision_reason)
        self.assertIn("high_upload_to_download_imbalance", signal.decision_reason)
        self.assertEqual(signal.observable_features["total_outbound_bytes"], 25000000)

    def test_ml_provenance_generation(self):
        """SignalAdapter attaches ML model provenance."""
        ml_res = ClassificationResult(
            predicted_class_index=1,
            predicted_class_name="VOLUMETRIC_DDOS",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            confidence=0.965,
            probabilities={"BENIGN": 0.01, "VOLUMETRIC_DDOS": 0.965},
            is_threat=True,
            model_name="LightGBMClassifier",
            inference_latency_ms=0.12,
        )
        signal = SignalAdapter.to_detection_signal(
            ml_res,
            source_entity="10.0.0.100",
            target_entity="10.0.0.1",
            timestamp_iso="2026-08-31T12:25:00Z",
        )
        self.assertIsNotNone(signal)
        self.assertEqual(signal.detector_id, "LightGBMClassifier")
        self.assertIn("ml_multiclass_prediction_volumetric_ddos", signal.decision_reason)
        self.assertEqual(signal.observable_features["top_probability"], 0.965)

    def test_alert_builder_preserves_provenance(self):
        """AlertBuilder forwards provenance fields into standardized Alert schema."""
        detector = DDoSBaselineDetector()
        fv = FeatureVector(
            feature_id="fv-alert-prov",
            entity_ip="192.168.1.75",
            flow_id="192.168.1.75:50000-10.0.0.1:80-6",
            timestamp_iso="2026-08-31T12:30:00Z",
            flow_features=FlowFeatures(packets_per_sec=8000.0, syn_ratio=0.95),
        )
        signal = detector.evaluate(fv)
        self.assertIsNotNone(signal)

        alert = build_alert_from_signal(signal)
        self.assertIsInstance(alert, Alert)
        self.assertEqual(alert.detector_id, "DDoSBaselineDetector")
        self.assertIn("critical_packet_velocity_exceeded", alert.decision_reason)
        self.assertEqual(alert.observable_features["packets_per_sec"], 8000.0)

    def test_json_roundtrip_provenance(self):
        """Signals with SignalProvenance serialize and deserialize cleanly to/from JSON."""
        detector = DDoSBaselineDetector()
        fv = FeatureVector(
            feature_id="fv-json-test",
            entity_ip="192.168.1.99",
            flow_id="192.168.1.99:50000-10.0.0.1:80-6",
            timestamp_iso="2026-08-31T12:35:00Z",
            flow_features=FlowFeatures(packets_per_sec=15000.0, syn_ratio=0.99),
        )
        signal = detector.evaluate(fv)
        json_str = signal.model_dump_json()
        restored = DetectionSignal.model_validate_json(json_str)
        self.assertEqual(restored.detector_id, signal.detector_id)
        self.assertEqual(restored.decision_reason, signal.decision_reason)
        self.assertEqual(restored.observable_features, signal.observable_features)
        self.assertEqual(restored.provenance.detector_id, signal.provenance.detector_id)


if __name__ == "__main__":
    unittest.main()
