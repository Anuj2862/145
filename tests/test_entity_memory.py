"""Unit tests for Entity Memory and Historical Baseline Profiler (Member 3)."""

import unittest
from entity.memory import EntityMemory, EntityProfile
from schemas import FeatureVector, FlowFeatures, DetectionSignal, ThreatClass, Severity, DetectorType


class TestEntityMemory(unittest.TestCase):
    def setUp(self):
        self.memory = EntityMemory(max_entities=100, history_window_size=10)

    def test_profile_creation_and_update(self):
        profile = self.memory.get_or_create_profile("10.0.0.42")
        self.assertEqual(profile.entity_id, "10.0.0.42")
        self.assertEqual(profile.total_observations, 0)

        fv = FeatureVector(
            feature_id="fv-01",
            entity_ip="10.0.0.42",
            timestamp_iso="2026-08-31T12:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=100.0, bytes_per_sec=50000.0),
        )
        profile.update_from_feature_vector(fv)

        self.assertEqual(profile.total_observations, 1)
        self.assertEqual(len(profile.pps_history), 1)

    def test_pps_z_score_calculation(self):
        profile = self.memory.get_or_create_profile("10.0.0.50")
        
        # Populate stable history: 100 pps with slight variations
        for pps in [98.0, 102.0, 100.0, 99.0, 101.0, 100.0]:
            fv = FeatureVector(
                feature_id="fv-x",
                entity_ip="10.0.0.50",
                timestamp_iso="2026-08-31T12:00:00Z",
                flow_features=FlowFeatures(packets_per_sec=pps, bytes_per_sec=pps*500),
            )
            profile.update_from_feature_vector(fv)

        # Baseline: mean ~100, std ~1.41
        normal_z = profile.compute_pps_z_score(102.0)
        self.assertLess(normal_z, 2.0)

        # Severe burst: 5000 pps -> Z-score >> 10.0
        burst_z = profile.compute_pps_z_score(5000.0)
        self.assertGreater(burst_z, 10.0)

    def test_destination_recording(self):
        profile = self.memory.get_or_create_profile("10.0.0.60")
        is_new1 = profile.record_destination("198.51.100.1", 443)
        self.assertTrue(is_new1)

        is_new2 = profile.record_destination("198.51.100.1", 443)
        self.assertFalse(is_new2)
        self.assertIn(443, profile.known_ports)

    def test_entity_event_evaluation(self):
        sig = DetectionSignal(
            signal_id="sig-test-01",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.90,
            severity=Severity.HIGH,
            source_entity="10.0.0.70",
            target_entity="198.51.100.2",
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        self.memory.record_signal(sig)
        event = self.memory.evaluate_entity_event("10.0.0.70", current_pps=500.0)

        self.assertEqual(event.entity_id, "10.0.0.70")
        self.assertIn("sig-test-01", event.active_signals)
        self.assertEqual(event.known_destinations_count, 1)


if __name__ == "__main__":
    unittest.main()
