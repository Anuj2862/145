"""Unit tests for Multi-Signal Fusion Engine (Member 3)."""

import unittest
from fusion.engine import MultiSignalFusionEngine
from entity.memory import EntityMemory
from entity.graph import EntityBehaviourGraph
from schemas import DetectionSignal, ThreatClass, DetectorType, Severity


class TestFusionEngine(unittest.TestCase):
    def setUp(self):
        self.fusion = MultiSignalFusionEngine(correlation_window_sec=300)
        self.memory = EntityMemory()
        self.graph = EntityBehaviourGraph()

    def test_single_signal_fusion(self):
        sig = DetectionSignal(
            signal_id="sig-single-01",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.85,
            severity=Severity.HIGH,
            source_entity="10.0.0.10",
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        group, risk, sev = self.fusion.process_signal(sig, self.memory, self.graph)

        self.assertEqual(len(group.signals), 1)
        self.assertAlmostEqual(risk, 0.85)
        self.assertEqual(sev, Severity.HIGH)

    def test_multi_signal_correlation_boost(self):
        # 1. Recon signal
        sig1 = DetectionSignal(
            signal_id="sig-01",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.75,
            severity=Severity.MEDIUM,
            source_entity="10.0.0.25",
            target_entity="198.51.100.2",
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        # 2. C2 Beacon signal from same entity
        sig2 = DetectionSignal(
            signal_id="sig-02",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            detector_type=DetectorType.LIGHTWEIGHT_ML,
            confidence=0.88,
            severity=Severity.HIGH,
            source_entity="10.0.0.25",
            target_entity="198.51.100.2",
            timestamp_iso="2026-08-31T12:02:00Z",
        )

        self.fusion.process_signal(sig1, self.memory, self.graph)
        group, risk, sev = self.fusion.process_signal(sig2, self.memory, self.graph)

        self.assertEqual(len(group.signals), 2)
        # Multi-threat diversity + multi-detector agreement bonus elevates risk
        self.assertGreater(risk, 0.88)
        self.assertEqual(sev, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
