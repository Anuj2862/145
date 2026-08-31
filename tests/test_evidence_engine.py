"""Unit tests for Evidence Engine (Member 3)."""

import unittest
from evidence.engine import EvidenceEngine
from schemas import DetectionSignal, ThreatClass, DetectorType, Severity


class TestEvidenceEngine(unittest.TestCase):
    def test_threat_stage_mapping(self):
        sig = DetectionSignal(
            signal_id="sig-recon-01",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.85,
            severity=Severity.MEDIUM,
            source_entity="10.0.0.10",
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        stage = EvidenceEngine.map_to_threat_stage(sig)
        self.assertEqual(stage.stage, "RECONNAISSANCE")
        self.assertEqual(stage.threat_class, ThreatClass.RECON_PORT_SCAN)

    def test_ddos_evidence_generation(self):
        sig = DetectionSignal(
            signal_id="sig-ddos-01",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.95,
            severity=Severity.CRITICAL,
            source_entity="10.0.0.10",
            timestamp_iso="2026-08-31T12:00:00Z",
            indicators={
                "packets_per_sec": 15000.0,
                "syn_ratio": 0.98,
                "bytes_per_sec": 1024000.0,
            },
        )
        evidence = EvidenceEngine.generate_evidence_items(sig, baseline_deviation=4.5)
        text = " ".join(evidence)

        self.assertIn("15000.0 packets/sec", text)
        self.assertIn("98.0%", text)
        self.assertIn("+4.5σ", text)

    def test_c2_evidence_generation(self):
        sig = DetectionSignal(
            signal_id="sig-c2-01",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            detector_type=DetectorType.LIGHTWEIGHT_ML,
            confidence=0.91,
            severity=Severity.HIGH,
            source_entity="10.0.0.15",
            timestamp_iso="2026-08-31T12:00:00Z",
            indicators={
                "periodicity_score": 0.94,
                "jitter_pct": 3.8,
                "connection_count": 28,
            },
        )
        evidence = EvidenceEngine.generate_evidence_items(sig)
        text = " ".join(evidence)

        self.assertIn("0.94", text)
        self.assertIn("3.8%", text)
        self.assertIn("28 connections", text)


if __name__ == "__main__":
    unittest.main()
