"""Unit tests for Incident Builder (Member 3)."""

import unittest
from incidents.incident_builder import IncidentBuilder
from fusion.engine import ActiveCorrelationGroup
from entity.memory import EntityMemory
from entity.graph import EntityBehaviourGraph
from schemas import DetectionSignal, ThreatClass, DetectorType, Severity, Incident, Alert


class TestIncidentBuilder(unittest.TestCase):
    def setUp(self):
        self.builder = IncidentBuilder()
        self.memory = EntityMemory()
        self.graph = EntityBehaviourGraph()

    def test_build_incident_and_alert(self):
        group = ActiveCorrelationGroup("10.0.0.99")
        sig = DetectionSignal(
            signal_id="sig-ddos-99",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.92,
            severity=Severity.HIGH,
            source_entity="10.0.0.99",
            target_entity="198.51.100.1",
            timestamp_iso="2026-08-31T12:00:00Z",
            indicators={"packets_per_sec": 10000.0, "syn_ratio": 0.99},
        )
        group.add_signal(sig)

        incident = self.builder.build_incident_from_group(group, self.memory, self.graph)

        self.assertIsInstance(incident, Incident)
        self.assertEqual(incident.primary_entity, "10.0.0.99")
        self.assertGreaterEqual(incident.risk_score, 0.92)
        self.assertEqual(len(incident.threat_stages), 1)
        self.assertGreaterEqual(len(incident.evidence_items), 1)

        alert = self.builder.build_incident_alert(incident, sig)
        self.assertIsInstance(alert, Alert)
        self.assertEqual(alert.incident_id, incident.incident_id)
        self.assertIn(incident.incident_id, alert.summary)


if __name__ == "__main__":
    unittest.main()
