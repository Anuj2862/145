"""Integration and pipeline verification tests for Member 3 (Milestone 1)."""

import unittest
import json
from schemas import (
    DetectionSignal,
    ThreatClass,
    DetectorType,
    Severity,
    Alert,
)
from incidents.verifier import run_milestone1_verification
from incidents.alert_builder import build_alert_from_signal
from incidents.formatter import alert_to_json, format_alert_cli


class TestMilestone1Integration(unittest.TestCase):
    def test_run_milestone1_verification_pipeline(self):
        """Test the complete Milestone 1 mock pipeline execution."""
        alert_obj, alert_json, alert_cli = run_milestone1_verification()

        # 1. Validate Alert object
        self.assertIsInstance(alert_obj, Alert)
        self.assertEqual(alert_obj.threat_class, ThreatClass.VOLUMETRIC_DDOS)
        self.assertEqual(alert_obj.source_ip, "198.51.100.42")
        self.assertEqual(alert_obj.destination_ip, "10.0.0.1")
        self.assertGreater(alert_obj.confidence, 0.70)

        # 2. Validate JSON string
        parsed = json.loads(alert_json)
        self.assertEqual(parsed["alert_id"], alert_obj.alert_id)
        self.assertEqual(parsed["threat_class"], "VOLUMETRIC_DDOS")

        # 3. Validate CLI output
        self.assertIn("SECURITY ALERT", alert_cli)
        self.assertIn(alert_obj.alert_id, alert_cli)
        self.assertIn("VOLUMETRIC_DDOS", alert_cli)
        self.assertIn("Packets Per Sec:", alert_cli)

    def test_multi_threat_class_alert_conversion(self):
        """Verify that Alert Builder handles multiple threat categories cleanly."""
        threat_samples = [
            (ThreatClass.RECON_PORT_SCAN, Severity.MEDIUM, 0.82, {"destination_ports_scanned": 120}),
            (ThreatClass.BOTNET_C2_BEACONING, Severity.HIGH, 0.88, {"periodicity_score": 0.94, "jitter_pct": 5.2}),
            (ThreatClass.DGA_DNS_TUNNELLING, Severity.HIGH, 0.91, {"entropy_mean": 3.85, "nxdomain_count": 45}),
        ]

        for tc, sev, conf, ind in threat_samples:
            sig = DetectionSignal(
                signal_id=f"sig-{tc.value.lower()}",
                threat_class=tc,
                detector_type=DetectorType.DETERMINISTIC_BASELINE,
                confidence=conf,
                severity=sev,
                source_entity="10.0.0.99",
                target_entity="203.0.113.5",
                timestamp_iso="2026-08-30T12:00:00Z",
                indicators=ind,
            )

            alert = build_alert_from_signal(sig, protocol=6)
            self.assertEqual(alert.threat_class, tc)
            self.assertEqual(alert.severity, sev)
            self.assertEqual(alert.confidence, conf)
            
            json_str = alert_to_json(alert)
            self.assertIn(tc.value, json_str)


if __name__ == "__main__":
    unittest.main()
