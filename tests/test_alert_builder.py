"""Unit tests for Alert Builder and Formatter (Member 3 - Milestone 1)."""

import unittest
import json
from datetime import datetime, timezone

from schemas import (
    DetectionSignal,
    ThreatClass,
    DetectorType,
    Severity,
    Alert,
)
from incidents.alert_builder import build_alert_from_signal
from incidents.formatter import alert_to_json, alert_from_json, format_alert_cli


class TestAlertBuilder(unittest.TestCase):
    def setUp(self):
        self.sample_signal = DetectionSignal(
            signal_id="sig-ddos-001",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.95,
            severity=Severity.HIGH,
            source_entity="198.51.100.42",
            target_entity="10.0.0.1",
            timestamp_iso="2026-08-30T10:00:05.000000Z",
            indicators={
                "packets_per_sec": 12500.0,
                "syn_ratio": 0.98,
            },
        )

    def test_build_alert_from_signal_preservation(self):
        """Test that all core signal fields are faithfully mapped to Alert."""
        alert = build_alert_from_signal(
            signal=self.sample_signal,
            alert_id="ALT-TEST-001",
            protocol=6,
        )

        self.assertIsInstance(alert, Alert)
        self.assertEqual(alert.alert_id, "ALT-TEST-001")
        self.assertEqual(alert.threat_class, ThreatClass.VOLUMETRIC_DDOS)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertAlmostEqual(alert.confidence, 0.95)
        self.assertEqual(alert.source_ip, "198.51.100.42")
        self.assertEqual(alert.destination_ip, "10.0.0.1")
        self.assertEqual(alert.protocol, 6)
        self.assertEqual(alert.timestamp_iso, "2026-08-30T10:00:05.000000Z")
        self.assertEqual(alert.evidence_count, 2)
        self.assertIn("Volumetric Ddos", alert.summary)
        self.assertIn("12500.0 pps", alert.summary)

    def test_auto_generate_alert_id(self):
        """Test that alert ID is automatically generated if not provided."""
        alert = build_alert_from_signal(signal=self.sample_signal)
        self.assertTrue(alert.alert_id.startswith("ALT-"))
        self.assertGreater(len(alert.alert_id), 10)

    def test_invalid_signal_type_raises_type_error(self):
        """Test that passing an invalid object raises TypeError."""
        with self.assertRaises(TypeError):
            build_alert_from_signal(signal={"not": "a_signal"})  # type: ignore

    def test_alert_json_serialization_and_deserialization(self):
        """Test round-trip JSON serialization and validation."""
        alert = build_alert_from_signal(signal=self.sample_signal, alert_id="ALT-ROUNDTRIP-001")
        json_str = alert_to_json(alert)

        # Verify it is valid JSON
        parsed_dict = json.loads(json_str)
        self.assertEqual(parsed_dict["alert_id"], "ALT-ROUNDTRIP-001")
        self.assertEqual(parsed_dict["threat_class"], "VOLUMETRIC_DDOS")
        self.assertEqual(parsed_dict["confidence"], 0.95)

        # Verify deserialization to Alert model
        reconstructed_alert = alert_from_json(json_str)
        self.assertEqual(reconstructed_alert.alert_id, alert.alert_id)
        self.assertEqual(reconstructed_alert.confidence, alert.confidence)
        self.assertEqual(reconstructed_alert.source_ip, alert.source_ip)

    def test_alert_cli_formatting(self):
        """Test terminal human-readable string generation."""
        alert = build_alert_from_signal(
            signal=self.sample_signal,
            alert_id="ALT-CLI-TEST",
            protocol=6,
        )
        cli_output = format_alert_cli(alert, indicators=self.sample_signal.indicators)

        self.assertIn("SECURITY ALERT", cli_output)
        self.assertIn("Alert ID     : ALT-CLI-TEST", cli_output)
        self.assertIn("Threat Class : VOLUMETRIC_DDOS", cli_output)
        self.assertIn("Severity     : HIGH", cli_output)
        self.assertIn("Confidence   : 0.95", cli_output)
        self.assertIn("Source       : 198.51.100.42", cli_output)
        self.assertIn("Destination  : 10.0.0.1", cli_output)
        self.assertIn("Protocol     : 6 (TCP)", cli_output)
        self.assertIn("Packets Per Sec: 12500.00", cli_output)
        self.assertIn("Syn Ratio: 0.98", cli_output)


if __name__ == "__main__":
    unittest.main()
