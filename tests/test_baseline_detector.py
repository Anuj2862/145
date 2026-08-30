import unittest

from detectors.baseline import BaselineConfig, BaselineDetector
from features.flow_features import FlowFeatures


def _features(
    packet_count: int = 0,
    duration: float = 0.0,
    packet_rate: float = 0.0,
    syn_ratio: float = 0.0,
    ack_ratio: float = 0.0,
) -> FlowFeatures:
    return FlowFeatures(
        protocol=6,
        src_port=49152,
        dst_port=443,
        packet_count=packet_count,
        byte_count=0,
        duration=duration,
        packet_rate=packet_rate,
        byte_rate=0.0,
        syn_count=0,
        ack_count=0,
        fin_count=0,
        rst_count=0,
        psh_count=0,
        urg_count=0,
        syn_ratio=syn_ratio,
        ack_ratio=ack_ratio,
        fin_ratio=0.0,
        rst_ratio=0.0,
        packet_length_min=0.0,
        packet_length_max=0.0,
        packet_length_mean=0.0,
        packet_length_std=0.0,
        iat_mean_ms=0.0,
        iat_std_ms=0.0,
        iat_min_ms=0.0,
        iat_max_ms=0.0,
        packet_lengths=(),
        inter_arrival_times_ms=(),
    )


class TestBaselineDetector(unittest.TestCase):
    def setUp(self):
        self.config = BaselineConfig(
            syn_flood_min_packet_count=10,
            syn_flood_min_duration=1.0,
            syn_flood_min_packet_rate=25.0,
            syn_flood_min_syn_ratio=0.7,
            syn_flood_max_ack_ratio=0.2,
        )
        self.detector = BaselineDetector(self.config)

    def test_normal_tcp_flow_does_not_trigger_syn_flood(self):
        alerts = self.detector.detect(
            features=_features(
                packet_count=20,
                duration=2.0,
                packet_rate=10.0,
                syn_ratio=0.05,
                ack_ratio=0.9,
            ),
            flow_id="normal-flow",
            timestamp="2026-08-30T10:00:00Z",
        )

        self.assertEqual(alerts, [])

    def test_high_syn_ratio_high_packet_rate_low_ack_ratio_triggers(self):
        alerts = self.detector.detect(
            features=_features(
                packet_count=100,
                duration=2.0,
                packet_rate=50.0,
                syn_ratio=0.95,
                ack_ratio=0.01,
            ),
            flow_id="suspect-flow",
            timestamp="2026-08-30T10:00:01Z",
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].flow_id, "suspect-flow")
        self.assertEqual(alerts[0].threat_class, "SYN_FLOOD_SUSPECTED")
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_boundary_values_trigger_inclusively(self):
        alerts = self.detector.detect(
            features=_features(
                packet_count=self.config.syn_flood_min_packet_count,
                duration=self.config.syn_flood_min_duration,
                packet_rate=self.config.syn_flood_min_packet_rate,
                syn_ratio=self.config.syn_flood_min_syn_ratio,
                ack_ratio=self.config.syn_flood_max_ack_ratio,
            ),
            flow_id="boundary-flow",
            timestamp="2026-08-30T10:00:02Z",
        )

        self.assertEqual(len(alerts), 1)

    def test_below_boundary_values_do_not_trigger(self):
        cases = [
            _features(
                packet_count=self.config.syn_flood_min_packet_count - 1,
                duration=self.config.syn_flood_min_duration,
                packet_rate=self.config.syn_flood_min_packet_rate,
                syn_ratio=self.config.syn_flood_min_syn_ratio,
                ack_ratio=self.config.syn_flood_max_ack_ratio,
            ),
            _features(
                packet_count=self.config.syn_flood_min_packet_count,
                duration=self.config.syn_flood_min_duration - 0.1,
                packet_rate=self.config.syn_flood_min_packet_rate,
                syn_ratio=self.config.syn_flood_min_syn_ratio,
                ack_ratio=self.config.syn_flood_max_ack_ratio,
            ),
            _features(
                packet_count=self.config.syn_flood_min_packet_count,
                duration=self.config.syn_flood_min_duration,
                packet_rate=self.config.syn_flood_min_packet_rate - 0.1,
                syn_ratio=self.config.syn_flood_min_syn_ratio,
                ack_ratio=self.config.syn_flood_max_ack_ratio,
            ),
            _features(
                packet_count=self.config.syn_flood_min_packet_count,
                duration=self.config.syn_flood_min_duration,
                packet_rate=self.config.syn_flood_min_packet_rate,
                syn_ratio=self.config.syn_flood_min_syn_ratio - 0.1,
                ack_ratio=self.config.syn_flood_max_ack_ratio,
            ),
            _features(
                packet_count=self.config.syn_flood_min_packet_count,
                duration=self.config.syn_flood_min_duration,
                packet_rate=self.config.syn_flood_min_packet_rate,
                syn_ratio=self.config.syn_flood_min_syn_ratio,
                ack_ratio=self.config.syn_flood_max_ack_ratio + 0.1,
            ),
        ]

        for features in cases:
            with self.subTest(features=features):
                alerts = self.detector.detect(
                    features=features,
                    flow_id="below-boundary-flow",
                    timestamp="2026-08-30T10:00:03Z",
                )
                self.assertEqual(alerts, [])

    def test_empty_features_do_not_crash_or_trigger(self):
        alerts = self.detector.detect(
            features=_features(),
            flow_id="empty-flow",
            timestamp="2026-08-30T10:00:04Z",
        )

        self.assertEqual(alerts, [])

    def test_confidence_remains_within_zero_and_one(self):
        alerts = self.detector.detect(
            features=_features(
                packet_count=10_000,
                duration=100.0,
                packet_rate=10_000.0,
                syn_ratio=1.0,
                ack_ratio=0.0,
            ),
            flow_id="confidence-flow",
            timestamp="2026-08-30T10:00:05Z",
        )

        self.assertEqual(len(alerts), 1)
        self.assertGreaterEqual(alerts[0].confidence, 0.0)
        self.assertLessEqual(alerts[0].confidence, 1.0)

    def test_evidence_contains_observed_trigger_features(self):
        alerts = self.detector.detect(
            features=_features(
                packet_count=100,
                duration=2.0,
                packet_rate=50.0,
                syn_ratio=0.95,
                ack_ratio=0.01,
            ),
            flow_id="evidence-flow",
            timestamp="2026-08-30T10:00:06Z",
        )

        evidence = alerts[0].evidence

        self.assertEqual(evidence["packet_rate"], 50.0)
        self.assertEqual(evidence["syn_ratio"], 0.95)
        self.assertEqual(evidence["ack_ratio"], 0.01)
        self.assertEqual(evidence["packet_count"], 100)
        self.assertEqual(evidence["duration"], 2.0)
        self.assertIn("thresholds", evidence)


if __name__ == "__main__":
    unittest.main()
