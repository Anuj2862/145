import unittest
from schemas import FlowEvent
from features.temporal_features import extract_temporal_features

class TestTemporalFeatures(unittest.TestCase):
    
    def create_mock_flow(self, start_time: str) -> FlowEvent:
        return FlowEvent(
            flow_id="mock",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1000,
            dst_port=80,
            protocol=6,
            start_time_iso=start_time,
            end_time_iso=start_time,
            duration_sec=1.0,
            packet_count=10,
            byte_count=100
        )

    def test_regular_60_second_intervals(self):
        """Test with perfectly regular 60-second intervals."""
        flows = [
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:01:00Z"),
            self.create_mock_flow("2026-08-30T10:02:00Z"),
            self.create_mock_flow("2026-08-30T10:03:00Z"),
        ]
        tf = extract_temporal_features(flows)
        
        self.assertAlmostEqual(tf.inter_arrival_mean_ms, 60000.0)
        self.assertAlmostEqual(tf.inter_arrival_std_ms, 0.0)
        self.assertAlmostEqual(tf.jitter_pct, 0.0)
        self.assertAlmostEqual(tf.periodicity_score, 1.0)

    def test_slightly_irregular_intervals(self):
        """Test with small variations in intervals."""
        flows = [
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:01:01Z"), # 61s
            self.create_mock_flow("2026-08-30T10:01:59Z"), # 58s
            self.create_mock_flow("2026-08-30T10:03:00Z"), # 61s
        ]
        tf = extract_temporal_features(flows)
        
        # intervals: 61000, 58000, 61000
        # mean: 60000
        self.assertAlmostEqual(tf.inter_arrival_mean_ms, 60000.0)
        self.assertGreater(tf.inter_arrival_std_ms, 0.0)
        self.assertGreater(tf.jitter_pct, 0.0)
        self.assertLess(tf.jitter_pct, 10.0) # Small jitter
        self.assertGreater(tf.periodicity_score, 0.9) # High periodicity

    def test_highly_irregular_intervals(self):
        """Test with highly irregular, bursty intervals."""
        flows = [
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:00:01Z"), # 1s
            self.create_mock_flow("2026-08-30T10:00:05Z"), # 4s
            self.create_mock_flow("2026-08-30T10:05:00Z"), # 295s
        ]
        tf = extract_temporal_features(flows)
        
        self.assertGreater(tf.inter_arrival_std_ms, tf.inter_arrival_mean_ms)
        self.assertGreater(tf.jitter_pct, 100.0)
        self.assertEqual(tf.periodicity_score, 0.0) # Bottoms out at 0.0

    def test_only_one_event(self):
        """Test safe handling of a single event."""
        flows = [self.create_mock_flow("2026-08-30T10:00:00Z")]
        tf = extract_temporal_features(flows)
        
        self.assertIsNone(tf.inter_arrival_mean_ms)
        self.assertIsNone(tf.periodicity_score)

    def test_empty_event_list(self):
        """Test safe handling of an empty list."""
        tf = extract_temporal_features([])
        self.assertIsNone(tf.inter_arrival_mean_ms)

    def test_out_of_chronological_order(self):
        """Test that events are sorted properly before IAT calculation."""
        flows = [
            self.create_mock_flow("2026-08-30T10:03:00Z"),
            self.create_mock_flow("2026-08-30T10:01:00Z"),
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:02:00Z"),
        ]
        tf = extract_temporal_features(flows)
        
        self.assertAlmostEqual(tf.inter_arrival_mean_ms, 60000.0)
        self.assertAlmostEqual(tf.inter_arrival_std_ms, 0.0)

    def test_duplicate_timestamps(self):
        """Test handling of simultaneous events (zero intervals)."""
        flows = [
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:00:00Z"),
        ]
        tf = extract_temporal_features(flows)
        
        self.assertAlmostEqual(tf.inter_arrival_mean_ms, 0.0)
        self.assertAlmostEqual(tf.inter_arrival_std_ms, 0.0)
        self.assertAlmostEqual(tf.jitter_pct, 0.0)
        self.assertAlmostEqual(tf.periodicity_score, 1.0) # Highly regular (zero variance)

    def test_timestamp_parsing_edge_cases(self):
        """Test handling of malformed or timezone-varied timestamps."""
        flows = [
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:00:05+00:00"), # Valid
            self.create_mock_flow("NOT-A-TIMESTAMP"),           # Invalid
            self.create_mock_flow("2026-08-30T10:00:10Z"),
        ]
        tf = extract_temporal_features(flows)
        
        # Should ignore the invalid one, leaving 3 events with 5s IATs.
        self.assertAlmostEqual(tf.inter_arrival_mean_ms, 5000.0)
        self.assertAlmostEqual(tf.inter_arrival_std_ms, 0.0)
        
    def test_deterministic_output(self):
        """Verify that the exact same input always produces the exact same output."""
        flows = [
            self.create_mock_flow("2026-08-30T10:00:00Z"),
            self.create_mock_flow("2026-08-30T10:00:10Z"),
            self.create_mock_flow("2026-08-30T10:00:15Z"),
        ]
        tf1 = extract_temporal_features(flows)
        tf2 = extract_temporal_features(flows)
        
        self.assertEqual(tf1.inter_arrival_mean_ms, tf2.inter_arrival_mean_ms)
        self.assertEqual(tf1.inter_arrival_std_ms, tf2.inter_arrival_std_ms)
        self.assertEqual(tf1.periodicity_score, tf2.periodicity_score)
