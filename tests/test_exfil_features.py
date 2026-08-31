import unittest
from schemas import FlowEvent
from features.exfil_features import aggregate_exfil_features, ExfiltrationFeatures

ENTITY = "10.0.0.1"


def make_flow(src_ip=ENTITY, dst_ip="1.2.3.4", dst_port=443,
              byte_count=1000, start="2026-08-30T10:00:00Z",
              end="2026-08-30T10:00:10Z") -> FlowEvent:
    return FlowEvent(
        flow_id=f"{src_ip}:50000-{dst_ip}:{dst_port}-6",
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=50000, dst_port=dst_port,
        protocol=6,
        start_time_iso=start,
        end_time_iso=end,
        duration_sec=10.0,
        packet_count=10,
        byte_count=byte_count,
    )


class TestExfilFeatures(unittest.TestCase):

    def test_normal_balanced_traffic(self):
        """Equal outbound and inbound traffic — benign pattern."""
        flows = [
            make_flow(src_ip=ENTITY, dst_ip="1.2.3.4", byte_count=1000),
            make_flow(src_ip="1.2.3.4", dst_ip=ENTITY, byte_count=950),
        ]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=2)

        self.assertEqual(ef.total_outbound_bytes, 1000)
        self.assertEqual(ef.total_inbound_bytes, 950)
        self.assertAlmostEqual(ef.upload_download_ratio, 1000 / 950)
        self.assertTrue(ef.sufficient_evidence)

    def test_high_outbound_traffic(self):
        """High outbound, low inbound."""
        flows = [
            make_flow(src_ip=ENTITY, byte_count=50_000_000),  # 50 MB out
            make_flow(src_ip="1.2.3.4", dst_ip=ENTITY, byte_count=100),   # tiny in
        ]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=2)

        self.assertEqual(ef.total_outbound_bytes, 50_000_000)
        self.assertGreater(ef.upload_download_ratio, 100)

    def test_large_single_transfer(self):
        """Single large transfer is identified."""
        flows = [make_flow(byte_count=2_000_000)]   # 2 MB > 1 MB threshold
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY,
                                       large_transfer_bytes=1_000_000,
                                       min_flows_required=1)

        self.assertEqual(ef.large_transfer_count, 1)
        self.assertEqual(ef.maximum_single_flow_bytes, 2_000_000)

    def test_multiple_large_transfers(self):
        """Multiple large flows all counted."""
        flows = [make_flow(byte_count=1_500_000) for _ in range(4)]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY,
                                       large_transfer_bytes=1_000_000,
                                       min_flows_required=3)

        self.assertEqual(ef.large_transfer_count, 4)

    def test_high_outbound_rate(self):
        """Short window + large volume = high rate."""
        flows = [make_flow(byte_count=5_000_000,
                           start="2026-08-30T10:00:00Z",
                           end="2026-08-30T10:00:01Z")]  # 1-second window
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=1)

        # Window is derived from timestamps: 1 second
        self.assertTrue(ef.window_derived_from_timestamps)
        self.assertAlmostEqual(ef.outbound_bytes_per_sec, 5_000_000.0, delta=1.0)

    def test_low_inbound_high_outbound_ratio(self):
        """Near-zero inbound yields None ratio (zero-division guard)."""
        flows = [make_flow(src_ip=ENTITY, byte_count=1_000_000)]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=1)

        self.assertIsNone(ef.upload_download_ratio)  # inbound == 0

    def test_empty_flow_list(self):
        """Empty input returns zeroed features without crashing."""
        ef = aggregate_exfil_features([], entity_ip=ENTITY)
        self.assertEqual(ef.flow_count, 0)
        self.assertIsNone(ef.outbound_bytes_per_sec)
        self.assertFalse(ef.sufficient_evidence)

    def test_single_flow(self):
        """A single flow below min_flows_required is insufficient evidence."""
        flows = [make_flow()]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=3)
        self.assertEqual(ef.flow_count, 1)
        self.assertFalse(ef.sufficient_evidence)

    def test_zero_duration_fallback(self):
        """Flows with same start/end timestamps fall back to configured window."""
        flows = [
            make_flow(start="2026-08-30T10:00:00Z", end="2026-08-30T10:00:00Z"),
            make_flow(start="2026-08-30T10:00:00Z", end="2026-08-30T10:00:00Z"),
        ]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY,
                                       window_duration_sec=30.0,
                                       min_flows_required=2)

        # Window is 0 sec from timestamps → falls back to 30.0
        self.assertFalse(ef.window_derived_from_timestamps)
        self.assertEqual(ef.window_duration_sec, 30.0)

    def test_deterministic_output(self):
        """Same flows always yield identical features."""
        flows = [make_flow(byte_count=i * 100_000) for i in range(1, 6)]
        ef1 = aggregate_exfil_features(flows, entity_ip=ENTITY)
        ef2 = aggregate_exfil_features(flows, entity_ip=ENTITY)

        self.assertEqual(ef1.total_outbound_bytes, ef2.total_outbound_bytes)
        self.assertEqual(ef1.large_transfer_count, ef2.large_transfer_count)
        self.assertEqual(ef1.outbound_bytes_per_sec, ef2.outbound_bytes_per_sec)

    def test_direction_unavailable_when_no_entity_match(self):
        """Flows whose IPs don't match entity_ip set direction_available=False."""
        flows = [
            make_flow(src_ip="9.9.9.9", dst_ip="8.8.8.8"),
        ]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=1)
        self.assertFalse(ef.direction_available)

    def test_ratio_zero_division_safety(self):
        """Pure-outbound scenario — no inbound bytes — ratio is None."""
        flows = [make_flow(src_ip=ENTITY, byte_count=1000) for _ in range(3)]
        ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=3)
        self.assertIsNone(ef.upload_download_ratio)
