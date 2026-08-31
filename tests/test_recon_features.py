import unittest
from schemas import FlowEvent, TCPFlags
from features.recon_features import aggregate_recon_features, ReconFeatures


def make_flow(src_ip="10.0.0.1", dst_ip="192.168.1.1", dst_port=80,
              byte_count=500, rst_count=0, src_port=10000, protocol=6) -> FlowEvent:
    """Minimal FlowEvent factory."""
    return FlowEvent(
        flow_id=f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        start_time_iso="2026-08-30T10:00:00Z",
        end_time_iso="2026-08-30T10:00:05Z",
        duration_sec=5.0,
        packet_count=10,
        byte_count=byte_count,
        tcp_flags=TCPFlags(rst_count=rst_count) if rst_count > 0 else None,
    )


class TestReconFeatures(unittest.TestCase):

    def test_single_normal_flow(self):
        """One normal flow — insufficient evidence, no scanning detected."""
        flows = [make_flow()]
        rf = aggregate_recon_features(flows, min_flows_required=3)

        self.assertEqual(rf.flow_count, 1)
        self.assertEqual(rf.unique_dst_ip_count, 1)
        self.assertEqual(rf.unique_dst_port_count, 1)
        self.assertFalse(rf.sufficient_evidence)
        self.assertFalse(rf.is_horizontal)
        self.assertFalse(rf.is_vertical)
        self.assertFalse(rf.is_broad)

    def test_many_destinations_horizontal(self):
        """Many unique destination IPs — horizontal scan pattern."""
        flows = [make_flow(dst_ip=f"10.1.1.{i}", dst_port=80) for i in range(10)]
        rf = aggregate_recon_features(flows, min_flows_required=3)

        self.assertEqual(rf.unique_dst_ip_count, 10)
        self.assertEqual(rf.unique_dst_port_count, 1)
        self.assertTrue(rf.is_horizontal)
        self.assertFalse(rf.is_vertical)
        self.assertFalse(rf.is_broad)

    def test_many_ports_vertical(self):
        """Many unique destination ports on same IP — vertical scan pattern."""
        flows = [make_flow(dst_ip="192.168.1.1", dst_port=p, src_port=10000 + p)
                 for p in range(1, 12)]
        rf = aggregate_recon_features(flows, min_flows_required=3)

        self.assertEqual(rf.unique_dst_ip_count, 1)
        self.assertGreaterEqual(rf.unique_dst_port_count, 5)
        self.assertFalse(rf.is_horizontal)
        self.assertTrue(rf.is_vertical)
        self.assertFalse(rf.is_broad)

    def test_many_ips_and_ports_broad(self):
        """Many IPs and many ports — broad scan."""
        flows = [make_flow(dst_ip=f"10.1.{i // 10}.{i % 10}", dst_port=(22 + i) % 65535)
                 for i in range(50)]
        rf = aggregate_recon_features(flows, min_flows_required=3)

        self.assertGreaterEqual(rf.unique_dst_ip_count, 5)
        self.assertGreaterEqual(rf.unique_dst_port_count, 5)
        self.assertTrue(rf.is_broad)

    def test_failed_connection_ratio_heuristic(self):
        """Zero-byte flows are proxied as failed connections."""
        flows = [
            make_flow(byte_count=0),    # failed
            make_flow(byte_count=0),    # failed
            make_flow(byte_count=500),  # success
            make_flow(byte_count=200),  # success
        ]
        rf = aggregate_recon_features(flows)

        self.assertEqual(rf.failed_connection_count, 2)
        self.assertAlmostEqual(rf.failed_connection_ratio, 0.5)

    def test_empty_flow_list(self):
        """Empty input returns zeroed ReconFeatures without crashing."""
        rf = aggregate_recon_features([])

        self.assertEqual(rf.flow_count, 0)
        self.assertEqual(rf.unique_dst_ip_count, 0)
        self.assertIsNone(rf.connection_rate_per_sec)
        self.assertFalse(rf.sufficient_evidence)

    def test_insufficient_evidence_flag(self):
        """Two flows below min_flows_required threshold."""
        flows = [make_flow(), make_flow(dst_port=443)]
        rf = aggregate_recon_features(flows, min_flows_required=5)
        self.assertFalse(rf.sufficient_evidence)

    def test_deterministic_aggregation(self):
        """Same flows produce the same result regardless of Python set ordering."""
        flows = [make_flow(dst_ip=f"10.0.0.{i}", dst_port=80) for i in range(6)]
        rf1 = aggregate_recon_features(flows)
        rf2 = aggregate_recon_features(flows)

        self.assertEqual(rf1.unique_dst_ip_count, rf2.unique_dst_ip_count)
        self.assertEqual(rf1.unique_dst_port_count, rf2.unique_dst_port_count)
        self.assertEqual(rf1.failed_connection_ratio, rf2.failed_connection_ratio)

    def test_connection_rate_calculation(self):
        """Rate = flow_count / window_duration_sec."""
        flows = [make_flow() for _ in range(10)]
        rf = aggregate_recon_features(flows, window_duration_sec=5.0)

        self.assertAlmostEqual(rf.connection_rate_per_sec, 2.0)

    def test_rst_based_failed_detection(self):
        """RST flag + small byte count is also treated as failed."""
        flows = [
            make_flow(byte_count=40, rst_count=1),   # likely RST-closed
            make_flow(byte_count=500),                # normal
        ]
        rf = aggregate_recon_features(flows, min_flows_required=2)
        self.assertEqual(rf.failed_connection_count, 1)
