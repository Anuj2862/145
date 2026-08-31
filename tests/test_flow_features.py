import unittest
from schemas import FlowEvent, TCPFlags
from features.feature_extractor import FeatureExtractor
from features.flow_features import FlowFeatures, extract_flow_features
from flow.flow_key import FlowKey
from flow.flow_state import FlowState
from ingest.pcap_reader import NormalizedPacket


# ──────────────────────────────────────────────────────────────────────────────
# M2 FlowEvent Test Suite
# ──────────────────────────────────────────────────────────────────────────────
class TestM2FlowEventFeatures(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window_size_sec=5)
        self.base_flow = FlowEvent(
            flow_id="10.0.0.1:1000-10.0.0.2:80-6",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1000,
            dst_port=80,
            protocol=6,
            start_time_iso="2026-08-30T10:00:00Z",
            end_time_iso="2026-08-30T10:00:05Z",
            duration_sec=5.0,
            packet_count=10,
            byte_count=1000,
            tcp_flags=TCPFlags(syn_count=1, ack_count=9),
            packet_lengths=[100]*10,
            inter_arrival_times_ms=[]
        )

    def test_normal_flow_extraction(self):
        """Test benign flow feature extraction."""
        fv = self.extractor.extract(self.base_flow)
        
        self.assertEqual(fv.entity_ip, "10.0.0.1")
        self.assertEqual(fv.flow_features.packets_per_sec, 2.0)
        self.assertEqual(fv.flow_features.bytes_per_sec, 200.0)
        self.assertEqual(fv.flow_features.syn_ratio, 0.1)

    def test_high_packet_rate_flow(self):
        """Test flow with high packet rate."""
        self.base_flow.packet_count = 10000
        self.base_flow.duration_sec = 2.0
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.packets_per_sec, 5000.0)

    def test_high_byte_rate_flow(self):
        """Test flow with high byte rate."""
        self.base_flow.byte_count = 5000000
        self.base_flow.duration_sec = 2.0
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.bytes_per_sec, 2500000.0)

    def test_tcp_syn_heavy_flow(self):
        """Test flow heavily weighted with SYN packets."""
        self.base_flow.packet_count = 100
        self.base_flow.tcp_flags = TCPFlags(syn_count=95, ack_count=5)
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.syn_ratio, 0.95)

    def test_zero_duration_handling(self):
        """Test safe handling of zero duration flows."""
        self.base_flow.duration_sec = 0.0
        self.base_flow.packet_count = 10
        self.base_flow.byte_count = 1000
        
        fv = self.extractor.extract(self.base_flow)
        # Should default to 1.0 duration divisor
        self.assertEqual(fv.flow_features.packets_per_sec, 10.0)
        self.assertEqual(fv.flow_features.bytes_per_sec, 1000.0)

    def test_empty_packet_handling(self):
        """Test flow with no packets (edge case)."""
        self.base_flow.packet_count = 0
        self.base_flow.duration_sec = 5.0
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.packets_per_sec, 0.0)
        self.assertEqual(fv.flow_features.syn_ratio, 0.0)


# ──────────────────────────────────────────────────────────────────────────────
# M1 Streaming FlowState Test Suite
# ──────────────────────────────────────────────────────────────────────────────
def _flow_state(
    start_time: float = 100.0,
    last_seen: float = 100.0,
    max_sequence_packets: int = 20,
) -> FlowState:
    return FlowState(
        key=FlowKey(
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=49152,
            dst_port=443,
            protocol=6,
        ),
        start_time=start_time,
        last_seen=last_seen,
        max_sequence_packets=max_sequence_packets,
    )


def _packet(
    timestamp: float,
    packet_length: int = 100,
    tcp_syn: int = 0,
    tcp_ack: int = 0,
    tcp_fin: int = 0,
    tcp_rst: int = 0,
    tcp_psh: int = 0,
    tcp_urg: int = 0,
) -> NormalizedPacket:
    return NormalizedPacket(
        timestamp=timestamp,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=49152,
        dst_port=443,
        protocol=6,
        packet_length=packet_length,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        tcp_fin=tcp_fin,
        tcp_rst=tcp_rst,
        tcp_psh=tcp_psh,
        tcp_urg=tcp_urg,
    )


class TestM1StreamingFlowFeatures(unittest.TestCase):
    def test_empty_flow_state_has_safe_defaults(self):
        features = extract_flow_features(_flow_state())

        self.assertIsInstance(features, FlowFeatures)
        self.assertEqual(features.protocol, 6)
        self.assertEqual(features.src_port, 49152)
        self.assertEqual(features.dst_port, 443)
        self.assertEqual(features.packet_count, 0)
        self.assertEqual(features.byte_count, 0)
        self.assertEqual(features.duration, 0.0)
        self.assertEqual(features.packet_rate, 0.0)
        self.assertEqual(features.byte_rate, 0.0)

    def test_one_packet_flow_state_has_safe_sequence_stats(self):
        state = _flow_state()
        state.update(
            _packet(
                timestamp=100.0,
                packet_length=64,
                tcp_syn=1,
            )
        )

        features = extract_flow_features(state)

        self.assertEqual(features.packet_count, 1)
        self.assertEqual(features.byte_count, 64)
        self.assertEqual(features.duration, 0.0)
        self.assertEqual(features.packet_rate, 0.0)
        self.assertEqual(features.byte_rate, 0.0)

    def test_multi_packet_flow_state_extracts_basic_features(self):
        state = _flow_state()
        state.update(_packet(timestamp=100.0, packet_length=100))
        state.update(_packet(timestamp=101.0, packet_length=200))
        state.update(_packet(timestamp=102.0, packet_length=300))

        features = extract_flow_features(state)

        self.assertEqual(features.packet_count, 3)
        self.assertEqual(features.byte_count, 600)
        self.assertEqual(features.duration, 2.0)
        self.assertEqual(features.packet_rate, 1.5)
        self.assertEqual(features.byte_rate, 300.0)

    def test_features_can_be_converted_to_dict(self):
        features = extract_flow_features(_flow_state())
        data = features.to_dict()

        self.assertEqual(data["protocol"], 6)
        self.assertEqual(data["packet_lengths"], ())


if __name__ == "__main__":
    unittest.main()
