import unittest

from features.flow_features import FlowFeatures, extract_flow_features
from flow.flow_key import FlowKey
from flow.flow_state import FlowState
from ingest.pcap_reader import NormalizedPacket


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


class TestFlowFeatures(unittest.TestCase):
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
        self.assertEqual(features.packet_length_min, 0.0)
        self.assertEqual(features.packet_length_max, 0.0)
        self.assertEqual(features.packet_length_mean, 0.0)
        self.assertEqual(features.packet_length_std, 0.0)
        self.assertEqual(features.iat_mean_ms, 0.0)
        self.assertEqual(features.iat_std_ms, 0.0)
        self.assertEqual(features.iat_min_ms, 0.0)
        self.assertEqual(features.iat_max_ms, 0.0)
        self.assertEqual(features.packet_lengths, ())
        self.assertEqual(features.inter_arrival_times_ms, ())

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
        self.assertEqual(features.packet_length_min, 64.0)
        self.assertEqual(features.packet_length_max, 64.0)
        self.assertEqual(features.packet_length_mean, 64.0)
        self.assertEqual(features.packet_length_std, 0.0)
        self.assertEqual(features.iat_mean_ms, 0.0)
        self.assertEqual(features.iat_std_ms, 0.0)
        self.assertEqual(features.packet_lengths, (64,))
        self.assertEqual(features.inter_arrival_times_ms, ())

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

    def test_packet_length_statistics_use_population_std(self):
        state = _flow_state()
        state.update(_packet(timestamp=100.0, packet_length=100))
        state.update(_packet(timestamp=101.0, packet_length=200))
        state.update(_packet(timestamp=102.0, packet_length=300))

        features = extract_flow_features(state)

        self.assertEqual(features.packet_length_min, 100.0)
        self.assertEqual(features.packet_length_max, 300.0)
        self.assertEqual(features.packet_length_mean, 200.0)
        self.assertAlmostEqual(
            features.packet_length_std,
            81.64965809277261,
        )

    def test_iat_statistics_use_population_std(self):
        state = _flow_state()
        state.update(_packet(timestamp=100.0))
        state.update(_packet(timestamp=100.1))
        state.update(_packet(timestamp=100.3))
        state.update(_packet(timestamp=100.6))

        features = extract_flow_features(state)

        self.assertAlmostEqual(features.iat_min_ms, 100.0)
        self.assertAlmostEqual(features.iat_max_ms, 300.0)
        self.assertAlmostEqual(features.iat_mean_ms, 200.0)
        self.assertAlmostEqual(
            features.iat_std_ms,
            81.64965809277261,
        )

    def test_tcp_flag_counts_and_ratios_are_extracted(self):
        state = _flow_state()
        state.update(
            _packet(
                timestamp=100.0,
                tcp_syn=1,
            )
        )
        state.update(
            _packet(
                timestamp=101.0,
                tcp_ack=1,
                tcp_psh=1,
            )
        )
        state.update(
            _packet(
                timestamp=102.0,
                tcp_ack=1,
                tcp_fin=1,
                tcp_rst=1,
                tcp_urg=1,
            )
        )

        features = extract_flow_features(state)

        self.assertEqual(features.syn_count, 1)
        self.assertEqual(features.ack_count, 2)
        self.assertEqual(features.fin_count, 1)
        self.assertEqual(features.rst_count, 1)
        self.assertEqual(features.psh_count, 1)
        self.assertEqual(features.urg_count, 1)
        self.assertAlmostEqual(features.syn_ratio, 1 / 3)
        self.assertAlmostEqual(features.ack_ratio, 2 / 3)
        self.assertAlmostEqual(features.fin_ratio, 1 / 3)
        self.assertAlmostEqual(features.rst_ratio, 1 / 3)

    def test_zero_duration_rates_remain_zero(self):
        state = _flow_state()
        state.update(_packet(timestamp=100.0, packet_length=100))
        state.update(_packet(timestamp=100.0, packet_length=200))

        features = extract_flow_features(state)

        self.assertEqual(features.duration, 0.0)
        self.assertEqual(features.packet_rate, 0.0)
        self.assertEqual(features.byte_rate, 0.0)

    def test_sequences_are_bounded_and_copied(self):
        state = _flow_state(max_sequence_packets=3)

        for index in range(5):
            state.update(
                _packet(
                    timestamp=100.0 + index,
                    packet_length=100 + index,
                )
            )

        features = extract_flow_features(state)
        state.packet_lengths.append(999)
        state.inter_arrival_times_ms.append(999.0)

        self.assertEqual(features.packet_lengths, (100, 101, 102))
        self.assertEqual(
            features.inter_arrival_times_ms,
            (1000.0, 1000.0, 1000.0),
        )

    def test_features_can_be_converted_to_dict(self):
        features = extract_flow_features(_flow_state())
        data = features.to_dict()

        self.assertEqual(data["protocol"], 6)
        self.assertEqual(data["packet_lengths"], ())


if __name__ == "__main__":
    unittest.main()
