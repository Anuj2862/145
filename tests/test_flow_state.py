import unittest

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
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
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
) -> NormalizedPacket:
    return NormalizedPacket(
        timestamp=timestamp,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=443,
        protocol=6,
        packet_length=packet_length,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        tcp_fin=tcp_fin,
        tcp_rst=tcp_rst,
    )


class TestFlowState(unittest.TestCase):
    def test_flow_identity_is_directional_but_conversation_identity_is_bidirectional(self):
        forward = FlowKey(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=443,
            protocol=6,
        )
        reverse = FlowKey(
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=443,
            dst_port=12345,
            protocol=6,
        )

        self.assertNotEqual(forward.flow_id, reverse.flow_id)
        self.assertEqual(
            forward.flow_id,
            "10.0.0.1:12345-10.0.0.2:443-6",
        )
        self.assertEqual(
            forward.conversation_id,
            reverse.conversation_id,
        )

    def test_asymmetric_one_way_flow_has_conversation_id_without_reverse_flow(self):
        state = _flow_state()
        state.update(_packet(timestamp=100.0, packet_length=60))

        self.assertEqual(state.packet_count, 1)
        self.assertEqual(
            state.conversation_id,
            "10.0.0.1:12345<->10.0.0.2:443-6",
        )
        self.assertEqual(state.entity_id, "10.0.0.1")

    def test_zero_packets_have_safe_derived_values(self):
        state = _flow_state()

        self.assertEqual(state.duration, 0.0)
        self.assertEqual(state.packet_rate, 0.0)
        self.assertEqual(state.byte_rate, 0.0)
        self.assertEqual(state.syn_ratio, 0.0)
        self.assertEqual(state.ack_ratio, 0.0)
        self.assertEqual(state.rst_ratio, 0.0)
        self.assertEqual(state.fin_ratio, 0.0)

    def test_one_packet_zero_duration_has_safe_rates(self):
        state = _flow_state()
        state.update(
            _packet(
                timestamp=100.0,
                packet_length=60,
                tcp_syn=1,
            )
        )

        self.assertEqual(state.duration, 0.0)
        self.assertEqual(state.packet_rate, 0.0)
        self.assertEqual(state.byte_rate, 0.0)
        self.assertEqual(state.syn_ratio, 1.0)
        self.assertEqual(state.ack_ratio, 0.0)
        self.assertEqual(state.rst_ratio, 0.0)
        self.assertEqual(state.fin_ratio, 0.0)

    def test_negative_duration_is_clamped_to_zero(self):
        state = _flow_state(
            start_time=101.0,
            last_seen=100.0,
        )

        self.assertEqual(state.duration, 0.0)
        self.assertEqual(state.packet_rate, 0.0)
        self.assertEqual(state.byte_rate, 0.0)

    def test_multi_packet_flow_derives_rates_and_ratios(self):
        state = _flow_state()

        state.update(
            _packet(
                timestamp=100.0,
                packet_length=60,
                tcp_syn=1,
            )
        )
        state.update(
            _packet(
                timestamp=101.0,
                packet_length=140,
                tcp_ack=1,
            )
        )
        state.update(
            _packet(
                timestamp=102.0,
                packet_length=300,
                tcp_ack=1,
                tcp_fin=1,
                tcp_rst=1,
            )
        )

        self.assertEqual(state.duration, 2.0)
        self.assertEqual(state.packet_rate, 1.5)
        self.assertEqual(state.byte_rate, 250.0)
        self.assertAlmostEqual(state.syn_ratio, 1 / 3)
        self.assertAlmostEqual(state.ack_ratio, 2 / 3)
        self.assertAlmostEqual(state.rst_ratio, 1 / 3)
        self.assertAlmostEqual(state.fin_ratio, 1 / 3)

    def test_packet_size_statistics_cover_all_packets_beyond_bounded_sample(self):
        state = _flow_state(max_sequence_packets=2)

        state.update(_packet(timestamp=100.0, packet_length=10))
        state.update(_packet(timestamp=101.0, packet_length=20))
        state.update(_packet(timestamp=102.0, packet_length=1000))

        self.assertEqual(state.packet_lengths, [10, 20])
        self.assertEqual(state.packet_length_min, 10.0)
        self.assertEqual(state.packet_length_max, 1000.0)
        self.assertAlmostEqual(state.packet_length_mean, 1030.0 / 3.0)

    def test_event_time_drives_duration_and_iat_independent_of_ingest_time(self):
        state = _flow_state()

        state.update(
            NormalizedPacket(
                timestamp=100.0,
                ingest_time=5000.0,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=12345,
                dst_port=443,
                protocol=6,
                packet_length=100,
            )
        )
        state.update(
            NormalizedPacket(
                timestamp=101.5,
                ingest_time=5000.1,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=12345,
                dst_port=443,
                protocol=6,
                packet_length=100,
            )
        )

        self.assertEqual(state.duration, 1.5)
        self.assertEqual(state.iat_mean_ms, 1500.0)
        self.assertEqual(state.ingest_time, 5000.1)


if __name__ == "__main__":
    unittest.main()
