import unittest

from flow.flow_key import FlowKey
from flow.flow_state import FlowState
from ingest.pcap_reader import NormalizedPacket


def _flow_state(
    start_time: float = 100.0,
    last_seen: float = 100.0,
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


if __name__ == "__main__":
    unittest.main()
