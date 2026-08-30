import dataclasses
import json
import unittest

from schemas.flow_event import FlowEvent


def _event() -> FlowEvent:
    return FlowEvent(
        timestamp=100.0,
        flow_id="10.0.0.1:49152-198.51.100.1:443-6",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=49152,
        dst_port=443,
        protocol=6,
        packet_count=20,
        byte_count=3000,
        duration=2.0,
        packet_rate=10.0,
        byte_rate=1500.0,
        syn_count=1,
        ack_count=19,
        fin_count=0,
        rst_count=0,
        psh_count=4,
        urg_count=0,
        syn_ratio=0.05,
        ack_ratio=0.95,
        fin_ratio=0.0,
        rst_ratio=0.0,
        packet_length_min=60.0,
        packet_length_max=300.0,
        packet_length_mean=150.0,
        packet_length_std=25.0,
        iat_min_ms=10.0,
        iat_max_ms=200.0,
        iat_mean_ms=100.0,
        iat_std_ms=30.0,
        packet_lengths=(60, 120, 300),
        inter_arrival_times_ms=(10.0, 90.0, 200.0),
    )


class TestFlowEvent(unittest.TestCase):
    def test_construction(self):
        event = _event()

        self.assertEqual(event.protocol, 6)
        self.assertEqual(event.src_port, 49152)
        self.assertEqual(event.packet_count, 20)
        self.assertEqual(event.packet_lengths, (60, 120, 300))

    def test_immutability(self):
        event = _event()

        with self.assertRaises(dataclasses.FrozenInstanceError):
            event.packet_count = 21

    def test_to_dict_returns_json_serializable_primitives(self):
        event = _event()
        data = event.to_dict()

        self.assertEqual(data["flow_id"], event.flow_id)
        self.assertEqual(data["packet_lengths"], (60, 120, 300))
        json.dumps(data)

    def test_to_json_returns_json_string(self):
        event = _event()
        data = json.loads(event.to_json())

        self.assertEqual(data["timestamp"], 100.0)
        self.assertEqual(
            data["flow_id"],
            "10.0.0.1:49152-198.51.100.1:443-6",
        )
        self.assertEqual(data["packet_lengths"], [60, 120, 300])

    def test_tuple_sequences_are_preserved_on_object_and_dict(self):
        event = _event()
        data = event.to_dict()

        self.assertIsInstance(event.packet_lengths, tuple)
        self.assertIsInstance(event.inter_arrival_times_ms, tuple)
        self.assertIsInstance(data["packet_lengths"], tuple)
        self.assertIsInstance(
            data["inter_arrival_times_ms"],
            tuple,
        )

    def test_representative_normal_event(self):
        event = _event()

        self.assertEqual(event.byte_count, 3000)
        self.assertEqual(event.duration, 2.0)
        self.assertEqual(event.packet_rate, 10.0)
        self.assertEqual(event.byte_rate, 1500.0)
        self.assertEqual(event.ack_ratio, 0.95)
        self.assertEqual(event.iat_mean_ms, 100.0)


if __name__ == "__main__":
    unittest.main()
