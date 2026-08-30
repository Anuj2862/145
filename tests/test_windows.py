import unittest

from flow.windows import StreamingWindowManager
from ingest.pcap_reader import NormalizedPacket


def _packet(
    timestamp: float,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "198.51.100.1",
    packet_length: int = 100,
    tcp_syn: int = 0,
    tcp_ack: int = 0,
) -> NormalizedPacket:
    return NormalizedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=49152,
        dst_port=443,
        protocol=6,
        packet_length=packet_length,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
    )


def _manager() -> StreamingWindowManager:
    return StreamingWindowManager(
        max_burst_events=10,
        max_timing_events=10,
        max_ips_per_baseline_bucket=10,
    )


class TestStreamingWindowManager(unittest.TestCase):
    def test_empty_windows_have_zero_state(self):
        manager = _manager()
        snapshot = manager.snapshot()

        self.assertEqual(snapshot.timestamp, 0.0)
        self.assertEqual(snapshot.burst.packet_count, 0)
        self.assertEqual(snapshot.burst.byte_count, 0)
        self.assertEqual(snapshot.burst.source_ip_counts, {})
        self.assertEqual(snapshot.timing.timestamp_count, 0)
        self.assertEqual(snapshot.timing.inter_arrival_count, 0)
        self.assertIsNone(snapshot.timing.first_timestamp)
        self.assertIsNone(snapshot.timing.last_timestamp)
        self.assertEqual(snapshot.baseline.bucket_count, 0)
        self.assertEqual(manager.active_state_size(), 0)

    def test_single_packet_updates_all_windows(self):
        manager = _manager()
        manager.update(
            _packet(
                timestamp=100.0,
                packet_length=250,
                tcp_syn=1,
            )
        )

        snapshot = manager.snapshot()

        self.assertEqual(snapshot.burst.packet_count, 1)
        self.assertEqual(snapshot.burst.byte_count, 250)
        self.assertEqual(snapshot.burst.syn_count, 1)
        self.assertEqual(snapshot.burst.ack_count, 0)
        self.assertEqual(snapshot.burst.source_ip_counts, {"10.0.0.1": 1})
        self.assertEqual(snapshot.burst.packet_rate, 0.2)
        self.assertEqual(snapshot.burst.byte_rate, 50.0)
        self.assertEqual(snapshot.timing.timestamp_count, 1)
        self.assertEqual(snapshot.timing.inter_arrival_times_ms, ())
        self.assertEqual(snapshot.baseline.packet_count, 1)
        self.assertEqual(snapshot.baseline.byte_count, 250)
        self.assertEqual(snapshot.baseline.source_ip_cardinality, 1)
        self.assertEqual(snapshot.baseline.destination_ip_cardinality, 1)

    def test_multiple_packets_aggregate_counts(self):
        manager = _manager()
        manager.update(_packet(timestamp=100.0, src_ip="10.0.0.1", packet_length=100, tcp_syn=1))
        manager.update(_packet(timestamp=101.0, src_ip="10.0.0.1", packet_length=200, tcp_ack=1))
        manager.update(_packet(timestamp=102.0, src_ip="10.0.0.2", packet_length=300, tcp_syn=1))

        snapshot = manager.snapshot()

        self.assertEqual(snapshot.burst.packet_count, 3)
        self.assertEqual(snapshot.burst.byte_count, 600)
        self.assertEqual(snapshot.burst.syn_count, 2)
        self.assertEqual(snapshot.burst.ack_count, 1)
        self.assertEqual(
            snapshot.burst.source_ip_counts,
            {
                "10.0.0.1": 2,
                "10.0.0.2": 1,
            },
        )
        self.assertEqual(snapshot.baseline.packet_counts, (1, 1, 1))
        self.assertEqual(snapshot.baseline.byte_counts, (100, 200, 300))

    def test_five_second_burst_expiration(self):
        manager = _manager()
        manager.update(_packet(timestamp=100.0, packet_length=100))
        manager.update(_packet(timestamp=101.0, packet_length=200))
        manager.update(_packet(timestamp=106.0, packet_length=300))

        snapshot = manager.snapshot(timestamp=106.0)

        self.assertEqual(snapshot.burst.packet_count, 2)
        self.assertEqual(snapshot.burst.byte_count, 500)

    def test_thirty_second_timing_expiration(self):
        manager = _manager()
        manager.update(_packet(timestamp=100.0))
        manager.update(_packet(timestamp=110.0))
        manager.update(_packet(timestamp=131.0))

        snapshot = manager.snapshot(timestamp=131.0)

        self.assertEqual(snapshot.timing.timestamp_count, 2)
        self.assertEqual(snapshot.timing.first_timestamp, 110.0)
        self.assertEqual(snapshot.timing.last_timestamp, 131.0)
        self.assertEqual(
            snapshot.timing.inter_arrival_times_ms,
            (21000.0,),
        )

    def test_five_minute_baseline_expiration(self):
        manager = _manager()
        manager.update(_packet(timestamp=0.0, packet_length=100))
        manager.update(_packet(timestamp=299.0, packet_length=200))
        manager.update(_packet(timestamp=301.0, packet_length=300))

        snapshot = manager.snapshot(timestamp=301.0)

        self.assertEqual(snapshot.baseline.packet_count, 2)
        self.assertEqual(snapshot.baseline.byte_count, 500)
        self.assertEqual(snapshot.baseline.packet_counts, (1, 1))

    def test_memory_bounds_are_enforced(self):
        manager = StreamingWindowManager(
            max_burst_events=3,
            max_timing_events=3,
            baseline_window_seconds=300.0,
            baseline_bucket_seconds=1.0,
            max_ips_per_baseline_bucket=2,
        )

        for index in range(10):
            manager.update(
                _packet(
                    timestamp=100.0,
                    src_ip=f"10.0.0.{index}",
                    dst_ip=f"198.51.100.{index}",
                )
            )

        snapshot = manager.snapshot(timestamp=100.0)

        self.assertEqual(snapshot.burst.packet_count, 3)
        self.assertEqual(snapshot.timing.timestamp_count, 3)
        self.assertEqual(snapshot.baseline.source_ip_cardinality, 2)
        self.assertEqual(snapshot.baseline.destination_ip_cardinality, 2)
        self.assertTrue(snapshot.baseline.source_ip_cardinality_capped)
        self.assertTrue(snapshot.baseline.destination_ip_cardinality_capped)
        self.assertLessEqual(manager.active_state_size(), 13)

    def test_out_of_order_timestamps_do_not_corrupt_state(self):
        manager = _manager()
        manager.update(_packet(timestamp=100.0, packet_length=100))
        manager.update(_packet(timestamp=110.0, packet_length=200))
        manager.update(_packet(timestamp=102.0, packet_length=300))

        snapshot = manager.snapshot(timestamp=110.0)

        self.assertEqual(snapshot.burst.packet_count, 1)
        self.assertEqual(snapshot.burst.byte_count, 200)
        self.assertEqual(snapshot.timing.timestamp_count, 3)
        self.assertEqual(
            snapshot.timing.inter_arrival_times_ms,
            (10000.0, 0.0),
        )

    def test_reset_clears_window_state(self):
        manager = _manager()
        manager.update(_packet(timestamp=100.0))

        self.assertGreater(manager.active_state_size(), 0)

        manager.reset()
        snapshot = manager.snapshot()

        self.assertEqual(snapshot.burst.packet_count, 0)
        self.assertEqual(snapshot.timing.timestamp_count, 0)
        self.assertEqual(snapshot.baseline.packet_count, 0)
        self.assertEqual(manager.active_state_size(), 0)


if __name__ == "__main__":
    unittest.main()
