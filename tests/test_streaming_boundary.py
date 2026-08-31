import io
import unittest

from detectors.baseline import BaselineConfig, BaselineDetector
from flow.flow_manager import FlowManager
from ingest.pcap_reader import NormalizedPacket
from pipeline.replay import BoundedPacketQueue, replay_pcap
from schemas.window_snapshot import WindowSnapshotEvent
from schemas.window_snapshot import window_snapshot_event_from_snapshot
from flow.windows import StreamingWindowManager


def _packet(
    timestamp: float,
    src_ip: str = "10.0.0.10",
    dst_ip: str = "198.51.100.10",
    src_port: int = 49152,
    dst_port: int = 443,
    packet_length: int = 60,
    tcp_syn: int = 1,
    tcp_ack: int = 0,
) -> NormalizedPacket:
    return NormalizedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=6,
        packet_length=packet_length,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
    )


def _detector() -> BaselineDetector:
    return BaselineDetector(
        BaselineConfig(
            syn_flood_min_packet_count=3,
            syn_flood_min_duration=2.0,
            syn_flood_min_packet_rate=1.0,
            syn_flood_min_syn_ratio=0.7,
            syn_flood_max_ack_ratio=0.1,
        )
    )


class _FakeMonotonic:
    def __init__(self, values):
        self.values = list(values)
        self.last_value = self.values[-1] if self.values else 0.0

    def __call__(self):
        if self.values:
            self.last_value = self.values.pop(0)

        return self.last_value


class TestStreamingBoundary(unittest.TestCase):
    def test_bounded_queue_preserves_capacity(self):
        queue = BoundedPacketQueue(capacity=2)

        self.assertTrue(queue.put(_packet(timestamp=1.0)))
        self.assertTrue(queue.put(_packet(timestamp=2.0)))
        self.assertEqual(len(queue), 2)
        self.assertFalse(queue.put(_packet(timestamp=3.0)))
        self.assertEqual(len(queue), 2)
        self.assertEqual(queue.dropped_packets, 1)

    def test_queue_full_behavior_drops_newest_in_replay(self):
        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=io.StringIO(),
            packet_source=[_packet(timestamp=100.0)],
            queue_capacity=0,
        )

        self.assertEqual(stats.packets_read, 1)
        self.assertEqual(stats.packets_processed, 0)
        self.assertEqual(stats.packets_ignored, 1)
        self.assertEqual(stats.packets_rejected, 1)
        self.assertEqual(stats.queue_packets_dropped, 1)

    def test_replay_speed_1x_5x_10x_uses_capture_deltas(self):
        cases = [
            ("1x", 10.0),
            ("5x", 2.0),
            ("10x", 1.0),
        ]

        for replay_speed, expected_delay in cases:
            with self.subTest(replay_speed=replay_speed):
                delays = []

                replay_pcap(
                    pcap_path="unused.pcap",
                    detector=_detector(),
                    output=io.StringIO(),
                    packet_source=[
                        _packet(timestamp=100.0),
                        _packet(timestamp=110.0),
                    ],
                    replay_speed=replay_speed,
                    sleep_fn=delays.append,
                )

                self.assertEqual(delays, [expected_delay])

    def test_offline_replay_mode_does_not_sleep(self):
        delays = []

        replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=io.StringIO(),
            packet_source=[
                _packet(timestamp=100.0),
                _packet(timestamp=110.0),
            ],
            replay_speed="offline",
            sleep_fn=delays.append,
        )

        self.assertEqual(delays, [])

    def test_throughput_counters_are_structured(self):
        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=io.StringIO(),
            packet_source=[
                _packet(timestamp=100.0),
                _packet(timestamp=101.0),
            ],
            monotonic_fn=_FakeMonotonic(
                [
                    0.0,
                    0.0,
                    0.25,
                    1.0,
                    1.25,
                    2.0,
                ]
            ),
            wall_clock_fn=lambda: 110.0,
        )

        self.assertEqual(stats.packets_read, 2)
        self.assertEqual(stats.packets_processed, 2)
        self.assertEqual(stats.active_flows, 1)
        self.assertEqual(stats.packets_per_second, 1.0)
        self.assertEqual(stats.flows_per_second, 0.5)
        self.assertEqual(
            stats.avg_processing_latency_seconds,
            0.25,
        )
        self.assertEqual(
            stats.max_processing_latency_seconds,
            0.25,
        )
        self.assertEqual(
            stats.avg_capture_to_process_latency_seconds,
            stats.avg_processing_latency_seconds,
        )
        self.assertEqual(
            stats.max_capture_to_process_latency_seconds,
            stats.max_processing_latency_seconds,
        )
        self.assertIn("packets_per_second", stats.to_dict())

    def test_old_capture_timestamp_does_not_create_fake_latency(self):
        old_epoch_timestamp = 1.0

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=io.StringIO(),
            packet_source=[
                _packet(timestamp=old_epoch_timestamp),
            ],
            monotonic_fn=_FakeMonotonic([0.0, 0.05, 0.1]),
            wall_clock_fn=lambda: 1_800_000_000.0,
        )

        self.assertEqual(
            stats.latest_capture_timestamp,
            old_epoch_timestamp,
        )
        self.assertEqual(
            stats.latest_processing_wall_timestamp,
            1_800_000_000.0,
        )
        self.assertLess(
            stats.avg_processing_latency_seconds,
            1.0,
        )
        self.assertLess(
            stats.avg_capture_to_process_latency_seconds,
            1.0,
        )
        self.assertGreaterEqual(
            stats.avg_processing_latency_seconds,
            0.0,
        )

    def test_flow_eviction_counter_is_reported(self):
        flow_manager = FlowManager(max_active_flows=1)

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            flow_manager=flow_manager,
            output=io.StringIO(),
            packet_source=[
                _packet(timestamp=100.0, src_port=1),
                _packet(timestamp=101.0, src_port=2),
            ],
        )

        self.assertEqual(stats.flow_evictions, 1)
        self.assertEqual(flow_manager.eviction_count(), 1)
        self.assertEqual(stats.active_flows, 1)

    def test_event_counters_are_reported(self):
        events = []
        output = io.StringIO()

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=output,
            event_callback=events.append,
            packet_source=[
                _packet(timestamp=100.0 + index)
                for index in range(25)
            ],
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(stats.flow_events_emitted, 1)
        self.assertGreater(stats.alerts_emitted, 0)
        self.assertEqual(stats.alerts_generated, stats.alerts_emitted)

    def test_window_snapshot_contract_from_manager_snapshot(self):
        manager = StreamingWindowManager()
        manager.update(_packet(timestamp=100.0, packet_length=100))
        snapshot_event = window_snapshot_event_from_snapshot(
            manager.snapshot()
        )

        self.assertIsInstance(snapshot_event, WindowSnapshotEvent)
        self.assertEqual(snapshot_event.timestamp, 100.0)
        self.assertEqual(snapshot_event.burst_packet_count, 1)
        self.assertEqual(snapshot_event.baseline_packet_count, 1)
        self.assertEqual(
            snapshot_event.burst_source_ip_counts,
            {"10.0.0.10": 1},
        )

    def test_window_snapshot_callback_is_emitted_by_replay(self):
        snapshots = []

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=io.StringIO(),
            window_snapshot_callback=snapshots.append,
            window_snapshot_interval_packets=2,
            packet_source=[
                _packet(timestamp=100.0),
                _packet(timestamp=101.0),
                _packet(timestamp=102.0),
            ],
        )

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(stats.window_snapshots_emitted, 1)
        self.assertEqual(snapshots[0].burst_packet_count, 2)

    def test_existing_replay_behavior_remains_compatible(self):
        output = io.StringIO()

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=output,
            packet_source=[
                _packet(timestamp=100.0),
                _packet(timestamp=101.0),
                _packet(timestamp=102.0),
            ],
        )

        self.assertEqual(stats.packets_processed, 3)
        self.assertEqual(stats.packets_ignored, 0)
        self.assertEqual(stats.alerts_generated, 1)
        self.assertEqual(len(output.getvalue().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
