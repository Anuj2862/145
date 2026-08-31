import io
import json
import unittest

from detectors.baseline import BaselineConfig, BaselineDetector
from ingest.pcap_reader import NormalizedPacket
from pipeline.replay import replay_pcap


def _packet(
    timestamp: float,
    packet_length: int = 60,
    tcp_syn: int = 1,
    tcp_ack: int = 0,
) -> NormalizedPacket:
    return NormalizedPacket(
        timestamp=timestamp,
        src_ip="10.0.0.10",
        dst_ip="198.51.100.10",
        src_port=49152,
        dst_port=443,
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


class RecoveringPacketSource:
    def __init__(self):
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.index += 1

        if self.index == 1:
            return _packet(timestamp=100.0)

        if self.index == 2:
            raise ValueError("bad packet")

        if self.index == 3:
            return _packet(timestamp=101.0)

        raise StopIteration


class TestReplayPipeline(unittest.TestCase):
    def test_replay_emits_alerts_as_json_lines(self):
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

        lines = output.getvalue().splitlines()
        alert = json.loads(lines[0])

        self.assertEqual(len(lines), 1)
        self.assertEqual(alert["flow_id"], "10.0.0.10:49152-198.51.100.10:443-6")
        self.assertEqual(alert["threat_class"], "SYN_FLOOD_SUSPECTED")
        self.assertEqual(alert["evidence"]["packet_count"], 3)
        self.assertEqual(stats.packets_processed, 3)
        self.assertEqual(stats.packets_ignored, 0)
        self.assertEqual(stats.alerts_generated, 1)
        self.assertEqual(stats.peak_active_flows, 1)
        self.assertGreaterEqual(stats.elapsed_seconds, 0.0)

    def test_replay_does_not_emit_for_normal_flow(self):
        output = io.StringIO()

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=output,
            packet_source=[
                _packet(timestamp=100.0, tcp_syn=1, tcp_ack=0),
                _packet(timestamp=101.0, tcp_syn=0, tcp_ack=1),
                _packet(timestamp=102.0, tcp_syn=0, tcp_ack=1),
            ],
        )

        self.assertEqual(output.getvalue(), "")
        self.assertEqual(stats.packets_processed, 3)
        self.assertEqual(stats.alerts_generated, 0)

    def test_replay_ignores_bad_packet_objects_without_crashing(self):
        output = io.StringIO()

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=output,
            packet_source=[
                _packet(timestamp=100.0),
                object(),
                _packet(timestamp=101.0),
            ],
        )

        self.assertEqual(output.getvalue(), "")
        self.assertEqual(stats.packets_processed, 2)
        self.assertEqual(stats.packets_ignored, 1)

    def test_replay_handles_iterator_errors_without_crashing(self):
        output = io.StringIO()

        stats = replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=output,
            packet_source=RecoveringPacketSource(),
        )

        self.assertEqual(output.getvalue(), "")
        self.assertEqual(stats.packets_processed, 2)
        self.assertEqual(stats.packets_ignored, 1)

    def test_replay_emits_flow_event_once_at_packet_threshold(self):
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

        self.assertEqual(stats.packets_processed, 25)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].packet_count, 20)
        self.assertEqual(
            events[0].flow_id,
            "10.0.0.10:49152-198.51.100.10:443-6",
        )
        self.assertEqual(len(events[0].packet_lengths), 20)

    def test_replay_does_not_emit_flow_event_before_threshold(self):
        events = []

        replay_pcap(
            pcap_path="unused.pcap",
            detector=_detector(),
            output=io.StringIO(),
            event_callback=events.append,
            packet_source=[
                _packet(timestamp=100.0 + index)
                for index in range(19)
            ],
        )

        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
