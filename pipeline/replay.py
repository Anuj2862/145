import argparse
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Callable, TextIO

from detectors.baseline import BaselineDetector
from features.flow_features import FlowFeatures
from features.flow_features import extract_flow_features
from flow.flow_key import FlowKey
from flow.flow_manager import FlowManager
from flow.windows import StreamingWindowManager
from ingest.pcap_reader import NormalizedPacket, PcapIngestionStats, iter_pcap
from schemas.flow_event import FlowEvent
from schemas.window_snapshot import WindowSnapshotEvent
from schemas.window_snapshot import window_snapshot_event_from_snapshot


FLOW_EVENT_PACKET_THRESHOLD = 20
DEFAULT_QUEUE_CAPACITY = 10_000


class BoundedPacketQueue:
    def __init__(
        self,
        capacity: int = DEFAULT_QUEUE_CAPACITY,
        full_policy: str = "drop_newest",
    ):
        if capacity < 0:
            raise ValueError("Queue capacity must be non-negative")

        if full_policy != "drop_newest":
            raise ValueError(
                "Unsupported queue full policy: "
                f"{full_policy}"
            )

        self.capacity = capacity
        self.full_policy = full_policy
        self.dropped_packets = 0
        self._items: deque[NormalizedPacket] = deque()

    def put(
        self,
        packet: NormalizedPacket,
    ) -> bool:
        if len(self._items) >= self.capacity:
            self.dropped_packets += 1
            return False

        self._items.append(packet)
        return True

    def get(self) -> NormalizedPacket:
        return self._items.popleft()

    def empty(self) -> bool:
        return not self._items

    def __len__(self) -> int:
        return len(self._items)


@dataclass(frozen=True)
class ReplayStats:
    packets_read: int
    packets_processed: int
    packets_rejected: int
    packets_ignored: int
    active_flows: int
    alerts_generated: int
    alerts_emitted: int
    peak_active_flows: int
    flow_evictions: int
    flow_events_emitted: int
    window_snapshots_emitted: int
    queue_capacity: int
    queue_packets_dropped: int
    elapsed_seconds: float
    packets_per_second: float
    flows_per_second: float
    latest_capture_timestamp: float | None = None
    latest_processing_wall_timestamp: float | None = None
    avg_processing_latency_seconds: float = 0.0
    max_processing_latency_seconds: float = 0.0
    avg_capture_to_process_latency_seconds: float = 0.0
    max_capture_to_process_latency_seconds: float = 0.0
    avg_emission_processing_latency_seconds: float = 0.0
    max_emission_processing_latency_seconds: float = 0.0

    def to_dict(self) -> dict[str, int | float | None]:
        return asdict(self)


def replay_pcap(
    pcap_path: str | Path,
    detector: BaselineDetector | None = None,
    flow_manager: FlowManager | None = None,
    window_manager: StreamingWindowManager | None = None,
    event_callback: Callable[[FlowEvent], None] | None = None,
    window_snapshot_callback: Callable[[WindowSnapshotEvent], None] | None = None,
    signal_adapter_callback: Callable[[list[FlowEvent], float, float], None] | None = None,
    output: TextIO | None = None,
    packet_source: Iterable[NormalizedPacket] | None = None,
    queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
    replay_speed: float | int | str | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
    wall_clock_fn: Callable[[], float] = time.time,
    window_snapshot_interval_packets: int = 1,
) -> ReplayStats:
    detector = detector or BaselineDetector()
    flow_manager = flow_manager or FlowManager()
    window_manager = window_manager or StreamingWindowManager()
    output = output or sys.stdout
    queue = BoundedPacketQueue(queue_capacity)
    speed_multiplier = _normalize_replay_speed(replay_speed)

    started_at = monotonic_fn()
    packets_read = 0
    packets_processed = 0
    packets_ignored = 0
    alerts_generated = 0
    alerts_emitted = 0
    flow_events_emitted = 0
    window_snapshots_emitted = 0
    peak_active_flows = flow_manager.active_flow_count()
    emitted_flow_ids: set[str] = set()
    emitted_flow_objects: list[FlowEvent] = []
    seen_flow_ids: set[str] = set()
    latest_capture_timestamp: float | None = None
    latest_processing_wall_timestamp: float | None = None
    processing_latency_sum = 0.0
    processing_latency_count = 0
    max_processing_latency = 0.0
    emission_latency_sum = 0.0
    emission_latency_count = 0
    max_emission_latency = 0.0

    ingestion_stats = (
        None
        if packet_source is not None
        else PcapIngestionStats()
    )

    packet_iterator = iter(
        packet_source
        if packet_source is not None
        else iter_pcap(
            pcap_path,
            stats=ingestion_stats,
        )
    )

    def record_emission_latency(
        processing_started: float,
    ) -> None:
        nonlocal emission_latency_sum
        nonlocal emission_latency_count
        nonlocal max_emission_latency

        latency = max(0.0, monotonic_fn() - processing_started)
        emission_latency_sum += latency
        emission_latency_count += 1
        max_emission_latency = max(
            max_emission_latency,
            latency,
        )

    def drain_queue() -> None:
        nonlocal packets_processed
        nonlocal packets_ignored
        nonlocal alerts_generated
        nonlocal alerts_emitted
        nonlocal flow_events_emitted
        nonlocal window_snapshots_emitted
        nonlocal peak_active_flows
        nonlocal latest_processing_wall_timestamp
        nonlocal processing_latency_sum
        nonlocal processing_latency_count
        nonlocal max_processing_latency

        while not queue.empty():
            packet = queue.get()
            processing_started = monotonic_fn()
            processed_successfully = False

            try:
                key = _flow_key_from_packet(packet)
                flow_manager.process_packet(packet)
                window_manager.update(packet)
                latest_processing_wall_timestamp = wall_clock_fn()

                flow_state = flow_manager.get_flow(key)

                if flow_state is None:
                    packets_ignored += 1
                    continue

                features = extract_flow_features(flow_state)
                flow_id = str(key)
                seen_flow_ids.add(flow_id)

                if (
                    window_snapshot_callback is not None
                    and window_snapshot_interval_packets > 0
                    and (
                        packets_processed + 1
                    )
                    % window_snapshot_interval_packets
                    == 0
                ):
                    window_snapshot_callback(
                        window_snapshot_event_from_snapshot(
                            window_manager.snapshot(packet.timestamp)
                        )
                    )
                    window_snapshots_emitted += 1
                    record_emission_latency(processing_started)

                if (
                    flow_id not in emitted_flow_ids
                    and features.packet_count
                    >= FLOW_EVENT_PACKET_THRESHOLD
                    and (
                        event_callback is not None
                        or signal_adapter_callback is not None
                    )
                ):
                    flow_evt = _flow_event_from_features(
                        timestamp=packet.timestamp,
                        flow_id=flow_id,
                        key=key,
                        features=features,
                    )
                    if event_callback is not None:
                        event_callback(flow_evt)
                    if signal_adapter_callback is not None:
                        emitted_flow_objects.append(flow_evt)
                    emitted_flow_ids.add(flow_id)
                    flow_events_emitted += 1
                    record_emission_latency(processing_started)

                alerts = detector.detect(
                    features=features,
                    flow_id=flow_id,
                    timestamp=_timestamp_iso(packet.timestamp),
                )

                for alert in alerts:
                    output.write(
                        json.dumps(
                            asdict(alert),
                            sort_keys=True,
                        )
                    )
                    output.write("\n")
                    alerts_generated += 1
                    alerts_emitted += 1
                    record_emission_latency(processing_started)

                packets_processed += 1
                peak_active_flows = max(
                    peak_active_flows,
                    flow_manager.active_flow_count(),
                )
                processed_successfully = True
            except (AttributeError, TypeError):
                packets_ignored += 1
            finally:
                if processed_successfully:
                    processing_latency = _non_negative_finite(
                        monotonic_fn() - processing_started
                    )
                    processing_latency_sum += processing_latency
                    processing_latency_count += 1
                    max_processing_latency = max(
                        max_processing_latency,
                        processing_latency,
                    )

    while True:
        try:
            packet = next(packet_iterator)
            packets_read += 1
        except StopIteration:
            break
        except ValueError:
            packets_ignored += 1
            continue

        latest_capture_timestamp = _apply_replay_delay(
            packet=packet,
            previous_capture_timestamp=latest_capture_timestamp,
            speed_multiplier=speed_multiplier,
            sleep_fn=sleep_fn,
        )

        if not queue.put(packet):
            packets_ignored += 1
            continue

        drain_queue()

    drain_queue()

    if signal_adapter_callback is not None and emitted_flow_objects:
        w_start = emitted_flow_objects[0].timestamp
        w_end = (
            latest_capture_timestamp
            if (latest_capture_timestamp is not None and latest_capture_timestamp > w_start)
            else w_start + 1.0
        )
        signal_adapter_callback(emitted_flow_objects, w_start, w_end)

    elapsed_seconds = round(
        max(0.0, monotonic_fn() - started_at),
        6,
    )
    packets_per_second = (
        round(packets_processed / elapsed_seconds, 6)
        if elapsed_seconds > 0
        else 0.0
    )
    flows_per_second = (
        round(len(seen_flow_ids) / elapsed_seconds, 6)
        if elapsed_seconds > 0
        else 0.0
    )

    parser_rejected = (
        ingestion_stats.packets_rejected
        if ingestion_stats is not None
        else 0
    )
    total_packets_read = (
        ingestion_stats.records_seen
        if ingestion_stats is not None
        else packets_read
    )
    packets_rejected = packets_ignored + parser_rejected

    return ReplayStats(
        packets_read=total_packets_read,
        packets_processed=packets_processed,
        packets_rejected=packets_rejected,
        packets_ignored=packets_ignored,
        active_flows=flow_manager.active_flow_count(),
        alerts_generated=alerts_generated,
        alerts_emitted=alerts_emitted,
        peak_active_flows=peak_active_flows,
        flow_evictions=(
            flow_manager.eviction_count()
            if hasattr(flow_manager, "eviction_count")
            else 0
        ),
        flow_events_emitted=flow_events_emitted,
        window_snapshots_emitted=window_snapshots_emitted,
        queue_capacity=queue.capacity,
        queue_packets_dropped=queue.dropped_packets,
        elapsed_seconds=elapsed_seconds,
        packets_per_second=packets_per_second,
        flows_per_second=flows_per_second,
        latest_capture_timestamp=latest_capture_timestamp,
        latest_processing_wall_timestamp=latest_processing_wall_timestamp,
        avg_processing_latency_seconds=(
            round(
                processing_latency_sum
                / processing_latency_count,
                6,
            )
            if processing_latency_count
            else 0.0
        ),
        max_processing_latency_seconds=round(
            max_processing_latency,
            6,
        ),
        avg_capture_to_process_latency_seconds=(
            round(
                processing_latency_sum
                / processing_latency_count,
                6,
            )
            if processing_latency_count
            else 0.0
        ),
        max_capture_to_process_latency_seconds=round(
            max_processing_latency,
            6,
        ),
        avg_emission_processing_latency_seconds=(
            round(
                emission_latency_sum / emission_latency_count,
                6,
            )
            if emission_latency_count
            else 0.0
        ),
        max_emission_processing_latency_seconds=round(
            max_emission_latency,
            6,
        ),
    )


def _non_negative_finite(
    value: float,
) -> float:
    if not math.isfinite(value):
        return 0.0

    return max(0.0, value)


def _normalize_replay_speed(
    replay_speed: float | int | str | None,
) -> float | None:
    if replay_speed is None:
        return None

    if isinstance(replay_speed, str):
        normalized = replay_speed.strip().lower()

        if normalized in {"", "offline", "max", "maximum"}:
            return None

        if normalized.endswith("x"):
            normalized = normalized[:-1]

        replay_speed = float(normalized)

    speed = float(replay_speed)

    if speed <= 0:
        return None

    return speed


def _apply_replay_delay(
    packet: NormalizedPacket,
    previous_capture_timestamp: float | None,
    speed_multiplier: float | None,
    sleep_fn: Callable[[float], None],
) -> float | None:
    packet_timestamp = getattr(packet, "timestamp", None)

    if not isinstance(packet_timestamp, (int, float)):
        return previous_capture_timestamp

    if (
        speed_multiplier is not None
        and previous_capture_timestamp is not None
        and packet_timestamp > previous_capture_timestamp
    ):
        sleep_fn(
            (packet_timestamp - previous_capture_timestamp)
            / speed_multiplier
        )

    return float(packet_timestamp)


def _flow_key_from_packet(
    packet: NormalizedPacket,
) -> FlowKey:
    return FlowKey(
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
    )


def _timestamp_iso(timestamp: float) -> str:
    return (
        datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        )
        .isoformat()
        .replace("+00:00", "Z")
    )


def _flow_event_from_features(
    timestamp: float,
    flow_id: str,
    key: FlowKey,
    features: FlowFeatures,
) -> FlowEvent:
    return FlowEvent(
        timestamp=timestamp,
        flow_id=flow_id,
        src_ip=key.src_ip,
        dst_ip=key.dst_ip,
        src_port=key.src_port,
        dst_port=key.dst_port,
        protocol=key.protocol,
        packet_count=features.packet_count,
        byte_count=features.byte_count,
        duration=features.duration,
        packet_rate=features.packet_rate,
        byte_rate=features.byte_rate,
        syn_count=features.syn_count,
        ack_count=features.ack_count,
        fin_count=features.fin_count,
        rst_count=features.rst_count,
        psh_count=features.psh_count,
        urg_count=features.urg_count,
        syn_ratio=features.syn_ratio,
        ack_ratio=features.ack_ratio,
        fin_ratio=features.fin_ratio,
        rst_ratio=features.rst_ratio,
        packet_length_min=features.packet_length_min,
        packet_length_max=features.packet_length_max,
        packet_length_mean=features.packet_length_mean,
        packet_length_std=features.packet_length_std,
        iat_min_ms=features.iat_min_ms,
        iat_max_ms=features.iat_max_ms,
        iat_mean_ms=features.iat_mean_ms,
        iat_std_ms=features.iat_std_ms,
        packet_lengths=features.packet_lengths,
        inter_arrival_times_ms=features.inter_arrival_times_ms,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay a PCAP through the read-only flow, feature, "
            "and deterministic baseline detection pipeline."
        )
    )
    parser.add_argument(
        "pcap_path",
        help="Path to a classic Ethernet PCAP file.",
    )
    parser.add_argument(
        "--queue-capacity",
        type=int,
        default=DEFAULT_QUEUE_CAPACITY,
        help="Maximum packets buffered between ingest and processing.",
    )
    parser.add_argument(
        "--replay-speed",
        default="offline",
        help=(
            "Timestamp-based replay speed such as 1x, 5x, 10x, "
            "or offline for maximum-speed replay."
        ),
    )
    return parser


def main(
    argv: list[str] | None = None,
) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    stats = replay_pcap(
        args.pcap_path,
        queue_capacity=args.queue_capacity,
        replay_speed=args.replay_speed,
    )
    print(
        json.dumps(
            stats.to_dict(),
            sort_keys=True,
        ),
        file=sys.stderr,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
