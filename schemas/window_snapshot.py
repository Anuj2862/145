from dataclasses import asdict, dataclass
import json
from typing import Any


@dataclass(frozen=True)
class WindowSnapshotEvent:
    timestamp: float

    burst_packet_count: int
    burst_byte_count: int
    burst_syn_count: int
    burst_ack_count: int
    burst_source_ip_counts: dict[str, int]
    burst_packet_rate: float
    burst_byte_rate: float

    timing_timestamp_count: int
    timing_inter_arrival_count: int
    timing_first_timestamp: float | None
    timing_last_timestamp: float | None
    timing_inter_arrival_times_ms: tuple[float, ...]

    baseline_bucket_count: int
    baseline_packet_count: int
    baseline_byte_count: int
    baseline_source_ip_cardinality: int
    baseline_destination_ip_cardinality: int
    baseline_source_ip_cardinality_capped: bool
    baseline_destination_ip_cardinality_capped: bool
    baseline_packet_counts: tuple[int, ...]
    baseline_byte_counts: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


def window_snapshot_event_from_snapshot(
    snapshot: Any,
) -> WindowSnapshotEvent:
    return WindowSnapshotEvent(
        timestamp=snapshot.timestamp,
        burst_packet_count=snapshot.burst.packet_count,
        burst_byte_count=snapshot.burst.byte_count,
        burst_syn_count=snapshot.burst.syn_count,
        burst_ack_count=snapshot.burst.ack_count,
        burst_source_ip_counts=dict(snapshot.burst.source_ip_counts),
        burst_packet_rate=snapshot.burst.packet_rate,
        burst_byte_rate=snapshot.burst.byte_rate,
        timing_timestamp_count=snapshot.timing.timestamp_count,
        timing_inter_arrival_count=snapshot.timing.inter_arrival_count,
        timing_first_timestamp=snapshot.timing.first_timestamp,
        timing_last_timestamp=snapshot.timing.last_timestamp,
        timing_inter_arrival_times_ms=tuple(
            snapshot.timing.inter_arrival_times_ms
        ),
        baseline_bucket_count=snapshot.baseline.bucket_count,
        baseline_packet_count=snapshot.baseline.packet_count,
        baseline_byte_count=snapshot.baseline.byte_count,
        baseline_source_ip_cardinality=(
            snapshot.baseline.source_ip_cardinality
        ),
        baseline_destination_ip_cardinality=(
            snapshot.baseline.destination_ip_cardinality
        ),
        baseline_source_ip_cardinality_capped=(
            snapshot.baseline.source_ip_cardinality_capped
        ),
        baseline_destination_ip_cardinality_capped=(
            snapshot.baseline.destination_ip_cardinality_capped
        ),
        baseline_packet_counts=tuple(snapshot.baseline.packet_counts),
        baseline_byte_counts=tuple(snapshot.baseline.byte_counts),
    )
