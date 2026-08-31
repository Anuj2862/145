from collections import Counter, deque
from dataclasses import dataclass

from ingest.pcap_reader import NormalizedPacket


@dataclass(frozen=True)
class BurstWindowSnapshot:
    packet_count: int
    byte_count: int
    syn_count: int
    ack_count: int
    source_ip_counts: dict[str, int]
    packet_rate: float
    byte_rate: float


@dataclass(frozen=True)
class TimingWindowSnapshot:
    timestamp_count: int
    inter_arrival_count: int
    first_timestamp: float | None
    last_timestamp: float | None
    inter_arrival_times_ms: tuple[float, ...]


@dataclass(frozen=True)
class BaselineWindowSnapshot:
    bucket_count: int
    packet_count: int
    byte_count: int
    source_ip_cardinality: int
    destination_ip_cardinality: int
    source_ip_cardinality_capped: bool
    destination_ip_cardinality_capped: bool
    packet_counts: tuple[int, ...]
    byte_counts: tuple[int, ...]


@dataclass(frozen=True)
class StreamingWindowSnapshot:
    timestamp: float
    burst: BurstWindowSnapshot
    timing: TimingWindowSnapshot
    baseline: BaselineWindowSnapshot


@dataclass(frozen=True)
class _BurstEvent:
    timestamp: float
    packet_length: int
    tcp_syn: int
    tcp_ack: int
    src_ip: str


@dataclass
class _BaselineBucket:
    packet_count: int = 0
    byte_count: int = 0
    source_ips: set[str] | None = None
    destination_ips: set[str] | None = None
    source_ips_capped: bool = False
    destination_ips_capped: bool = False

    def __post_init__(self) -> None:
        if self.source_ips is None:
            self.source_ips = set()

        if self.destination_ips is None:
            self.destination_ips = set()


class StreamingWindowManager:
    def __init__(
        self,
        burst_window_seconds: float = 5.0,
        timing_window_seconds: float = 30.0,
        baseline_window_seconds: float = 300.0,
        baseline_bucket_seconds: float = 1.0,
        max_burst_events: int = 100_000,
        max_timing_events: int = 100_000,
        max_ips_per_baseline_bucket: int = 1_000,
    ):
        self.burst_window_seconds = burst_window_seconds
        self.timing_window_seconds = timing_window_seconds
        self.baseline_window_seconds = baseline_window_seconds
        self.baseline_bucket_seconds = baseline_bucket_seconds
        self.max_burst_events = max_burst_events
        self.max_timing_events = max_timing_events
        self.max_ips_per_baseline_bucket = max_ips_per_baseline_bucket

        self._burst_events: deque[_BurstEvent] = deque()
        self._burst_source_counts: Counter[str] = Counter()
        self._burst_packet_count = 0
        self._burst_byte_count = 0
        self._burst_syn_count = 0
        self._burst_ack_count = 0

        self._timestamps: deque[float] = deque()
        self._inter_arrival_times_ms: deque[float] = deque()

        self._baseline_buckets: dict[int, _BaselineBucket] = {}
        self._max_baseline_buckets = max(
            1,
            int(
                self.baseline_window_seconds
                / self.baseline_bucket_seconds
            )
            + 1,
        )
        self._latest_timestamp: float | None = None

    def update(
        self,
        packet: NormalizedPacket,
    ) -> None:
        if self._latest_timestamp is None:
            self._latest_timestamp = packet.timestamp
        else:
            self._latest_timestamp = max(
                self._latest_timestamp,
                packet.timestamp,
            )

        self._update_burst(packet)
        self._update_timing(packet)
        self._update_baseline(packet)
        self._expire(self._latest_timestamp)

    def snapshot(
        self,
        timestamp: float | None = None,
    ) -> StreamingWindowSnapshot:
        current_timestamp = self._current_timestamp(timestamp)
        self._expire(current_timestamp)

        return StreamingWindowSnapshot(
            timestamp=current_timestamp,
            burst=self._burst_snapshot(),
            timing=self._timing_snapshot(),
            baseline=self._baseline_snapshot(),
        )

    def active_state_size(self) -> int:
        baseline_ip_count = 0

        for bucket in self._baseline_buckets.values():
            baseline_ip_count += len(bucket.source_ips or ())
            baseline_ip_count += len(bucket.destination_ips or ())

        return (
            len(self._burst_events)
            + len(self._timestamps)
            + len(self._inter_arrival_times_ms)
            + len(self._baseline_buckets)
            + baseline_ip_count
        )

    def reset(self) -> None:
        self._burst_events.clear()
        self._burst_source_counts.clear()
        self._burst_packet_count = 0
        self._burst_byte_count = 0
        self._burst_syn_count = 0
        self._burst_ack_count = 0

        self._timestamps.clear()
        self._inter_arrival_times_ms.clear()
        self._baseline_buckets.clear()
        self._latest_timestamp = None

    def _update_burst(
        self,
        packet: NormalizedPacket,
    ) -> None:
        event = _BurstEvent(
            timestamp=packet.timestamp,
            packet_length=packet.packet_length,
            tcp_syn=packet.tcp_syn,
            tcp_ack=packet.tcp_ack,
            src_ip=packet.src_ip,
        )
        self._burst_events.append(event)
        self._burst_packet_count += 1
        self._burst_byte_count += packet.packet_length
        self._burst_syn_count += packet.tcp_syn
        self._burst_ack_count += packet.tcp_ack
        self._burst_source_counts[packet.src_ip] += 1

        while len(self._burst_events) > self.max_burst_events:
            self._evict_oldest_burst_event()

    def _update_timing(
        self,
        packet: NormalizedPacket,
    ) -> None:
        if self._timestamps:
            delta_ms = (
                packet.timestamp - self._timestamps[-1]
            ) * 1000.0
            self._inter_arrival_times_ms.append(
                max(0.0, delta_ms)
            )

        self._timestamps.append(packet.timestamp)

        while len(self._timestamps) > self.max_timing_events:
            self._timestamps.popleft()

        while (
            self._inter_arrival_times_ms
            and len(self._inter_arrival_times_ms)
            >= len(self._timestamps)
        ):
            self._inter_arrival_times_ms.popleft()

        while len(self._inter_arrival_times_ms) > self.max_timing_events:
            self._inter_arrival_times_ms.popleft()

    def _update_baseline(
        self,
        packet: NormalizedPacket,
    ) -> None:
        bucket_id = self._bucket_id(packet.timestamp)
        bucket = self._baseline_buckets.get(bucket_id)

        if bucket is None:
            bucket = _BaselineBucket()
            self._baseline_buckets[bucket_id] = bucket

        bucket.packet_count += 1
        bucket.byte_count += packet.packet_length
        self._add_bounded_ip(
            values=bucket.source_ips,
            ip=packet.src_ip,
            capped_attr="source_ips_capped",
            bucket=bucket,
        )
        self._add_bounded_ip(
            values=bucket.destination_ips,
            ip=packet.dst_ip,
            capped_attr="destination_ips_capped",
            bucket=bucket,
        )

    def _add_bounded_ip(
        self,
        values: set[str] | None,
        ip: str,
        capped_attr: str,
        bucket: _BaselineBucket,
    ) -> None:
        if values is None:
            return

        if ip in values:
            return

        if len(values) >= self.max_ips_per_baseline_bucket:
            setattr(bucket, capped_attr, True)
            return

        values.add(ip)

    def _expire(
        self,
        current_timestamp: float,
    ) -> None:
        self._expire_burst(current_timestamp)
        self._expire_timing(current_timestamp)
        self._expire_baseline(current_timestamp)

    def _expire_burst(
        self,
        current_timestamp: float,
    ) -> None:
        cutoff = current_timestamp - self.burst_window_seconds

        if not any(
            event.timestamp < cutoff
            for event in self._burst_events
        ):
            return

        retained = [
            event
            for event in self._burst_events
            if event.timestamp >= cutoff
        ]

        self._burst_events = deque(retained)
        self._burst_source_counts.clear()
        self._burst_packet_count = 0
        self._burst_byte_count = 0
        self._burst_syn_count = 0
        self._burst_ack_count = 0

        for event in retained:
            self._burst_packet_count += 1
            self._burst_byte_count += event.packet_length
            self._burst_syn_count += event.tcp_syn
            self._burst_ack_count += event.tcp_ack
            self._burst_source_counts[event.src_ip] += 1

    def _evict_oldest_burst_event(self) -> None:
        event = self._burst_events.popleft()
        self._burst_packet_count -= 1
        self._burst_byte_count -= event.packet_length
        self._burst_syn_count -= event.tcp_syn
        self._burst_ack_count -= event.tcp_ack
        self._burst_source_counts[event.src_ip] -= 1

        if self._burst_source_counts[event.src_ip] <= 0:
            del self._burst_source_counts[event.src_ip]

    def _expire_timing(
        self,
        current_timestamp: float,
    ) -> None:
        cutoff = current_timestamp - self.timing_window_seconds

        if not any(
            timestamp < cutoff
            for timestamp in self._timestamps
        ):
            return

        retained = [
            timestamp
            for timestamp in self._timestamps
            if timestamp >= cutoff
        ]

        self._timestamps = deque(retained)
        self._inter_arrival_times_ms.clear()

        previous_timestamp = None

        for timestamp in retained:
            if previous_timestamp is not None:
                self._inter_arrival_times_ms.append(
                    max(
                        0.0,
                        (timestamp - previous_timestamp) * 1000.0,
                    )
                )

            previous_timestamp = timestamp

    def _expire_baseline(
        self,
        current_timestamp: float,
    ) -> None:
        cutoff_bucket_id = self._bucket_id(
            current_timestamp - self.baseline_window_seconds
        )

        expired = [
            bucket_id
            for bucket_id in self._baseline_buckets
            if bucket_id < cutoff_bucket_id
        ]

        for bucket_id in expired:
            del self._baseline_buckets[bucket_id]

        while len(self._baseline_buckets) > self._max_baseline_buckets:
            oldest_bucket_id = min(self._baseline_buckets)
            del self._baseline_buckets[oldest_bucket_id]

    def _burst_snapshot(self) -> BurstWindowSnapshot:
        return BurstWindowSnapshot(
            packet_count=self._burst_packet_count,
            byte_count=self._burst_byte_count,
            syn_count=self._burst_syn_count,
            ack_count=self._burst_ack_count,
            source_ip_counts=dict(self._burst_source_counts),
            packet_rate=self._burst_packet_count
            / self.burst_window_seconds,
            byte_rate=self._burst_byte_count
            / self.burst_window_seconds,
        )

    def _timing_snapshot(self) -> TimingWindowSnapshot:
        return TimingWindowSnapshot(
            timestamp_count=len(self._timestamps),
            inter_arrival_count=len(self._inter_arrival_times_ms),
            first_timestamp=(
                self._timestamps[0]
                if self._timestamps
                else None
            ),
            last_timestamp=(
                self._timestamps[-1]
                if self._timestamps
                else None
            ),
            inter_arrival_times_ms=tuple(
                self._inter_arrival_times_ms
            ),
        )

    def _baseline_snapshot(self) -> BaselineWindowSnapshot:
        source_ips: set[str] = set()
        destination_ips: set[str] = set()
        source_capped = False
        destination_capped = False

        packet_counts = []
        byte_counts = []

        for bucket_id in sorted(self._baseline_buckets):
            bucket = self._baseline_buckets[bucket_id]
            packet_counts.append(bucket.packet_count)
            byte_counts.append(bucket.byte_count)
            source_ips.update(bucket.source_ips or ())
            destination_ips.update(bucket.destination_ips or ())
            source_capped = source_capped or bucket.source_ips_capped
            destination_capped = (
                destination_capped
                or bucket.destination_ips_capped
            )

        return BaselineWindowSnapshot(
            bucket_count=len(self._baseline_buckets),
            packet_count=sum(packet_counts),
            byte_count=sum(byte_counts),
            source_ip_cardinality=len(source_ips),
            destination_ip_cardinality=len(destination_ips),
            source_ip_cardinality_capped=source_capped,
            destination_ip_cardinality_capped=destination_capped,
            packet_counts=tuple(packet_counts),
            byte_counts=tuple(byte_counts),
        )

    def _current_timestamp(
        self,
        timestamp: float | None,
    ) -> float:
        if timestamp is not None:
            return timestamp

        if self._latest_timestamp is not None:
            return self._latest_timestamp

        if self._timestamps:
            return self._timestamps[-1]

        if self._burst_events:
            return self._burst_events[-1].timestamp

        if self._baseline_buckets:
            return max(self._baseline_buckets) * self.baseline_bucket_seconds

        return 0.0

    def _bucket_id(
        self,
        timestamp: float,
    ) -> int:
        return int(timestamp // self.baseline_bucket_seconds)
