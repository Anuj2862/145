from dataclasses import dataclass, field
import math

from ingest.pcap_reader import NormalizedPacket
from flow.flow_key import FlowKey
from schemas.telemetry import UNKNOWN_SENSOR_ID
from schemas.telemetry import canonical_entity_id


@dataclass
class FlowState:

    key: FlowKey

    start_time: float
    last_seen: float

    packet_count: int = 0
    byte_count: int = 0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    packet_lengths: list[int] = field(default_factory=list)

    inter_arrival_times_ms: list[float] = field(
        default_factory=list
    )

    max_sequence_packets: int = 20
    sensor_id: str = UNKNOWN_SENSOR_ID
    ingest_time: float | None = None
    dns: object | None = None
    tls: object | None = None
    quic: object | None = None

    packet_length_min_value: float | None = None
    packet_length_max_value: float | None = None
    packet_length_sum: float = 0.0
    packet_length_sum_sq: float = 0.0

    iat_min_value: float | None = None
    iat_max_value: float | None = None
    iat_sum: float = 0.0
    iat_sum_sq: float = 0.0
    iat_count: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    @property
    def packet_rate(self) -> float:
        if self.duration == 0:
            return 0.0

        return self.packet_count / self.duration

    @property
    def byte_rate(self) -> float:
        if self.duration == 0:
            return 0.0

        return self.byte_count / self.duration

    @property
    def syn_ratio(self) -> float:
        if self.packet_count == 0:
            return 0.0

        return self.syn_count / self.packet_count

    @property
    def ack_ratio(self) -> float:
        if self.packet_count == 0:
            return 0.0

        return self.ack_count / self.packet_count

    @property
    def rst_ratio(self) -> float:
        if self.packet_count == 0:
            return 0.0

        return self.rst_count / self.packet_count

    @property
    def fin_ratio(self) -> float:
        if self.packet_count == 0:
            return 0.0

        return self.fin_count / self.packet_count

    @property
    def flow_id(self) -> str:
        return self.key.flow_id

    @property
    def conversation_id(self) -> str:
        return self.key.conversation_id

    @property
    def entity_id(self) -> str:
        return canonical_entity_id(
            src_ip=self.key.src_ip,
            sensor_id=self.sensor_id,
        )

    @property
    def event_time(self) -> float:
        return self.last_seen

    @property
    def packet_length_min(self) -> float:
        return float(self.packet_length_min_value or 0.0)

    @property
    def packet_length_max(self) -> float:
        return float(self.packet_length_max_value or 0.0)

    @property
    def packet_length_mean(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return self.packet_length_sum / self.packet_count

    @property
    def packet_length_std(self) -> float:
        if self.packet_count < 2:
            return 0.0
        mean = self.packet_length_mean
        variance = self.packet_length_sum_sq / self.packet_count - mean * mean
        return math.sqrt(max(0.0, variance))

    @property
    def iat_min_ms(self) -> float:
        return float(self.iat_min_value or 0.0)

    @property
    def iat_max_ms(self) -> float:
        return float(self.iat_max_value or 0.0)

    @property
    def iat_mean_ms(self) -> float:
        if self.iat_count == 0:
            return 0.0
        return self.iat_sum / self.iat_count

    @property
    def iat_std_ms(self) -> float:
        if self.iat_count < 2:
            return 0.0
        mean = self.iat_mean_ms
        variance = self.iat_sum_sq / self.iat_count - mean * mean
        return math.sqrt(max(0.0, variance))

    def update(
        self,
        packet: NormalizedPacket,
    ) -> None:

        if self.packet_count > 0:

            delta_ms = (
                packet.event_time - self.last_seen
            ) * 1000.0

            iat_ms = max(0.0, delta_ms)
            self.inter_arrival_times_ms.append(iat_ms)
            self.iat_count += 1
            self.iat_sum += iat_ms
            self.iat_sum_sq += iat_ms * iat_ms
            self.iat_min_value = (
                iat_ms
                if self.iat_min_value is None
                else min(self.iat_min_value, iat_ms)
            )
            self.iat_max_value = (
                iat_ms
                if self.iat_max_value is None
                else max(self.iat_max_value, iat_ms)
            )

        self.packet_count += 1

        self.byte_count += packet.packet_length
        self.packet_length_sum += packet.packet_length
        self.packet_length_sum_sq += packet.packet_length * packet.packet_length
        self.packet_length_min_value = (
            packet.packet_length
            if self.packet_length_min_value is None
            else min(self.packet_length_min_value, packet.packet_length)
        )
        self.packet_length_max_value = (
            packet.packet_length
            if self.packet_length_max_value is None
            else max(self.packet_length_max_value, packet.packet_length)
        )

        self.syn_count += packet.tcp_syn
        self.ack_count += packet.tcp_ack
        self.fin_count += packet.tcp_fin
        self.rst_count += packet.tcp_rst
        self.psh_count += packet.tcp_psh
        self.urg_count += packet.tcp_urg

        if len(self.packet_lengths) < self.max_sequence_packets:

            self.packet_lengths.append(
                packet.packet_length
            )

        if len(self.inter_arrival_times_ms) > self.max_sequence_packets:

            self.inter_arrival_times_ms = (
                self.inter_arrival_times_ms[
                    -self.max_sequence_packets:
                ]
            )

        if packet.ingest_time is not None:
            self.ingest_time = packet.ingest_time
        self.sensor_id = packet.sensor_id
        self.dns = packet.dns if packet.dns is not None else self.dns
        self.tls = packet.tls if packet.tls is not None else self.tls
        self.quic = packet.quic if packet.quic is not None else self.quic

        self.last_seen = packet.event_time
