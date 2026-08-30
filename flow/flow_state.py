from dataclasses import dataclass, field

from ingest.pcap_reader import NormalizedPacket
from flow.flow_key import FlowKey


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

    def update(
        self,
        packet: NormalizedPacket,
    ) -> None:

        if self.packet_count > 0:

            delta_ms = (
                packet.timestamp - self.last_seen
            ) * 1000.0

            self.inter_arrival_times_ms.append(
                max(0.0, delta_ms)
            )

        self.packet_count += 1

        self.byte_count += packet.packet_length

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

        self.last_seen = packet.timestamp
