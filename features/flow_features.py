from dataclasses import asdict, dataclass
from statistics import mean, pstdev
from typing import Any

from flow.flow_state import FlowState


@dataclass(frozen=True)
class FlowFeatures:
    """
    Deterministic flow measurements derived from FlowState.

    Standard deviation fields use population standard deviation.
    """

    protocol: int
    src_port: int
    dst_port: int

    packet_count: int
    byte_count: int
    duration: float
    packet_rate: float
    byte_rate: float

    syn_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    psh_count: int
    urg_count: int
    syn_ratio: float
    ack_ratio: float
    fin_ratio: float
    rst_ratio: float

    packet_length_min: float
    packet_length_max: float
    packet_length_mean: float
    packet_length_std: float

    iat_mean_ms: float
    iat_std_ms: float
    iat_min_ms: float
    iat_max_ms: float

    packet_lengths: tuple[int, ...]
    inter_arrival_times_ms: tuple[float, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sequence_min(values: tuple[int, ...] | tuple[float, ...]) -> float:
    if not values:
        return 0.0

    return float(min(values))


def _sequence_max(values: tuple[int, ...] | tuple[float, ...]) -> float:
    if not values:
        return 0.0

    return float(max(values))


def _sequence_mean(values: tuple[int, ...] | tuple[float, ...]) -> float:
    if not values:
        return 0.0

    return float(mean(values))


def _sequence_std(values: tuple[int, ...] | tuple[float, ...]) -> float:
    if len(values) < 2:
        return 0.0

    return float(pstdev(values))


def extract_flow_features(
    flow_state: FlowState,
) -> FlowFeatures:
    packet_lengths = tuple(flow_state.packet_lengths)
    inter_arrival_times_ms = tuple(
        flow_state.inter_arrival_times_ms
    )

    return FlowFeatures(
        protocol=flow_state.key.protocol,
        src_port=flow_state.key.src_port,
        dst_port=flow_state.key.dst_port,
        packet_count=flow_state.packet_count,
        byte_count=flow_state.byte_count,
        duration=flow_state.duration,
        packet_rate=flow_state.packet_rate,
        byte_rate=flow_state.byte_rate,
        syn_count=flow_state.syn_count,
        ack_count=flow_state.ack_count,
        fin_count=flow_state.fin_count,
        rst_count=flow_state.rst_count,
        psh_count=flow_state.psh_count,
        urg_count=flow_state.urg_count,
        syn_ratio=flow_state.syn_ratio,
        ack_ratio=flow_state.ack_ratio,
        fin_ratio=flow_state.fin_ratio,
        rst_ratio=flow_state.rst_ratio,
        packet_length_min=_sequence_min(packet_lengths),
        packet_length_max=_sequence_max(packet_lengths),
        packet_length_mean=_sequence_mean(packet_lengths),
        packet_length_std=_sequence_std(packet_lengths),
        iat_mean_ms=_sequence_mean(inter_arrival_times_ms),
        iat_std_ms=_sequence_std(inter_arrival_times_ms),
        iat_min_ms=_sequence_min(inter_arrival_times_ms),
        iat_max_ms=_sequence_max(inter_arrival_times_ms),
        packet_lengths=packet_lengths,
        inter_arrival_times_ms=inter_arrival_times_ms,
    )
