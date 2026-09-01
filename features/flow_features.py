"""Flow feature extraction logic for UniGuard (Member 1 Streaming & Member 2 Event-based).

Supports:
  1. Streaming FlowState feature extraction (Member 1 pipeline) -> FlowFeatures dataclass
  2. Batch FlowEvent feature extraction (Member 2 pipeline) -> schemas.FlowFeatures Pydantic model
"""

from dataclasses import asdict, dataclass
from statistics import mean, pstdev
from typing import Any, Optional, Union

from schemas import FlowEvent, FlowFeatures as PydanticFlowFeatures
from flow.flow_state import FlowState


@dataclass(frozen=True)
class FlowFeatures:
    """
    Deterministic flow measurements derived from FlowState (Member 1 streaming pipeline).

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


def _sequence_min(values: Union[tuple[int, ...], tuple[float, ...]]) -> float:
    if not values:
        return 0.0
    return float(min(values))


def _sequence_max(values: Union[tuple[int, ...], tuple[float, ...]]) -> float:
    if not values:
        return 0.0
    return float(max(values))


def _sequence_mean(values: Union[tuple[int, ...], tuple[float, ...]]) -> float:
    if not values:
        return 0.0
    return float(mean(values))


def _sequence_std(values: Union[tuple[int, ...], tuple[float, ...]]) -> float:
    if len(values) < 2:
        return 0.0
    return float(pstdev(values))


def extract_flow_features_from_event(flow: FlowEvent) -> PydanticFlowFeatures:
    """Extract flow velocity and cardinality features from a FlowEvent (Member 2)."""
    duration = flow.duration_sec if flow.duration_sec > 0 else 1.0

    packets_per_sec = float(flow.packet_count) / duration
    bytes_per_sec = float(flow.byte_count) / duration

    syn_ratio: Optional[float] = None
    if flow.protocol == 6 and flow.tcp_flags is not None:
        if flow.packet_count > 0:
            syn_ratio = float(flow.tcp_flags.syn_count) / float(flow.packet_count)
        else:
            syn_ratio = 0.0

    fan_out_dest_count = 1
    dst_port_cardinality = 1

    return PydanticFlowFeatures(
        packets_per_sec=packets_per_sec,
        bytes_per_sec=bytes_per_sec,
        syn_ratio=syn_ratio,
        fan_out_dest_count=fan_out_dest_count,
        dst_port_cardinality=dst_port_cardinality,
    )


def extract_flow_features(
    flow_input: Union[FlowState, FlowEvent],
) -> Union[FlowFeatures, PydanticFlowFeatures]:
    """Polymorphic feature extractor supporting both FlowState (M1) and FlowEvent (M2)."""
    if isinstance(flow_input, FlowEvent):
        return extract_flow_features_from_event(flow_input)

    flow_state = flow_input
    packet_lengths = tuple(flow_state.packet_lengths)
    inter_arrival_times_ms = tuple(flow_state.inter_arrival_times_ms)

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
        packet_length_min=flow_state.packet_length_min,
        packet_length_max=flow_state.packet_length_max,
        packet_length_mean=flow_state.packet_length_mean,
        packet_length_std=flow_state.packet_length_std,
        iat_mean_ms=flow_state.iat_mean_ms,
        iat_std_ms=flow_state.iat_std_ms,
        iat_min_ms=flow_state.iat_min_ms,
        iat_max_ms=flow_state.iat_max_ms,
        packet_lengths=packet_lengths,
        inter_arrival_times_ms=inter_arrival_times_ms,
    )
