from dataclasses import asdict, dataclass
import json
from typing import Any


@dataclass(frozen=True)
class FlowEvent:
    timestamp: float
    flow_id: str

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

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

    iat_min_ms: float
    iat_max_ms: float
    iat_mean_ms: float
    iat_std_ms: float

    packet_lengths: tuple[int, ...]
    inter_arrival_times_ms: tuple[float, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )
