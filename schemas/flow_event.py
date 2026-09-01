from dataclasses import asdict, dataclass
import json
from typing import Any

from schemas.telemetry import DNSMetadata
from schemas.telemetry import QUICMetadata
from schemas.telemetry import TLSMetadata
from schemas.telemetry import UNKNOWN_SENSOR_ID
from schemas.telemetry import canonical_conversation_id
from schemas.telemetry import canonical_entity_id


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

    event_time: float | None = None
    ingest_time: float | None = None
    processing_time: float | None = None
    alert_time: float | None = None
    sensor_id: str = UNKNOWN_SENSOR_ID
    conversation_id: str | None = None
    entity_id: str | None = None
    dns: DNSMetadata | None = None
    tls: TLSMetadata | None = None
    quic: QUICMetadata | None = None

    def __post_init__(self) -> None:
        if self.event_time is None:
            object.__setattr__(self, "event_time", self.timestamp)
        if self.conversation_id is None:
            object.__setattr__(
                self,
                "conversation_id",
                canonical_conversation_id(
                    src_ip=self.src_ip,
                    src_port=self.src_port,
                    dst_ip=self.dst_ip,
                    dst_port=self.dst_port,
                    protocol=self.protocol,
                ),
            )
        if self.entity_id is None:
            object.__setattr__(
                self,
                "entity_id",
                canonical_entity_id(
                    src_ip=self.src_ip,
                    sensor_id=self.sensor_id,
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )
