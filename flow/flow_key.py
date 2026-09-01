from dataclasses import dataclass

from schemas.telemetry import canonical_conversation_id
from schemas.telemetry import canonical_flow_id


@dataclass(frozen=True)
class FlowKey:

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: int

    def __str__(self) -> str:
        return canonical_flow_id(
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            protocol=self.protocol,
        )

    @property
    def flow_id(self) -> str:
        return str(self)

    @property
    def conversation_id(self) -> str:
        return canonical_conversation_id(
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            protocol=self.protocol,
        )
