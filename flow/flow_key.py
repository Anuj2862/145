from dataclasses import dataclass


@dataclass(frozen=True)
class FlowKey:

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: int

    def __str__(self) -> str:
        return (
            f"{self.src_ip}:{self.src_port}"
            f"-"
            f"{self.dst_ip}:{self.dst_port}"
            f"-"
            f"{self.protocol}"
        )