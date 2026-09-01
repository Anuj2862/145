from dataclasses import dataclass
from typing import Any


UNKNOWN_SENSOR_ID = "unknown"


@dataclass(frozen=True)
class DNSMetadata:
    query_name: str | None = None
    query_type: str | None = None
    response_code: str | None = None
    answer_count: int | None = None


@dataclass(frozen=True)
class TLSMetadata:
    sni: str | None = None
    alpn: str | None = None
    ja3_hash: str | None = None
    ja4_hash: str | None = None
    tls_version: str | None = None


@dataclass(frozen=True)
class QUICMetadata:
    sni: str | None = None
    alpn: str | None = None
    version: str | None = None
    connection_id: str | None = None


def canonical_flow_id(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: int,
) -> str:
    """Directional 5-tuple identity."""
    return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"


def canonical_conversation_id(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: int,
) -> str:
    """Bidirectional grouping key derived deterministically from a 5-tuple."""
    left = (src_ip, int(src_port))
    right = (dst_ip, int(dst_port))
    first, second = sorted((left, right))
    return (
        f"{first[0]}:{first[1]}"
        f"<->"
        f"{second[0]}:{second[1]}"
        f"-{int(protocol)}"
    )


def canonical_entity_id(
    src_ip: str,
    sensor_id: str | None = None,
) -> str:
    """Behavioral aggregation key for a passively observed source entity."""
    if sensor_id and sensor_id != UNKNOWN_SENSOR_ID:
        return f"{sensor_id}:{src_ip}"
    return src_ip


def metadata_to_dict(metadata: Any) -> dict[str, Any] | None:
    if metadata is None:
        return None
    if hasattr(metadata, "model_dump"):
        return metadata.model_dump()
    if hasattr(metadata, "__dict__"):
        return dict(metadata.__dict__)
    return dict(metadata)
