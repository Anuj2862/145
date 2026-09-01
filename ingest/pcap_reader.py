from dataclasses import dataclass
from pathlib import Path
import socket
import struct
from typing import Any, Iterator, Optional

from schemas.telemetry import DNSMetadata
from schemas.telemetry import TLSMetadata
from schemas.telemetry import UNKNOWN_SENSOR_ID


DEFAULT_MAX_CAPTURED_PACKET_SIZE = 262_144


@dataclass
class PcapIngestionStats:
    records_seen: int = 0
    packets_yielded: int = 0
    packets_rejected: int = 0
    records_too_large: int = 0
    truncated_records: int = 0


@dataclass(frozen=True)
class NormalizedPacket:
    """
    Protocol-neutral representation of a passively observed packet.

    This object is the boundary between packet ingestion and
    the flow engine.
    """

    timestamp: float

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: int

    packet_length: int

    tcp_syn: int = 0
    tcp_ack: int = 0
    tcp_fin: int = 0
    tcp_rst: int = 0
    tcp_psh: int = 0
    tcp_urg: int = 0

    ingest_time: float | None = None
    sensor_id: str = UNKNOWN_SENSOR_ID
    dns: Any | None = None
    tls: Any | None = None
    quic: Any | None = None

    @property
    def event_time(self) -> float:
        return self.timestamp


def _ip_text(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)

    return socket.inet_ntop(socket.AF_INET6, raw)


def _parse_transport(
    timestamp: float,
    src_ip: str,
    dst_ip: str,
    protocol: int,
    packet_length: int,
    payload: bytes,
) -> Optional[NormalizedPacket]:

    src_port = 0
    dst_port = 0

    syn = 0
    ack = 0
    fin = 0
    rst = 0
    psh = 0
    urg = 0
    dns = None
    tls = None

    # TCP
    if protocol == 6:

        if len(payload) < 20:
            return None

        data_offset = (payload[12] >> 4) * 4

        if data_offset < 20 or data_offset > len(payload):
            return None

        src_port, dst_port = struct.unpack(
            "!HH",
            payload[:4]
        )

        flags = struct.unpack(
            "!H",
            payload[12:14]
        )[0]

        syn = int(bool(flags & 0x0002))
        fin = int(bool(flags & 0x0001))
        rst = int(bool(flags & 0x0004))
        psh = int(bool(flags & 0x0008))
        ack = int(bool(flags & 0x0010))
        urg = int(bool(flags & 0x0020))

        if src_port in {443, 8443} or dst_port in {443, 8443}:
            tls = _parse_tls_client_hello_metadata(payload[data_offset:])

    # UDP
    elif protocol == 17:

        if len(payload) < 8:
            return None

        src_port, dst_port, udp_length = struct.unpack(
            "!HHH",
            payload[:6]
        )

        if udp_length < 8 or udp_length > len(payload):
            return None

        if src_port == 53 or dst_port == 53:
            dns = _parse_dns_metadata(payload[8:udp_length])

    return NormalizedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=packet_length,
        tcp_syn=syn,
        tcp_ack=ack,
        tcp_fin=fin,
        tcp_rst=rst,
        tcp_psh=psh,
        tcp_urg=urg,
        dns=dns,
        tls=tls,
    )


def _parse_dns_metadata(
    payload: bytes,
) -> DNSMetadata | None:
    if len(payload) < 12:
        return None

    _, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH",
        payload[:12],
    )
    if qdcount == 0 and ancount == 0 and nscount == 0 and arcount == 0:
        return None

    rcode = flags & 0x000F

    labels: list[str] = []
    offset = 12
    if qdcount > 0:
        parsed = _read_dns_name(payload, offset)
        if parsed is None:
            return None
        labels, offset = parsed

    query_type = None
    if qdcount > 0 and offset + 4 <= len(payload):
        qtype = struct.unpack("!H", payload[offset:offset + 2])[0]
        query_type = {
            1: "A",
            2: "NS",
            5: "CNAME",
            15: "MX",
            16: "TXT",
            28: "AAAA",
        }.get(qtype, str(qtype))

    return DNSMetadata(
        query_name=".".join(labels) if labels else None,
        query_type=query_type,
        response_code={
            0: "NOERROR",
            3: "NXDOMAIN",
        }.get(rcode, str(rcode)),
        answer_count=ancount,
    )


def _read_dns_name(payload: bytes, offset: int) -> tuple[list[str], int] | None:
    labels = []
    cursor = offset
    next_offset = offset
    jumped = False
    seen_offsets: set[int] = set()

    for _ in range(128):
        if cursor >= len(payload):
            return None
        label_len = payload[cursor]

        if (label_len & 0xC0) == 0xC0:
            if cursor + 1 >= len(payload):
                return None
            pointer = ((label_len & 0x3F) << 8) | payload[cursor + 1]
            if pointer in seen_offsets or pointer >= len(payload):
                return None
            seen_offsets.add(pointer)
            if not jumped:
                next_offset = cursor + 2
            cursor = pointer
            jumped = True
            continue

        if label_len & 0xC0:
            return None

        cursor += 1
        if label_len == 0:
            if not jumped:
                next_offset = cursor
            return labels, next_offset

        if cursor + label_len > len(payload):
            return None
        try:
            labels.append(payload[cursor:cursor + label_len].decode("ascii"))
        except UnicodeDecodeError:
            return None
        cursor += label_len
        if not jumped:
            next_offset = cursor

    return None


def _parse_tls_client_hello_metadata(payload: bytes) -> TLSMetadata | None:
    if len(payload) < 9 or payload[0] != 22:
        return None

    record_length = struct.unpack("!H", payload[3:5])[0]
    if record_length + 5 > len(payload):
        return None

    handshake = payload[5:5 + record_length]
    if len(handshake) < 4 or handshake[0] != 1:
        return None

    handshake_length = int.from_bytes(handshake[1:4], "big")
    body = handshake[4:4 + handshake_length]
    if len(body) < 38:
        return None

    offset = 34
    session_id_len = body[offset]
    offset += 1 + session_id_len
    if offset + 2 > len(body):
        return None

    cipher_len = struct.unpack("!H", body[offset:offset + 2])[0]
    offset += 2 + cipher_len
    if offset >= len(body):
        return None

    compression_len = body[offset]
    offset += 1 + compression_len
    if offset + 2 > len(body):
        return TLSMetadata(tls_version=_tls_version_name(body[:2]))

    extensions_len = struct.unpack("!H", body[offset:offset + 2])[0]
    offset += 2
    extensions_end = min(len(body), offset + extensions_len)
    sni = None
    alpn = None

    while offset + 4 <= extensions_end:
        ext_type, ext_len = struct.unpack("!HH", body[offset:offset + 4])
        offset += 4
        ext_data = body[offset:offset + ext_len]
        offset += ext_len

        if ext_type == 0 and sni is None:
            sni = _parse_tls_sni(ext_data)
        elif ext_type == 16 and alpn is None:
            alpn = _parse_tls_alpn(ext_data)

    return TLSMetadata(
        sni=sni,
        alpn=alpn,
        tls_version=_tls_version_name(body[:2]),
    )


def _parse_tls_sni(data: bytes) -> str | None:
    if len(data) < 5:
        return None
    list_len = struct.unpack("!H", data[:2])[0]
    offset = 2
    end = min(len(data), 2 + list_len)
    while offset + 3 <= end:
        name_type = data[offset]
        name_len = struct.unpack("!H", data[offset + 1:offset + 3])[0]
        offset += 3
        if offset + name_len > end:
            return None
        if name_type == 0:
            try:
                return data[offset:offset + name_len].decode("ascii")
            except UnicodeDecodeError:
                return None
        offset += name_len
    return None


def _parse_tls_alpn(data: bytes) -> str | None:
    if len(data) < 3:
        return None
    list_len = struct.unpack("!H", data[:2])[0]
    offset = 2
    end = min(len(data), 2 + list_len)
    names = []
    while offset < end:
        name_len = data[offset]
        offset += 1
        if offset + name_len > end:
            return None
        try:
            names.append(data[offset:offset + name_len].decode("ascii"))
        except UnicodeDecodeError:
            return None
        offset += name_len
    return ",".join(name for name in names if name) or None


def _tls_version_name(raw: bytes) -> str | None:
    versions = {
        b"\x03\x01": "TLS1.0",
        b"\x03\x02": "TLS1.1",
        b"\x03\x03": "TLS1.2",
        b"\x03\x04": "TLS1.3",
    }
    return versions.get(raw)


def _parse_ipv4(
    timestamp: float,
    data: bytes,
) -> Optional[NormalizedPacket]:

    if len(data) < 20:
        return None

    version_ihl = data[0]

    if version_ihl >> 4 != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4

    if ihl < 20 or len(data) < ihl:
        return None

    total_length = struct.unpack(
        "!H",
        data[2:4]
    )[0]

    if total_length < ihl or total_length > len(data):
        return None

    protocol = data[9]

    src_ip = _ip_text(data[12:16])
    dst_ip = _ip_text(data[16:20])

    payload = data[ihl:total_length]

    return _parse_transport(
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        total_length,
        payload,
    )


def _parse_ipv6(
    timestamp: float,
    data: bytes,
) -> Optional[NormalizedPacket]:

    if len(data) < 40:
        return None

    if data[0] >> 4 != 6:
        return None

    payload_length = struct.unpack(
        "!H",
        data[4:6]
    )[0]

    total_length = 40 + payload_length

    if total_length > len(data):
        return None

    next_header = data[6]

    src_ip = _ip_text(data[8:24])
    dst_ip = _ip_text(data[24:40])

    payload = data[
        40:total_length
    ]

    return _parse_transport(
        timestamp,
        src_ip,
        dst_ip,
        next_header,
        total_length,
        payload,
    )


def _parse_ethernet(
    timestamp: float,
    raw: bytes,
) -> Optional[NormalizedPacket]:

    if len(raw) < 14:
        return None

    eth_type = struct.unpack(
        "!H",
        raw[12:14]
    )[0]

    offset = 14

    # VLAN
    while eth_type in (0x8100, 0x88A8, 0x9100):

        if len(raw) < offset + 4:
            return None

        eth_type = struct.unpack(
            "!H",
            raw[offset + 2:offset + 4]
        )[0]

        offset += 4

    if eth_type == 0x0800:

        return _parse_ipv4(
            timestamp,
            raw[offset:]
        )

    if eth_type == 0x86DD:

        return _parse_ipv6(
            timestamp,
            raw[offset:]
        )

    return None


def iter_pcap(
    path: str | Path,
    max_captured_packet_size: int = DEFAULT_MAX_CAPTURED_PACKET_SIZE,
    stats: PcapIngestionStats | None = None,
) -> Iterator[NormalizedPacket]:

    path = Path(path)

    with path.open("rb") as handle:

        global_header = handle.read(24)

        if len(global_header) != 24:
            raise ValueError(
                "Invalid PCAP: truncated global header"
            )

        magic = global_header[:4]

        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }

        if magic not in formats:
            raise ValueError(
                "Unsupported capture format. "
                "Expected classic PCAP."
            )

        endian = formats[magic]

        network = struct.unpack(
            endian + "I",
            global_header[20:24]
        )[0]

        # Ethernet
        if network != 1:
            raise ValueError(
                f"Unsupported link type: {network}"
            )

        nanosecond = magic in (
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        )

        while True:

            record_header = handle.read(16)

            if not record_header:
                break

            if len(record_header) != 16:
                raise ValueError(
                    "Truncated PCAP packet header"
                )

            seconds, fraction, captured_length, _ = struct.unpack(
                endian + "IIII",
                record_header,
            )

            if stats is not None:
                stats.records_seen += 1

            if captured_length > max_captured_packet_size:
                if stats is not None:
                    stats.records_too_large += 1
                    stats.packets_rejected += 1

                current_position = handle.tell()
                remaining_bytes = path.stat().st_size - current_position

                if remaining_bytes < captured_length:
                    if stats is not None:
                        stats.truncated_records += 1
                    raise ValueError(
                        "Truncated PCAP packet"
                    )

                handle.seek(captured_length, 1)
                continue

            raw = handle.read(captured_length)

            if len(raw) != captured_length:
                if stats is not None:
                    stats.truncated_records += 1
                raise ValueError(
                    "Truncated PCAP packet"
                )

            if nanosecond:
                timestamp = seconds + fraction / 1_000_000_000
            else:
                timestamp = seconds + fraction / 1_000_000

            packet = _parse_ethernet(
                timestamp,
                raw,
            )

            if packet is not None:
                if stats is not None:
                    stats.packets_yielded += 1
                yield packet
            elif stats is not None:
                stats.packets_rejected += 1
