from dataclasses import dataclass
from pathlib import Path
import socket
import struct
from typing import Iterator, Optional


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
    )


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
