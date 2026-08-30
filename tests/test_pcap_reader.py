import os
import struct
import tempfile
import unittest

from ingest.pcap_reader import PcapIngestionStats, iter_pcap


def _pcap_bytes(
    frames: list[bytes],
    captured_lengths: list[int] | None = None,
) -> bytes:
    data = bytearray()
    data.extend(b"\xd4\xc3\xb2\xa1")
    data.extend(struct.pack("<HHIIII", 2, 4, 0, 0, 65_535, 1))

    lengths = captured_lengths or [len(frame) for frame in frames]

    for index, frame in enumerate(frames):
        captured_length = lengths[index]
        data.extend(
            struct.pack(
                "<IIII",
                100 + index,
                0,
                captured_length,
                captured_length,
            )
        )
        data.extend(frame)

    return bytes(data)


def _write_temp_pcap(data: bytes) -> str:
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")

    try:
        handle.write(data)
        return handle.name
    finally:
        handle.close()


def _ethernet(
    eth_type: int,
    payload: bytes,
) -> bytes:
    return (
        b"\x00\x01\x02\x03\x04\x05"
        b"\x06\x07\x08\x09\x0a\x0b"
        + struct.pack("!H", eth_type)
        + payload
    )


def _vlan_ethernet(
    inner_eth_type: int,
    payload: bytes,
) -> bytes:
    return (
        b"\x00\x01\x02\x03\x04\x05"
        b"\x06\x07\x08\x09\x0a\x0b"
        + struct.pack("!HHH", 0x8100, 1, inner_eth_type)
        + payload
    )


def _ipv4(
    protocol: int,
    payload: bytes,
    version_ihl: int = 0x45,
    total_length: int | None = None,
) -> bytes:
    total_length = 20 + len(payload) if total_length is None else total_length
    return (
        bytes([version_ihl, 0])
        + struct.pack("!H", total_length)
        + b"\x00\x00\x00\x00"
        + bytes([64, protocol])
        + b"\x00\x00"
        + bytes([192, 0, 2, 1])
        + bytes([198, 51, 100, 2])
        + payload
    )


def _ipv6(
    next_header: int,
    payload: bytes,
    payload_length: int | None = None,
) -> bytes:
    payload_length = (
        len(payload)
        if payload_length is None
        else payload_length
    )
    return (
        b"\x60\x00\x00\x00"
        + struct.pack("!H", payload_length)
        + bytes([next_header, 64])
        + bytes.fromhex("20010db8000000000000000000000001")
        + bytes.fromhex("20010db8000000000000000000000002")
        + payload
    )


def _tcp(
    data_offset_byte: int = 0x50,
    flags: int = 0x02,
) -> bytes:
    return (
        struct.pack("!HH", 12345, 443)
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + bytes([data_offset_byte, flags])
        + b"\x00\x00\x00\x00\x00\x00"
    )


def _udp(
    length: int = 8,
) -> bytes:
    return struct.pack("!HHHH", 12345, 53, length, 0)


def _packets_from_frame(
    frame: bytes,
    stats: PcapIngestionStats | None = None,
    max_captured_packet_size: int = 262_144,
):
    path = _write_temp_pcap(_pcap_bytes([frame]))

    try:
        return list(
            iter_pcap(
                path,
                max_captured_packet_size=max_captured_packet_size,
                stats=stats,
            )
        )
    finally:
        os.unlink(path)


class TestPcapReaderHardening(unittest.TestCase):
    def test_truncated_ethernet_frame_is_rejected(self):
        stats = PcapIngestionStats()

        packets = _packets_from_frame(b"\x00" * 13, stats)

        self.assertEqual(packets, [])
        self.assertEqual(stats.packets_rejected, 1)

    def test_truncated_ipv4_header_is_rejected(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, b"\x45" + b"\x00" * 18)
        )

        self.assertEqual(packets, [])

    def test_invalid_ipv4_ihl_is_rejected(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(6, _tcp(), version_ihl=0x44))
        )

        self.assertEqual(packets, [])

    def test_ipv4_total_length_smaller_than_ihl_is_rejected(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(6, _tcp(), total_length=19))
        )

        self.assertEqual(packets, [])

    def test_ipv4_total_length_larger_than_captured_bytes_is_rejected(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(6, _tcp(), total_length=41))
        )

        self.assertEqual(packets, [])

    def test_truncated_tcp_header_is_rejected(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(6, _tcp()[:19]))
        )

        self.assertEqual(packets, [])

    def test_invalid_tcp_data_offset_is_rejected(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(6, _tcp(data_offset_byte=0x40)))
        )

        self.assertEqual(packets, [])

    def test_truncated_udp_header_is_rejected(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(17, _udp()[:7]))
        )

        self.assertEqual(packets, [])

    def test_invalid_too_large_captured_length_is_rejected(self):
        frame = _ethernet(0x0800, _ipv4(6, _tcp()))
        stats = PcapIngestionStats()

        packets = _packets_from_frame(
            frame,
            stats=stats,
            max_captured_packet_size=len(frame) - 1,
        )

        self.assertEqual(packets, [])
        self.assertEqual(stats.records_too_large, 1)
        self.assertEqual(stats.packets_rejected, 1)

    def test_truncated_pcap_record_raises_clean_error(self):
        frame = _ethernet(0x0800, _ipv4(6, _tcp()))
        path = _write_temp_pcap(
            _pcap_bytes(
                [frame[:-1]],
                captured_lengths=[len(frame)],
            )
        )
        stats = PcapIngestionStats()

        try:
            with self.assertRaisesRegex(ValueError, "Truncated PCAP packet"):
                list(iter_pcap(path, stats=stats))

            self.assertEqual(stats.truncated_records, 1)
        finally:
            os.unlink(path)

    def test_valid_ipv4_tcp_still_parses(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(6, _tcp(flags=0x12)))
        )

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].src_ip, "192.0.2.1")
        self.assertEqual(packets[0].dst_ip, "198.51.100.2")
        self.assertEqual(packets[0].src_port, 12345)
        self.assertEqual(packets[0].dst_port, 443)
        self.assertEqual(packets[0].tcp_syn, 1)
        self.assertEqual(packets[0].tcp_ack, 1)

    def test_valid_ipv4_udp_still_parses(self):
        packets = _packets_from_frame(
            _ethernet(0x0800, _ipv4(17, _udp()))
        )

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].src_port, 12345)
        self.assertEqual(packets[0].dst_port, 53)
        self.assertEqual(packets[0].protocol, 17)

    def test_valid_vlan_still_parses(self):
        packets = _packets_from_frame(
            _vlan_ethernet(0x0800, _ipv4(6, _tcp()))
        )

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].protocol, 6)
        self.assertEqual(packets[0].src_port, 12345)

    def test_valid_ipv6_still_parses(self):
        packets = _packets_from_frame(
            _ethernet(0x86DD, _ipv6(6, _tcp()))
        )

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].src_ip, "2001:db8::1")
        self.assertEqual(packets[0].dst_ip, "2001:db8::2")
        self.assertEqual(packets[0].src_port, 12345)
        self.assertEqual(packets[0].dst_port, 443)


if __name__ == "__main__":
    unittest.main()
