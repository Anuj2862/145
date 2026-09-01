from pathlib import Path
import os
import tempfile

from features.feature_engine import (
    CANONICAL_FEATURE_NAMES,
    DEFAULT_WINDOWS_SECONDS,
    FEATURE_SCHEMA_VERSION,
    FeatureEngine,
)
from ingest.pcap_reader import iter_pcap
from schemas.flow_event import FlowEvent
from schemas.telemetry import DNSMetadata, TLSMetadata, QUICMetadata
from tests.test_pcap_reader import (
    _dns_query_payload,
    _ethernet,
    _ipv4,
    _pcap_bytes,
    _tcp,
    _tls_client_hello_payload,
    _udp,
)


def make_flow(
    timestamp: float,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "198.51.100.2",
    src_port: int = 50000,
    dst_port: int = 443,
    protocol: int = 6,
    packet_count: int = 10,
    byte_count: int = 1000,
    duration: float = 1.0,
    syn_count: int = 1,
    ack_count: int = 9,
    rst_count: int = 0,
    packet_lengths: tuple[int, ...] = (100, 120, 140),
    dns: DNSMetadata | None = None,
    tls: TLSMetadata | None = None,
    quic: QUICMetadata | None = None,
) -> FlowEvent:
    return FlowEvent(
        timestamp=timestamp,
        event_time=timestamp,
        flow_id=f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_count=packet_count,
        byte_count=byte_count,
        duration=duration,
        packet_rate=packet_count / duration if duration > 0 else 0.0,
        byte_rate=byte_count / duration if duration > 0 else 0.0,
        syn_count=syn_count,
        ack_count=ack_count,
        fin_count=0,
        rst_count=rst_count,
        psh_count=0,
        urg_count=0,
        syn_ratio=syn_count / packet_count if packet_count else 0.0,
        ack_ratio=ack_count / packet_count if packet_count else 0.0,
        fin_ratio=0.0,
        rst_ratio=rst_count / packet_count if packet_count else 0.0,
        packet_length_min=min(packet_lengths) if packet_lengths else 0.0,
        packet_length_max=max(packet_lengths) if packet_lengths else 0.0,
        packet_length_mean=sum(packet_lengths) / len(packet_lengths) if packet_lengths else 0.0,
        packet_length_std=0.0,
        iat_min_ms=10.0,
        iat_max_ms=20.0,
        iat_mean_ms=15.0,
        iat_std_ms=5.0,
        packet_lengths=packet_lengths,
        inter_arrival_times_ms=(10.0, 20.0),
        dns=dns,
        tls=tls,
        quic=quic,
    )


def _values(events, entity_id="10.0.0.1", as_of=100.0):
    return FeatureEngine().extract_from_events(
        events,
        entity_id=entity_id,
        as_of_event_time=as_of,
    )


def test_feature_schema_is_versioned_and_described():
    engine = FeatureEngine()
    schema = engine.schema()

    assert engine.schema_version == FEATURE_SCHEMA_VERSION
    assert len(CANONICAL_FEATURE_NAMES) == len(schema)
    assert set(DEFAULT_WINDOWS_SECONDS) == {1, 5, 15, 30, 60, 300}
    assert schema["duration"].family == "flow"
    assert schema["duration"].missing_data_policy


def test_flow_family_features_are_populated():
    result = _values([make_flow(100.0)])
    values = result.values()

    assert values["60s.duration"] == 1.0
    assert values["60s.total_packets"] == 10
    assert values["60s.total_bytes"] == 1000
    assert values["60s.bytes_forward"] == 1000
    assert values["60s.packets_forward"] == 10
    assert values["60s.packet_size_mean"] == 120.0
    assert values["60s.packet_size_min"] == 100
    assert values["60s.packet_size_max"] == 140
    assert values["60s.syn_ratio"] == 0.1
    assert result.features["60s.syn_ratio"].metadata.family == "flow"


def test_temporal_family_features_are_populated():
    result = _values([
        make_flow(70.0),
        make_flow(80.0),
        make_flow(90.0),
        make_flow(100.0),
    ])
    values = result.values()

    assert values["60s.iat_mean"] == 10000.0
    assert values["60s.iat_median"] == 10000.0
    assert values["60s.iat_mad"] == 0.0
    assert values["60s.iat_cv"] == 0.0
    assert values["60s.periodicity_score"] == 1.0
    assert values["60s.jitter"] == 0.0


def test_dns_family_features_are_populated_without_zero_filling_unknowns():
    result = _values([
        make_flow(
            99.0,
            protocol=17,
            dst_port=53,
            dns=DNSMetadata(
                query_name="a1b2c3.example.test",
                query_type="TXT",
                response_code="NXDOMAIN",
            ),
        )
    ])
    values = result.values()

    assert values["60s.dns_query_count"] == 1
    assert values["60s.unique_domain_count"] == 1
    assert values["60s.unique_subdomain_count"] == 1
    assert values["60s.txt_ratio"] == 1.0
    assert values["60s.nxdomain_ratio"] == 1.0
    assert values["60s.domain_entropy"] is not None
    assert values["60s.tls_version"] is None
    assert result.features["60s.tls_version"].missing_reason == "tls_quic_metadata_unavailable"


def test_tls_quic_family_features_are_populated():
    result = _values([
        make_flow(
            100.0,
            tls=TLSMetadata(
                sni="secure.example.test",
                alpn="h2",
                ja3_hash="JA3_A",
                ja4_hash="JA4_A",
                tls_version="TLS1.3",
            ),
        ),
        make_flow(
            101.0,
            dst_port=8443,
            quic=QUICMetadata(sni="quic.example.test", alpn="h3", version="1"),
        ),
    ], as_of=101.0)
    values = result.values()

    assert values["60s.tls_version"] == "TLS1.3"
    assert values["60s.ja3"] == "JA3_A"
    assert values["60s.ja4"] == "JA4_A"
    assert values["60s.sni"] == "secure.example.test"
    assert values["60s.alpn"] == "h2"
    assert values["60s.tls_packet_size_mean"] == 120.0
    assert values["60s.tls_fingerprint_novelty"] == 1


def test_recon_family_features_are_populated():
    events = [
        make_flow(100.0, dst_ip=f"198.51.100.{index}", dst_port=80 + index, byte_count=0, rst_count=1)
        for index in range(1, 6)
    ]
    result = _values(events)
    values = result.values()

    assert values["60s.unique_dst_ips"] == 5
    assert values["60s.unique_dst_ports"] == 5
    assert values["60s.connection_attempt_rate"] == 5 / 60
    assert values["60s.failed_connection_ratio"] == 1.0
    assert values["60s.fan_out"] == 1.0
    assert values["60s.destination_entropy"] is not None


def test_exfil_family_features_are_populated():
    result = _values([
        make_flow(99.0, byte_count=2_000_000, duration=120.0),
        make_flow(100.0, src_ip="198.51.100.2", dst_ip="10.0.0.1", src_port=443, dst_port=50000, byte_count=500),
    ])
    values = result.values()

    assert values["60s.outbound_bytes"] == 2_000_000
    assert values["60s.inbound_bytes"] == 500
    assert values["60s.outbound_rate"] == 2_000_000 / 60
    assert values["60s.inbound_rate"] == 500 / 60
    assert values["60s.upload_download_ratio"] == 4000.0
    assert values["60s.large_flow_count"] == 1
    assert values["60s.long_flow_count"] == 1


def test_entity_family_features_are_populated():
    engine = FeatureEngine()
    previous = [make_flow(70.0, dst_ip="198.51.100.10")]
    current = [make_flow(100.0, dst_ip="198.51.100.11")]

    engine.extract_from_events(previous, entity_id="10.0.0.1", as_of_event_time=70.0, update_history=True)
    result = engine.extract_from_events(current, entity_id="10.0.0.1", as_of_event_time=100.0)
    values = result.values()

    assert values["60s.entity_flow_count"] == 1
    assert values["60s.entity_unique_destinations"] == 1
    assert values["60s.entity_new_destinations"] == 1
    assert values["60s.baseline_deviation"] is None
    assert result.features["60s.baseline_deviation"].missing_reason == "insufficient_entity_baseline"


def test_multiple_windows_are_respected_with_bounded_state():
    result = _values([make_flow(96.0), make_flow(100.0)], as_of=100.0)
    values = result.values()

    assert values["1s.entity_flow_count"] == 1
    assert values["5s.entity_flow_count"] == 2
    assert values["300s.entity_flow_count"] == 2
    assert result.features["1s.iat_mean"].missing_reason == "insufficient_event_time_observations"


def _write_temp_pcap(frames: list[bytes]) -> str:
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        handle.write(_pcap_bytes(frames))
        return handle.name
    finally:
        handle.close()


def _feature_set_from_temp_pcap(frames: list[bytes], entity_id: str = "192.0.2.1"):
    path = _write_temp_pcap(frames)
    try:
        engine = FeatureEngine()
        latest = None
        for packet in iter_pcap(path):
            latest = engine.update_packet(packet)
        assert latest is not None
        if latest.entity_id != entity_id:
            latest = engine.extract(entity_id=entity_id)
        return latest
    finally:
        os.unlink(path)


def test_dataset_dns_pcap_marks_zero_payload_dns_as_unavailable():
    pcap_path = Path("dataset/pcaps/dns/dga_dns_tunnel_queries.pcap")
    assert pcap_path.exists()

    packets = list(iter_pcap(pcap_path))
    dns_transport_packets = [
        packet for packet in packets
        if packet.protocol == 17 and (packet.src_port == 53 or packet.dst_port == 53)
    ]
    assert dns_transport_packets
    assert all(packet.dns is None for packet in dns_transport_packets)

    engine = FeatureEngine()
    latest = None
    for packet in dns_transport_packets[:10]:
        latest = engine.update_packet(packet)

    values = latest.values()
    assert values["60s.dns_query_count"] == 0
    assert values["60s.unique_domain_count"] == 0
    assert values["60s.domain_entropy"] is None
    assert latest.features["60s.domain_entropy"].missing_reason == "dns_metadata_unavailable"


def test_pcap_derived_dns_features_populate_when_dns_question_exists():
    frame = _ethernet(
        0x0800,
        _ipv4(17, _udp(payload=_dns_query_payload("a1b2c3.example.test"))),
    )

    result = _feature_set_from_temp_pcap([frame])
    values = result.values()

    assert values["60s.dns_query_count"] == 1
    assert values["60s.unique_domain_count"] == 1
    assert values["60s.unique_subdomain_count"] == 1
    assert values["60s.txt_ratio"] == 1.0
    assert values["60s.domain_entropy"] is not None
    assert result.features["60s.domain_entropy"].missing_reason is None


def test_pcap_derived_tls_features_populate_when_client_hello_exists():
    frame = _ethernet(
        0x0800,
        _ipv4(6, _tcp(flags=0x18, payload=_tls_client_hello_payload())),
    )

    result = _feature_set_from_temp_pcap([frame])
    values = result.values()

    assert values["60s.tls_version"] == "TLS1.2"
    assert values["60s.sni"] == "secure.example.test"
    assert values["60s.alpn"] == "h2"
    assert values["60s.tls_packet_size_mean"] is not None
    assert result.features["60s.sni"].missing_reason is None


def test_real_pcap_recon_exfil_and_entity_features_populate_with_history():
    recon_packets = list(iter_pcap("dataset/pcaps/recon/horizontal_vertical_port_scan.pcap"))
    recon_engine = FeatureEngine()
    recon_latest = None
    for packet in recon_packets[:40]:
        recon_latest = recon_engine.update_packet(packet)

    recon_values = recon_latest.values()
    assert recon_values["60s.unique_dst_ports"] >= 40
    assert recon_values["60s.connection_attempt_rate"] > 0
    assert recon_values["60s.failed_connection_ratio"] == 1.0
    assert recon_values["60s.entity_flow_count"] >= 40

    exfil_packets = list(iter_pcap("dataset/pcaps/exfiltration/outbound_bulk_exfil_burst.pcap"))
    exfil_engine = FeatureEngine()
    exfil_latest = None
    for packet in exfil_packets[:80]:
        exfil_latest = exfil_engine.update_packet(packet)

    exfil_values = exfil_latest.values()
    assert exfil_values["60s.outbound_bytes"] > 0
    assert exfil_values["60s.outbound_rate"] > 0
    assert exfil_values["60s.inbound_bytes"] == 0
    assert exfil_latest.features["60s.inbound_bytes"].missing_reason is None
    assert exfil_latest.features["60s.upload_download_ratio"].missing_reason == "inbound_bytes_zero"
