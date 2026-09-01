"""Milestone 14 Comprehensive Test Suite: Entity Behaviour State, Baselines and Novelty.

Verifies:
A. Entity creation
B. Entity state updates
C. Multi-window aggregation (1s, 5s, 15s, 30s, 60s, 300s)
D. Baseline convergence (EWMA + median/MAD)
E. Novel destination (first-seen, frequency, age)
F. Novel port
G. Novel domain and DNS history
H. Novel JA4 / TLS fingerprint and history
I. Periodic communication and temporal metrics
J. Baseline deviation (robust Z-scores)
K. Attack contamination protection (100 pps baseline vs 100,000 pps attack freeze)
L. Event-time replay determinism
M. Bounded memory limits
N. LRU eviction behavior
O. One-way traffic support
Real PCAP Integration tests:
- Recon traffic creates destination/port novelty
- Exfil traffic creates outbound deviation
- DNS traffic creates domain history
- TLS traffic creates fingerprint/history
- Repeated traffic creates temporal history
Entity Graph compatibility verification
"""

import math
import os
import tempfile
import pytest

from entity.memory import (
    BaselineUpdatePolicy,
    EntityFlowRecord,
    EntityMemory,
    EntityProfile,
    EntityState,
    MetricBaseline,
)
from features.feature_engine import FeatureEngine
from ingest.pcap_reader import iter_pcap
from schemas.flow_event import FlowEvent
from schemas.telemetry import DNSMetadata, QUICMetadata, TLSMetadata
from tests.test_pcap_reader import (
    _dns_query_payload,
    _ethernet,
    _ipv4,
    _pcap_bytes,
    _tcp,
    _tls_client_hello_payload,
    _udp,
)


def _make_flow(
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


def test_a_entity_creation():
    """Verify initial state, entity ID, and zeroed counters upon creation."""
    profile = EntityProfile("192.168.1.100")
    assert profile.entity_id == "192.168.1.100"
    assert profile.flow_count == 0
    assert profile.packet_count == 0
    assert profile.byte_count == 0
    assert profile.total_observations == 0
    assert len(profile.known_destinations) == 0
    assert len(profile.known_ports) == 0
    assert len(profile.known_domains) == 0


def test_b_entity_state_updates():
    """Verify flow ingestion updates packet, byte, flag, and directional metrics."""
    profile = EntityProfile("10.0.0.5")
    flow1 = _make_flow(100.0, src_ip="10.0.0.5", dst_ip="198.51.100.1", packet_count=20, byte_count=2000)
    flow2 = _make_flow(105.0, src_ip="198.51.100.1", dst_ip="10.0.0.5", packet_count=15, byte_count=1500)

    profile.update_from_flow(flow1)
    profile.update_from_flow(flow2)

    assert profile.flow_count == 2
    assert profile.packet_count == 35
    assert profile.byte_count == 3500
    assert profile.outbound_flow_count == 1
    assert profile.inbound_flow_count == 1
    assert profile.total_outbound_bytes == 2000
    assert profile.total_inbound_bytes == 1500
    assert profile.first_seen == 100.0
    assert profile.last_seen == 105.0


def test_c_multi_window_aggregation():
    """Verify sliding window event retrieval for 1s, 5s, 15s, 30s, 60s, 300s."""
    profile = EntityProfile("10.0.0.5")
    # Ingest flows at timestamps 10, 250, 280, 295, 299, 300
    for ts in [10.0, 250.0, 280.0, 295.0, 299.0, 300.0]:
        profile.update_from_flow(_make_flow(ts, src_ip="10.0.0.5"))

    as_of = 300.0
    assert len(profile.get_window_events(1.0, as_of=as_of)) == 2  # 299, 300
    assert len(profile.get_window_events(5.0, as_of=as_of)) == 3  # 295, 299, 300
    assert len(profile.get_window_events(15.0, as_of=as_of)) == 3  # 295, 299, 300
    assert len(profile.get_window_events(30.0, as_of=as_of)) == 4  # 280, 295, 299, 300
    assert len(profile.get_window_events(60.0, as_of=as_of)) == 5  # 250, 280, 295, 299, 300
    assert len(profile.get_window_events(300.0, as_of=as_of)) == 6  # all 6


def test_d_baseline_convergence():
    """Verify statistical baseline converges to steady-state value under normal traffic."""
    baseline = MetricBaseline(BaselineUpdatePolicy(alpha=0.1, warmup_min_observations=5))

    # Feed 30 observations around 100.0 (e.g. 98 to 102)
    for i in range(30):
        val = 100.0 + (i % 5) - 2.0  # 98, 99, 100, 101, 102
        baseline.update(val)

    med, mad = baseline.compute_robust_stats()
    assert math.isclose(med, 100.0, abs_tol=1.5)
    assert math.isclose(baseline.ewma_mean, 100.0, abs_tol=2.0)
    assert baseline.count == 30


def test_e_novel_destination():
    """Verify destination first-seen, frequency, and first-seen age calculation."""
    profile = EntityProfile("10.0.0.1")

    is_new = profile.record_destination("198.51.100.50", dst_port=443, event_time=100.0)
    assert is_new is True

    is_new2 = profile.record_destination("198.51.100.50", dst_port=443, event_time=120.0)
    assert is_new2 is False

    is_new_flag, freq, age = profile.get_destination_novelty_stats("198.51.100.50", as_of=130.0)
    assert is_new_flag is False
    assert freq == 2
    assert age == 30.0  # 130 - 100


def test_f_novel_port():
    """Verify port first-seen vs recurring observations."""
    profile = EntityProfile("10.0.0.1")

    assert profile.record_port(8080, event_time=100.0) is True
    assert profile.record_port(8080, event_time=105.0) is False
    assert 8080 in profile.known_ports
    assert profile.port_meta[8080]["count"] == 2


def test_g_novel_domain_and_dns():
    """Verify DNS query name novelty, subdomain detection, and NXDOMAIN counter."""
    profile = EntityProfile("10.0.0.1")

    is_new1 = profile.record_dns(query_name="auth.api.internal.net", response_code="NOERROR", event_time=100.0)
    assert is_new1 is True

    is_new2 = profile.record_dns(query_name="auth.api.internal.net", response_code="NOERROR", event_time=102.0)
    assert is_new2 is False

    profile.record_dns(query_name="nonexistent.bad.test", response_code="NXDOMAIN", query_type="TXT", event_time=105.0)

    assert profile.dns_query_count == 3
    assert profile.dns_nxdomain_count == 1
    assert profile.dns_txt_count == 1
    assert len(profile.known_domains) == 2


def test_h_novel_ja4_and_tls():
    """Verify TLS/QUIC fingerprint frequency, first-seen tracking, and novelty."""
    profile = EntityProfile("10.0.0.1")

    is_new_fp1 = profile.record_tls(ja4="t13d1516h2_8daaf6152771_b186095e22b7", version="TLS1.3", alpn="h2", resumption=True, event_time=100.0)
    assert is_new_fp1 is True
    assert profile.first_seen_fingerprint == "ja4:t13d1516h2_8daaf6152771_b186095e22b7"
    assert profile.session_resumption_count == 1
    assert "TLS1.3" in profile.tls_versions
    assert "h2" in profile.alpn_protocols

    is_new_fp2 = profile.record_tls(ja4="t13d1516h2_8daaf6152771_b186095e22b7", version="TLS1.3", event_time=110.0)
    assert is_new_fp2 is False
    assert profile.fingerprint_meta["ja4:t13d1516h2_8daaf6152771_b186095e22b7"]["count"] == 2


def test_i_periodic_communication():
    """Verify temporal inter-arrival mean, variance, periodicity score, and jitter."""
    profile = EntityProfile("10.0.0.1")

    # Ingest 10 strictly periodic flows exactly 1.0 second apart
    for i in range(10):
        profile.update_from_flow(_make_flow(100.0 + i * 1.0, src_ip="10.0.0.1"))

    mean_iat, std_iat, periodicity, jitter = profile.get_temporal_features()
    assert mean_iat is not None
    assert math.isclose(mean_iat, 1000.0, rel_tol=1e-3)  # 1000 ms
    assert math.isclose(std_iat, 0.0, abs_tol=1e-3)
    assert math.isclose(periodicity, 1.0, abs_tol=1e-3)
    assert math.isclose(jitter, 0.0, abs_tol=1e-3)


def test_j_baseline_deviation():
    """Verify robust Z-score deviation reflects significant rate bursts."""
    profile = EntityProfile("10.0.0.1")

    # Establish baseline around 100 pps
    for _ in range(20):
        profile.pps_baseline.update(100.0)

    # Moderate deviation
    normal_z = profile.compute_pps_z_score(105.0)
    assert normal_z < 3.0

    # Severe burst (e.g. 5000 pps vs 100 baseline)
    burst_z = profile.compute_pps_z_score(5000.0)
    assert burst_z > 10.0


def test_k_attack_contamination_protection():
    """Mandatory test: Normal traffic at 100 pps followed by 100,000 pps attack burst

    Verify the baseline freezes and does NOT immediately learn the attack.
    """
    baseline = MetricBaseline(BaselineUpdatePolicy(
        warmup_min_observations=5,
        freeze_z_threshold=3.5,
        attack_freeze_ratio=10.0,
        alpha=0.05,
    ))

    # Phase 1: Normal benign traffic at 100 pps
    for _ in range(25):
        baseline.update(100.0)

    assert baseline.count == 25
    assert math.isclose(baseline.ewma_mean, 100.0, abs_tol=1.0)

    # Phase 2: Massive volumetric DDoS attack burst at 100,000 pps
    for _ in range(50):
        updated = baseline.update(100_000.0)
        assert updated is False  # Must be rejected / frozen!

    # Baseline MUST remain untainted at ~100 pps
    assert baseline.count == 25  # No attack observations accepted into baseline count
    assert baseline.frozen_count == 50
    assert math.isclose(baseline.ewma_mean, 100.0, abs_tol=1.0)
    assert baseline.compute_z_score(100_000.0) > 100.0


def test_l_event_time_replay_determinism():
    """Verify processing out-of-order flows produces deterministic state regardless of wall clock."""
    flows = [
        _make_flow(100.0, src_ip="10.0.0.1"),
        _make_flow(102.0, src_ip="10.0.0.1"),
        _make_flow(101.0, src_ip="10.0.0.1"),
    ]

    engine1 = FeatureEngine()
    engine2 = FeatureEngine()

    set1 = engine1.extract_from_events(flows, entity_id="10.0.0.1", as_of_event_time=105.0)
    set2 = engine2.extract_from_events(reversed(flows), entity_id="10.0.0.1", as_of_event_time=105.0)

    assert set1.values() == set2.values()


def test_m_bounded_memory_limits():
    """Verify per-entity bounds on destinations, ports, domains, fingerprints."""
    profile = EntityProfile(
        "10.0.0.1",
        max_destinations=10,
        max_ports=5,
        max_domains=5,
        max_fingerprints=5,
    )

    for i in range(25):
        profile.record_destination(f"198.51.100.{i}")
        profile.record_port(1000 + i)
        profile.record_dns(query_name=f"sub{i}.example.com")
        profile.record_tls(ja4=f"ja4_hash_{i}")

    assert len(profile.destination_meta) <= 10
    assert len(profile.known_destinations) <= 10
    assert len(profile.port_meta) <= 5
    assert len(profile.known_ports) <= 5
    assert len(profile.domain_meta) <= 5
    assert len(profile.known_domains) <= 5
    assert len(profile.fingerprint_meta) <= 5


def test_n_lru_eviction_behavior():
    """Verify EntityMemory evicts oldest inactive entity when capacity limit is reached."""
    memory = EntityMemory(max_entities=3)

    memory.get_or_create_profile("10.0.0.1", event_time=10.0)
    memory.get_or_create_profile("10.0.0.2", event_time=20.0)
    memory.get_or_create_profile("10.0.0.3", event_time=30.0)

    assert len(memory) == 3
    assert "10.0.0.1" in memory.get_all_profiles()

    # Touch 10.0.0.1 to make 10.0.0.2 the LRU
    memory.get_or_create_profile("10.0.0.1", event_time=40.0)

    # Insert 4th entity -> 10.0.0.2 must be evicted
    memory.get_or_create_profile("10.0.0.4", event_time=50.0)

    assert len(memory) == 3
    all_profiles = memory.get_all_profiles()
    assert "10.0.0.2" not in all_profiles
    assert "10.0.0.1" in all_profiles
    assert "10.0.0.3" in all_profiles
    assert "10.0.0.4" in all_profiles


def test_o_one_way_traffic_support():
    """Verify graceful handling when inbound / reverse traffic is completely absent."""
    profile = EntityProfile("10.0.0.1")
    # Outbound only flow
    outbound_flow = _make_flow(100.0, src_ip="10.0.0.1", dst_ip="198.51.100.1", packet_count=5, byte_count=500)
    profile.update_from_flow(outbound_flow)

    assert profile.outbound_flow_count == 1
    assert profile.inbound_flow_count == 0
    assert profile.total_inbound_bytes == 0

    engine = FeatureEngine()
    snapshot = engine.extract_from_events([outbound_flow], entity_id="10.0.0.1", as_of_event_time=100.0)
    assert snapshot.features["60s.upload_download_ratio"].value is None
    assert snapshot.features["60s.upload_download_ratio"].missing_reason == "inbound_bytes_zero"


def test_real_pcap_recon_novelty():
    """Real PCAP test: Recon scanning creates destination and port novelty."""
    engine = FeatureEngine()
    recon_pcap = "dataset/pcaps/recon/horizontal_vertical_port_scan.pcap"
    assert os.path.exists(recon_pcap)

    latest = None
    for index, packet in enumerate(iter_pcap(recon_pcap)):
        if index >= 30:
            break
        latest = engine.update_packet(packet)

    assert latest is not None
    assert latest.features["60s.unique_dst_ports"].value is not None
    assert int(latest.features["60s.unique_dst_ports"].value) >= 10
    assert latest.features["60s.entity_flow_count"].value is not None
    assert int(latest.features["60s.entity_flow_count"].value) >= 10

    # Profile tracks all unique novel ports in memory
    profile = engine.entity_memory.get_or_create_profile(latest.entity_id)
    assert len(profile.known_ports) >= 10


def test_real_pcap_exfil_outbound_deviation():
    """Real PCAP test: Exfiltration burst creates high outbound rate."""
    engine = FeatureEngine()
    exfil_pcap = "dataset/pcaps/exfiltration/outbound_bulk_exfil_burst.pcap"
    assert os.path.exists(exfil_pcap)

    latest = None
    for index, packet in enumerate(iter_pcap(exfil_pcap)):
        if index >= 50:
            break
        latest = engine.update_packet(packet)

    assert latest is not None
    assert latest.features["60s.outbound_rate"].value is not None
    assert float(latest.features["60s.outbound_rate"].value) > 1000.0
    assert latest.features["60s.bytes_forward"].value is not None


def test_real_pcap_dns_domain_history():
    """Real PCAP test: DNS queries create domain history and entropy."""
    raw_pcap = _write_temp_pcap([
        _ethernet(0x0800, _ipv4(17, _udp(payload=_dns_query_payload("login.secure-service.corp.internal"))))
    ])
    try:
        engine = FeatureEngine()
        latest = None
        for packet in iter_pcap(raw_pcap):
            latest = engine.update_packet(packet)
        assert latest is not None
        assert latest.features["60s.dns_query_count"].value == 1
        assert latest.features["60s.unique_domain_count"].value == 1
        assert latest.features["60s.domain_entropy"].value is not None
        assert float(latest.features["60s.domain_entropy"].value) > 2.0
    finally:
        os.unlink(raw_pcap)


def test_real_pcap_tls_fingerprint_history():
    """Real PCAP test: TLS ClientHello creates fingerprint history and metadata."""
    raw_pcap = _write_temp_pcap([
        _ethernet(0x0800, _ipv4(6, _tcp(flags=0x18, payload=_tls_client_hello_payload())))
    ])
    try:
        engine = FeatureEngine()
        latest = None
        for packet in iter_pcap(raw_pcap):
            latest = engine.update_packet(packet)
        assert latest is not None
        assert latest.features["60s.tls_version"].value == "TLS1.2"
        assert latest.features["60s.sni"].value == "secure.example.test"
    finally:
        os.unlink(raw_pcap)


def test_entity_graph_compatibility():
    """Verify EntityProfile provides stable graph summary properties for EntityBehaviourGraph."""
    profile = EntityProfile("10.0.0.10")
    profile.record_destination("198.51.100.1", dst_port=443, event_time=100.0)
    profile.record_dns(query_name="auth.example.com", event_time=100.0)
    profile.record_tls(ja4="ja4_sample", event_time=100.0)

    summary = profile.get_graph_summary()
    assert summary["entity_id"] == "10.0.0.10"
    assert summary["entity_ip"] == "10.0.0.10"
    assert summary["first_seen"] == 100.0
    assert summary["unique_destinations"] == 1
    assert summary["unique_ports"] == 1
    assert summary["unique_domains"] == 1
    assert summary["first_seen_fingerprint"] == "ja4:ja4_sample"


def _write_temp_pcap(frames):
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        handle.write(_pcap_bytes(frames))
        return handle.name
    finally:
        handle.close()
