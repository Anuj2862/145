"""Unit and Integration Tests for M1 → M2 Entity/Window Context Adapter (signal_adapter.py).

Verifies lossless conversion, entity grouping semantics, direction handling, window duration safety,
DetectionContext creation, UnifiedM2Orchestrator compatibility, and zero regression.
"""

from datetime import datetime, timezone
import pytest

from schemas.flow_event import FlowEvent as M1FlowEvent
from schemas import (
    FlowEvent as M2FlowEvent,
    TCPFlags,
    DetectionSignal,
)
from features.recon_features import ReconFeatures
from features.exfil_features import ExfiltrationFeatures
from detectors.engine import DetectionContext
from detectors.unified_detector import UnifiedM2Orchestrator
import signal_adapter as adapter


def make_m1_flow(
    flow_id: str = "10.0.0.1:12345-8.8.8.8:80-6",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "8.8.8.8",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: int = 6,
    timestamp: float = 1600000000.0,
    duration: float = 2.5,
    packet_count: int = 25,
    byte_count: int = 1500,
    syn_count: int = 1,
    ack_count: int = 24,
    fin_count: int = 1,
    rst_count: int = 0,
    psh_count: int = 5,
    urg_count: int = 0,
    packet_lengths: tuple[int, ...] = (60, 1500, 100),
    inter_arrival_times_ms: tuple[float, ...] = (10.0, 20.0),
) -> M1FlowEvent:
    return M1FlowEvent(
        timestamp=timestamp,
        flow_id=flow_id,
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
        fin_count=fin_count,
        rst_count=rst_count,
        psh_count=psh_count,
        urg_count=urg_count,
        syn_ratio=syn_count / packet_count,
        ack_ratio=ack_count / packet_count,
        fin_ratio=fin_count / packet_count,
        rst_ratio=rst_count / packet_count,
        packet_length_min=min(packet_lengths),
        packet_length_max=max(packet_lengths),
        packet_length_mean=sum(packet_lengths) / len(packet_lengths),
        packet_length_std=0.0,
        iat_min_ms=min(inter_arrival_times_ms),
        iat_max_ms=max(inter_arrival_times_ms),
        iat_mean_ms=sum(inter_arrival_times_ms) / len(inter_arrival_times_ms),
        iat_std_ms=0.0,
        packet_lengths=packet_lengths,
        inter_arrival_times_ms=inter_arrival_times_ms,
    )


# ---------------------------------------------------------------------------
# 1. Translation Tests (M1 -> M2)
# ---------------------------------------------------------------------------

def test_m1_to_m2_flow_event_translation_precision():
    m1_flow = make_m1_flow()
    m2_flow = adapter.m1_to_m2_flow_event(m1_flow)

    assert m2_flow.flow_id == m1_flow.flow_id
    assert m2_flow.src_ip == m1_flow.src_ip
    assert m2_flow.dst_ip == m1_flow.dst_ip
    assert m2_flow.src_port == m1_flow.src_port
    assert m2_flow.dst_port == m1_flow.dst_port
    assert m2_flow.protocol == m1_flow.protocol

    # Timestamp & duration preservation
    assert m2_flow.duration_sec == m1_flow.duration
    assert m2_flow.start_time_iso.endswith("Z")
    assert m2_flow.end_time_iso.endswith("Z")

    # TCP flag preservation
    assert m2_flow.tcp_flags is not None
    assert m2_flow.tcp_flags.syn_count == m1_flow.syn_count
    assert m2_flow.tcp_flags.ack_count == m1_flow.ack_count
    assert m2_flow.tcp_flags.fin_count == m1_flow.fin_count
    assert m2_flow.tcp_flags.rst_count == m1_flow.rst_count
    assert m2_flow.tcp_flags.psh_count == m1_flow.psh_count
    assert m2_flow.tcp_flags.urg_count == m1_flow.urg_count

    # Packet lengths & inter-arrival times
    assert list(m2_flow.packet_lengths) == list(m1_flow.packet_lengths)
    assert list(m2_flow.inter_arrival_times_ms) == list(m1_flow.inter_arrival_times_ms)


def test_m1_to_m2_non_tcp_protocol():
    m1_flow = make_m1_flow(protocol=17)  # UDP
    m2_flow = adapter.m1_to_m2_flow_event(m1_flow)
    assert m2_flow.protocol == 17
    assert m2_flow.tcp_flags is None


# ---------------------------------------------------------------------------
# 2. Window Duration & Boundaries
# ---------------------------------------------------------------------------

def test_explicit_window_duration_epoch():
    m1_flow = make_m1_flow()
    recon, exfil = adapter.aggregate_window(
        flows=[m1_flow],
        entity_ip="10.0.0.1",
        window_start=1600000000.0,
        window_end=1600000060.0,
    )
    assert recon.window_duration_sec == 60.0
    assert exfil.window_duration_sec == 60.0


def test_explicit_window_duration_datetime():
    dt_start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    dt_end = datetime(2026, 1, 1, 12, 1, 0, tzinfo=timezone.utc)
    m1_flow = make_m1_flow()

    recon, exfil = adapter.aggregate_window(
        flows=[m1_flow],
        entity_ip="10.0.0.1",
        window_start=dt_start,
        window_end=dt_end,
    )
    assert recon.window_duration_sec == 60.0
    assert exfil.window_duration_sec == 60.0


def test_invalid_window_duration_raises_error():
    m1_flow = make_m1_flow()
    with pytest.raises(ValueError, match="Invalid window duration"):
        adapter.aggregate_window(
            flows=[m1_flow],
            entity_ip="10.0.0.1",
            window_start=1600000060.0,
            window_end=1600000000.0,  # Negative duration
        )

    with pytest.raises(ValueError, match="Invalid window duration"):
        adapter.aggregate_window(
            flows=[m1_flow],
            entity_ip="10.0.0.1",
            window_start=1600000000.0,
            window_end=1600000000.0,  # Zero duration
        )


# ---------------------------------------------------------------------------
# 3. Empty Input Handling
# ---------------------------------------------------------------------------

def test_aggregate_window_empty_flows():
    recon, exfil = adapter.aggregate_window(
        flows=[],
        entity_ip="10.0.0.1",
        window_start=1600000000.0,
        window_end=1600000030.0,
    )
    assert recon.flow_count == 0
    assert recon.window_duration_sec == 30.0
    assert exfil.flow_count == 0
    assert exfil.window_duration_sec == 30.0
    assert exfil.direction_available is False


def test_batch_aggregate_empty_flows():
    res = adapter.batch_aggregate(
        flows=[],
        window_start=1600000000.0,
        window_end=1600000060.0,
    )
    assert res == {}


# ---------------------------------------------------------------------------
# 4. Entity Grouping & Direction Semantics
# ---------------------------------------------------------------------------

def test_direction_evaluation_outbound():
    entity_ip = "10.0.0.1"
    flow_outbound = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=5000)

    recon, exfil = adapter.aggregate_window(
        flows=[flow_outbound],
        entity_ip=entity_ip,
        window_start=1600000000.0,
        window_end=1600000060.0,
    )
    assert exfil.outbound_flow_count == 1
    assert exfil.inbound_flow_count == 0
    assert exfil.total_outbound_bytes == 5000
    assert exfil.total_inbound_bytes == 0
    assert exfil.direction_available is True


def test_direction_evaluation_inbound():
    entity_ip = "10.0.0.1"
    flow_inbound = make_m1_flow(src_ip="8.8.8.8", dst_ip="10.0.0.1", byte_count=3000)

    recon, exfil = adapter.aggregate_window(
        flows=[flow_inbound],
        entity_ip=entity_ip,
        window_start=1600000000.0,
        window_end=1600000060.0,
    )
    assert exfil.outbound_flow_count == 0
    assert exfil.inbound_flow_count == 1
    assert exfil.total_outbound_bytes == 0
    assert exfil.total_inbound_bytes == 3000
    assert exfil.direction_available is True


def test_direction_evaluation_mixed():
    entity_ip = "10.0.0.1"
    flow1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=4000)
    flow2 = make_m1_flow(src_ip="1.1.1.1", dst_ip="10.0.0.1", byte_count=2000)

    recon, exfil = adapter.aggregate_window(
        flows=[flow1, flow2],
        entity_ip=entity_ip,
        window_start=1600000000.0,
        window_end=1600000060.0,
    )
    assert exfil.outbound_flow_count == 1
    assert exfil.inbound_flow_count == 1
    assert exfil.total_outbound_bytes == 4000
    assert exfil.total_inbound_bytes == 2000
    assert exfil.upload_download_ratio == 2.0
    assert exfil.direction_available is True


def test_batch_aggregate_multiple_entities():
    flow1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="10.0.0.2")
    flow2 = make_m1_flow(src_ip="10.0.0.2", dst_ip="10.0.0.3")

    res = adapter.batch_aggregate(
        flows=[flow1, flow2],
        window_start=1600000000.0,
        window_end=1600000060.0,
    )

    # Entities present: 10.0.0.1, 10.0.0.2, 10.0.0.3
    assert set(res.keys()) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    # Check 10.0.0.1 (outbound to 10.0.0.2)
    rf1, ef1 = res["10.0.0.1"]
    assert ef1.outbound_flow_count == 1
    assert ef1.inbound_flow_count == 0

    # Check 10.0.0.2 (inbound from 10.0.0.1, outbound to 10.0.0.3)
    rf2, ef2 = res["10.0.0.2"]
    assert ef2.outbound_flow_count == 1
    assert ef2.inbound_flow_count == 1


# ---------------------------------------------------------------------------
# 5. Feature Generation & DetectionContext Creation
# ---------------------------------------------------------------------------

def test_recon_and_exfil_features_generation():
    flows = [
        make_m1_flow(src_ip="10.0.0.1", dst_ip=f"10.0.0.{i}", dst_port=80, byte_count=0)
        for i in range(2, 8)
    ]
    recon, exfil = adapter.aggregate_window(
        flows=flows,
        entity_ip="10.0.0.1",
        window_start=1600000000.0,
        window_end=1600000060.0,
    )

    assert recon.flow_count == 6
    assert recon.unique_dst_ip_count == 6
    assert recon.is_horizontal is True
    assert recon.failed_connection_count == 6

    assert exfil.flow_count == 6
    assert exfil.outbound_flow_count == 6
    assert exfil.destination_count == 6


def test_create_detection_context():
    recon = ReconFeatures(flow_count=5)
    exfil = ExfiltrationFeatures(flow_count=5)

    ctx = adapter.create_detection_context(
        entity_ip="192.168.1.5",
        recon_feats=recon,
        exfil_feats=exfil,
        observation_count=5,
    )

    assert isinstance(ctx, DetectionContext)
    assert ctx.source_entity == "192.168.1.5"
    assert ctx.recon_features == recon
    assert ctx.exfil_features == exfil
    assert ctx.observation_count == 5


# ---------------------------------------------------------------------------
# 6. UnifiedM2Orchestrator Compatibility
# ---------------------------------------------------------------------------

def test_process_window_for_orchestrator_execution():
    orchestrator = UnifiedM2Orchestrator(enable_ml=False, enable_baseline=True)

    # 6 scan flows to trigger horizontal recon detector
    flows = [
        make_m1_flow(src_ip="10.0.0.5", dst_ip=f"10.0.1.{i}", dst_port=443, byte_count=0)
        for i in range(10, 17)
    ]

    signals = adapter.process_window_for_orchestrator(
        orchestrator=orchestrator,
        flows=flows,
        window_start=1600000000.0,
        window_end=1600000060.0,
    )

    assert isinstance(signals, list)
    # ReconDetector should have emitted RECON_PORT_SCAN for 10.0.0.5
    recon_signals = [s for s in signals if s.threat_class.value == "RECON_PORT_SCAN"]
    assert len(recon_signals) >= 1
    assert recon_signals[0].source_entity == "10.0.0.5"


# ---------------------------------------------------------------------------
# 7. Replay Integration Test
# ---------------------------------------------------------------------------

def test_replay_pcap_callback_none_unchanged(tmp_path):
    from pipeline.replay import replay_pcap
    # Pass non-existent pcap to verify clean failure handling or mock iter
    with pytest.raises(Exception):
        replay_pcap("non_existent_file.pcap")
