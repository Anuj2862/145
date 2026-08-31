"""Unit & Integration Tests for EntityContextManager (features/entity_context.py).

Verifies stateful multi-window entity retention, reference counting, direction isolation, out-of-order timestamps,
sliding expiration, LRU/TTL capacity bounds, and signal adapter backward compatibility.
"""

from datetime import datetime, timezone
import pytest

from schemas.flow_event import FlowEvent as M1FlowEvent
from features.entity_context import EntityContextManager, EntityState, EntityFlowRecord
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
# 1. Entity Creation & Isolation Tests
# ---------------------------------------------------------------------------

def test_new_entity_creation_src_and_dst():
    mgr = EntityContextManager()
    flow = make_m1_flow(src_ip="10.0.0.1", dst_ip="10.0.0.2")
    mgr.update([flow])

    assert "10.0.0.1" in mgr.entities
    assert "10.0.0.2" in mgr.entities
    assert mgr.entities["10.0.0.1"].outbound_flow_count == 1
    assert mgr.entities["10.0.0.2"].inbound_flow_count == 1


def test_multiple_entity_isolation():
    mgr = EntityContextManager()
    flow1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=1000)
    flow2 = make_m1_flow(src_ip="10.0.0.2", dst_ip="1.1.1.1", byte_count=5000)
    mgr.update([flow1, flow2])

    assert mgr.entities["10.0.0.1"].total_outbound_bytes == 1000
    assert mgr.entities["10.0.0.2"].total_outbound_bytes == 5000


# ---------------------------------------------------------------------------
# 2. Direction & Reference Counting Tests
# ---------------------------------------------------------------------------

def test_outbound_recon_cardinality_excludes_inbound_flows():
    mgr = EntityContextManager()
    # Flow 1: Outbound from 10.0.0.1 to 8.8.8.8:80
    f1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80)
    # Flow 2: Inbound to 10.0.0.1 from 1.1.1.1:443
    f2 = make_m1_flow(src_ip="1.1.1.1", dst_ip="10.0.0.1", dst_port=443)

    mgr.update([f1, f2])

    rf = mgr.get_recon_features("10.0.0.1")
    # Recon cardinality for 10.0.0.1 should only count outbound target 8.8.8.8:80
    assert rf.unique_dst_ip_count == 1
    assert "8.8.8.8" in rf.unique_dst_ips
    assert "1.1.1.1" not in rf.unique_dst_ips


def test_destination_ip_and_port_reference_counting():
    mgr = EntityContextManager(retention_window_sec=60.0)
    f1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80, timestamp=100.0)
    f2 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80, timestamp=120.0)
    mgr.update([f1, f2])

    state = mgr.entities["10.0.0.1"]
    assert state.dst_ips["8.8.8.8"] == 2
    assert state.dst_ports[80] == 2

    # Expire f1 at timestamp 170.0 (cutoff = 110.0)
    mgr.update([make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", timestamp=170.0)])
    # f1 is expired, f2 remains active, f3 is added
    assert "8.8.8.8" in state.dst_ips


# ---------------------------------------------------------------------------
# 3. Expiration Tests
# ---------------------------------------------------------------------------

def test_rolling_expiration_prunes_old_flows():
    mgr = EntityContextManager(retention_window_sec=50.0)
    f1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", timestamp=100.0)
    mgr.update([f1])
    assert mgr.entities["10.0.0.1"].outbound_flow_count == 1

    # Advance time to 160.0 (cutoff = 110.0, f1 expires)
    f2 = make_m1_flow(src_ip="10.0.0.1", dst_ip="1.1.1.1", timestamp=160.0)
    mgr.update([f2])

    state = mgr.entities["10.0.0.1"]
    assert state.outbound_flow_count == 1
    assert "8.8.8.8" not in state.dst_ips
    assert "1.1.1.1" in state.dst_ips


def test_failed_connection_counter_expiration():
    mgr = EntityContextManager(retention_window_sec=50.0)
    failed_flow = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=0, timestamp=100.0)
    mgr.update([failed_flow])
    assert mgr.entities["10.0.0.1"].failed_connection_count == 1

    # Advance time to expire failed_flow
    mgr.update([make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=1000, timestamp=160.0)])
    assert mgr.entities["10.0.0.1"].failed_connection_count == 0


def test_byte_counter_expiration():
    mgr = EntityContextManager(retention_window_sec=50.0)
    f1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=5000, timestamp=100.0)
    mgr.update([f1])
    assert mgr.entities["10.0.0.1"].total_outbound_bytes == 5000

    # Expire f1
    mgr.update([make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=1000, timestamp=160.0)])
    assert mgr.entities["10.0.0.1"].total_outbound_bytes == 1000


def test_maximum_single_flow_bytes_recalculation_on_eviction():
    mgr = EntityContextManager(retention_window_sec=50.0)
    large_flow = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=100_000, timestamp=100.0)
    small_flow = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=2_000, timestamp=120.0)
    mgr.update([large_flow, small_flow])

    assert mgr.entities["10.0.0.1"].maximum_single_flow_bytes == 100_000

    # Advance time to 160.0 (large_flow expires)
    mgr.update([make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=500, timestamp=160.0)])
    assert mgr.entities["10.0.0.1"].maximum_single_flow_bytes == 2_000


def test_large_transfer_count_expiration():
    mgr = EntityContextManager(retention_window_sec=50.0, large_transfer_bytes=500_000)
    f_large = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=1_000_000, timestamp=100.0)
    mgr.update([f_large])
    assert mgr.entities["10.0.0.1"].large_transfer_count == 1

    # Expire f_large
    mgr.update([make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", byte_count=100, timestamp=160.0)])
    assert mgr.entities["10.0.0.1"].large_transfer_count == 0


# ---------------------------------------------------------------------------
# 4. Out-of-Order & Capacity Bounds Tests
# ---------------------------------------------------------------------------

def test_timestamp_out_of_order_insertion_handling():
    mgr = EntityContextManager()
    f1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", timestamp=100.0)
    f3 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", timestamp=300.0)
    f2 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", timestamp=200.0)  # Arrives out-of-order

    mgr.update([f1, f3, f2])
    timestamps = list(mgr.entities["10.0.0.1"].flow_timestamps)
    assert timestamps == [100.0, 200.0, 300.0]


def test_idle_entity_ttl_cleanup():
    mgr = EntityContextManager(retention_window_sec=50.0, entity_ttl_sec=100.0)
    f1 = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", timestamp=100.0)
    mgr.update([f1])
    assert "10.0.0.1" in mgr.entities

    # Advance time beyond TTL (timestamp = 250.0 > 100.0 + 100.0)
    f2 = make_m1_flow(src_ip="10.0.0.2", dst_ip="8.8.8.8", timestamp=250.0)
    mgr.update([f2])

    assert "10.0.0.1" not in mgr.entities
    assert "10.0.0.2" in mgr.entities


def test_lru_capacity_eviction_when_max_entities_reached():
    mgr = EntityContextManager(max_active_entities=2)
    mgr.update([make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", timestamp=100.0)])
    mgr.update([make_m1_flow(src_ip="10.0.0.2", dst_ip="8.8.8.8", timestamp=101.0)])
    mgr.update([make_m1_flow(src_ip="10.0.0.3", dst_ip="8.8.8.8", timestamp=102.0)])

    # Capacity is 2 -> oldest entities evicted
    assert len(mgr.entities) <= 2
    assert "10.0.0.3" in mgr.entities


# ---------------------------------------------------------------------------
# 5. Multi-Window Synthetic Scenarios
# ---------------------------------------------------------------------------

def test_low_and_slow_recon_across_multiple_synthetic_windows():
    mgr = EntityContextManager(retention_window_sec=600.0)
    src_ip = "10.0.0.99"

    # Simulate 6 consecutive windows, contacting 1 unique IP per window
    for w in range(6):
        flow = make_m1_flow(
            src_ip=src_ip,
            dst_ip=f"10.0.1.{w+1}",
            dst_port=80,
            byte_count=0,
            timestamp=1000.0 + (w * 30.0),
        )
        mgr.update([flow])

    rf = mgr.get_recon_features(src_ip, window_duration_sec=600.0)
    assert rf.unique_dst_ip_count == 6
    assert rf.is_horizontal is True


def test_trickle_exfiltration_across_multiple_synthetic_windows():
    mgr = EntityContextManager(retention_window_sec=600.0)
    src_ip = "10.0.0.99"

    # 5 consecutive windows uploading 300KB each
    for w in range(5):
        flow = make_m1_flow(
            src_ip=src_ip,
            dst_ip="185.1.2.3",
            byte_count=300_000,
            timestamp=1000.0 + (w * 20.0),
        )
        mgr.update([flow])

    ef = mgr.get_exfil_features(src_ip, window_duration_sec=600.0)
    assert ef.total_outbound_bytes == 1_500_000
    assert ef.outbound_flow_count == 5


def test_periodic_beaconing_history_accumulation():
    mgr = EntityContextManager(retention_window_sec=600.0)
    src_ip = "10.0.0.99"

    # 6 flow events spaced exactly 30.0 seconds apart
    for i in range(6):
        flow = make_m1_flow(
            src_ip=src_ip,
            dst_ip="185.1.2.3",
            timestamp=1000.0 + (i * 30.0),
        )
        mgr.update([flow])

    tf = mgr.get_temporal_features(src_ip)
    assert tf.periodicity_score is not None
    assert tf.periodicity_score > 0.9  # Highly periodic
    assert tf.jitter_pct < 1.0


def test_insufficient_temporal_evidence_handling():
    mgr = EntityContextManager()
    src_ip = "10.0.0.99"

    # Only 3 flow events (< 5 required threshold)
    for i in range(3):
        flow = make_m1_flow(
            src_ip=src_ip,
            dst_ip="185.1.2.3",
            timestamp=1000.0 + (i * 30.0),
        )
        mgr.update([flow])

    tf = mgr.get_temporal_features(src_ip)
    assert tf.periodicity_score is None
    assert tf.jitter_pct is None


# ---------------------------------------------------------------------------
# 6. Backward Compatibility Test
# ---------------------------------------------------------------------------

def test_signal_adapter_backward_compatibility_when_manager_is_none():
    m1_flow = make_m1_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8")

    # Call batch_aggregate with entity_manager=None
    res = adapter.batch_aggregate(
        flows=[m1_flow],
        window_start=1600000000.0,
        window_end=1600000060.0,
        entity_manager=None,
    )

    assert "10.0.0.1" in res
    assert "8.8.8.8" in res
    rf, ef = res["10.0.0.1"]
    assert rf.flow_count == 1
    assert ef.outbound_flow_count == 1
