"""Milestone 1 Verification Runner (Member 3).

Demonstrates the minimal working vertical slice:
    FlowEvent (Mock/Ingested)
        ↓
    Feature Extraction (Simulated/Member 2)
        ↓
    Volumetric DDoS Heuristic (Simulated/Member 2)
        ↓
    DetectionSignal
        ↓
    Alert Builder (Member 3)
        ↓
    Validated Alert JSON + CLI Output
"""

import sys
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from schemas import (
    FlowEvent,
    TCPFlags,
    FeatureVector,
    FlowFeatures,
    DetectionSignal,
    ThreatClass,
    DetectorType,
    Severity,
    Alert,
)
from incidents.alert_builder import build_alert_from_signal
from incidents.formatter import alert_to_json, format_alert_cli


def create_sample_ddos_flow() -> FlowEvent:
    """Fixture generating a high-velocity SYN flood flow event."""
    return FlowEvent(
        flow_id="198.51.100.42:49152-10.0.0.1:80-6",
        src_ip="198.51.100.42",
        dst_ip="10.0.0.1",
        src_port=49152,
        dst_port=80,
        protocol=6,
        start_time_iso=datetime.now(timezone.utc).isoformat(),
        end_time_iso=datetime.now(timezone.utc).isoformat(),
        duration_sec=5.0,
        packet_count=50000,
        byte_count=3200000,
        tcp_flags=TCPFlags(syn_count=49950, ack_count=50),
        packet_lengths=[64] * 10,
        inter_arrival_times_ms=[0.1] * 10,
    )


def simulate_member2_detector(flow: FlowEvent) -> Tuple[FeatureVector, DetectionSignal]:
    """Simulate Member 2 feature extraction and deterministic DDoS detection."""
    # 1. Feature extraction
    pps = flow.packet_count / max(flow.duration_sec, 0.001)
    bps = flow.byte_count / max(flow.duration_sec, 0.001)
    total_flags = (flow.tcp_flags.syn_count + flow.tcp_flags.ack_count) if flow.tcp_flags else 1
    syn_ratio = (flow.tcp_flags.syn_count / total_flags) if flow.tcp_flags else 0.0

    fv = FeatureVector(
        feature_id="fv-m1-demo-001",
        entity_ip=flow.src_ip,
        flow_id=flow.flow_id,
        window_size_sec=int(flow.duration_sec),
        timestamp_iso=flow.end_time_iso,
        flow_features=FlowFeatures(
            packets_per_sec=pps,
            bytes_per_sec=bps,
            syn_ratio=syn_ratio,
            fan_out_dest_count=1,
        ),
    )

    # 2. Deterministic DDoS heuristic baseline: pps > 1000 and syn_ratio > 0.9
    is_ddos = (pps > 1000.0) and (syn_ratio > 0.9)
    confidence = min(0.99, 0.70 + (syn_ratio * 0.25)) if is_ddos else 0.0
    severity = Severity.HIGH if pps < 20000 else Severity.CRITICAL

    signal = DetectionSignal(
        signal_id="sig-m1-ddos-001",
        threat_class=ThreatClass.VOLUMETRIC_DDOS,
        detector_type=DetectorType.DETERMINISTIC_BASELINE,
        confidence=confidence,
        severity=severity,
        source_entity=flow.src_ip,
        target_entity=flow.dst_ip,
        timestamp_iso=flow.end_time_iso,
        indicators={
            "packets_per_sec": pps,
            "bytes_per_sec": bps,
            "syn_ratio": syn_ratio,
            "total_packets": flow.packet_count,
        },
    )

    return fv, signal


def run_milestone1_verification() -> Tuple[Alert, str, str]:
    """Execute complete Milestone 1 Member 3 verification pipeline.

    Returns:
        Tuple of (Alert object, JSON string, CLI formatted text).
    """
    flow = create_sample_ddos_flow()
    _, signal = simulate_member2_detector(flow)
    
    # Member 3: Convert signal to standardized Alert
    alert = build_alert_from_signal(signal=signal, protocol=flow.protocol)
    
    # Member 3: Serialize to JSON
    json_output = alert_to_json(alert, indent=2)
    
    # Member 3: Format CLI display
    cli_output = format_alert_cli(alert=alert, indicators=signal.indicators)
    
    return alert, json_output, cli_output


if __name__ == "__main__":
    print("Executing Milestone 1 End-to-End Verification Pipeline...\n")
    alert_obj, alert_json, alert_cli = run_milestone1_verification()
    
    print(alert_cli)
    print("\n--- STANDARDIZED JSON SCHEMA OUTPUT ---")
    print(alert_json)
    print("\n[SUCCESS] Milestone 1 verification complete.")
