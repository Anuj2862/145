"""M1 → M2 Entity/Window Context Adapter (PS 26145).

Bridging module that converts streaming M1 FlowEvent dataclasses into M2
window-level feature representations (ReconFeatures, ExfiltrationFeatures)
and constructs internal DetectionContext containers for UnifiedM2Orchestrator.

SAFETY & INTEGRATION CONSTRAINTS:
- Lossless M1 -> M2 translation: preserves duration, tcp_flags, timestamps, packet sizes, IATs.
- Explicit window boundaries (window_start, window_end) are authoritative.
- Rejects invalid/non-positive window durations.
- Evaluates exfiltration direction relative to entity_ip (src=outbound, dst=inbound).
- Evaluates detection strictly via UnifiedM2Orchestrator without premature signal fusion.
- No modifications to shared Pydantic schemas or ML 52-feature contract.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

from schemas.flow_event import FlowEvent as M1FlowEvent
from schemas import (
    FlowEvent as M2FlowEvent,
    TCPFlags,
    DetectionSignal,
    FeatureVector,
)
from features.recon_features import ReconFeatures, aggregate_recon_features
from features.exfil_features import ExfiltrationFeatures, aggregate_exfil_features
from detectors.engine import DetectionContext
from detectors.unified_detector import UnifiedM2Orchestrator


def _timestamp_iso(ts: float) -> str:
    """Format Unix epoch float timestamp into UTC ISO 8601 string."""
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def m1_to_m2_flow_event(m1_flow: M1FlowEvent) -> M2FlowEvent:
    """Perform genuinely lossless translation from M1 FlowEvent dataclass to M2 Pydantic FlowEvent.

    Preserves exact duration, timestamps, TCP flag counts, packet lengths, and IATs.
    """
    start_iso = _timestamp_iso(m1_flow.timestamp)
    end_iso = _timestamp_iso(m1_flow.timestamp + m1_flow.duration)

    tcp_flags = None
    if m1_flow.protocol == 6:  # TCP
        tcp_flags = TCPFlags(
            syn_count=m1_flow.syn_count,
            ack_count=m1_flow.ack_count,
            fin_count=m1_flow.fin_count,
            rst_count=m1_flow.rst_count,
            psh_count=m1_flow.psh_count,
            urg_count=m1_flow.urg_count,
        )

    return M2FlowEvent(
        flow_id=m1_flow.flow_id,
        src_ip=m1_flow.src_ip,
        dst_ip=m1_flow.dst_ip,
        src_port=m1_flow.src_port,
        dst_port=m1_flow.dst_port,
        protocol=m1_flow.protocol,
        start_time_iso=start_iso,
        end_time_iso=end_iso,
        duration_sec=m1_flow.duration,
        packet_count=m1_flow.packet_count,
        byte_count=m1_flow.byte_count,
        tcp_flags=tcp_flags,
        packet_lengths=list(m1_flow.packet_lengths) if m1_flow.packet_lengths else [],
        inter_arrival_times_ms=list(m1_flow.inter_arrival_times_ms) if m1_flow.inter_arrival_times_ms else [],
    )


def _to_epoch_seconds(ts: Union[float, int, datetime]) -> float:
    """Convert timestamp float/int/datetime into Unix epoch float seconds."""
    if isinstance(ts, datetime):
        return ts.timestamp()
    return float(ts)


def aggregate_window(
    flows: List[M1FlowEvent],
    entity_ip: str,
    window_start: Union[float, int, datetime],
    window_end: Union[float, int, datetime],
    min_flows_required: int = 3,
) -> Tuple[ReconFeatures, ExfiltrationFeatures]:
    """Aggregate a list of M1 FlowEvents into ReconFeatures and ExfiltrationFeatures for a single entity.

    Args:
        flows: List of M1 FlowEvents associated with entity_ip.
        entity_ip: The target or source entity IP being profiled.
        window_start: Start boundary of analysis window (epoch timestamp or datetime).
        window_end: End boundary of analysis window (epoch timestamp or datetime).
        min_flows_required: Minimum flows required for sufficient evidence.

    Returns:
        (ReconFeatures, ExfiltrationFeatures) for the given entity and window.

    Raises:
        ValueError: If window_duration_sec <= 0.
    """
    t_start = _to_epoch_seconds(window_start)
    t_end = _to_epoch_seconds(window_end)
    window_duration_sec = t_end - t_start

    if window_duration_sec <= 0:
        raise ValueError(
            f"Invalid window duration: {window_duration_sec}s. window_end must be greater than window_start."
        )

    # Translate M1 flows to M2 Pydantic representation
    m2_flows = [m1_to_m2_flow_event(f) for f in flows]

    # Run existing M2 baseline aggregation routines
    recon_feats = aggregate_recon_features(
        flows=m2_flows,
        window_duration_sec=window_duration_sec,
        min_flows_required=min_flows_required,
    )

    exfil_feats = aggregate_exfil_features(
        flows=m2_flows,
        entity_ip=entity_ip,
        window_duration_sec=window_duration_sec,
        min_flows_required=min_flows_required,
    )

    if not flows:
        exfil_feats.direction_available = False

    # Authoritative explicit window boundaries overwrite timestamp-derived window duration
    exfil_feats.window_duration_sec = window_duration_sec
    if window_duration_sec > 0 and exfil_feats.direction_available:
        exfil_feats.outbound_bytes_per_sec = (
            exfil_feats.total_outbound_bytes / window_duration_sec
        )

    return recon_feats, exfil_feats


def batch_aggregate(
    flows: List[M1FlowEvent],
    window_start: Union[float, int, datetime],
    window_end: Union[float, int, datetime],
    min_flows_required: int = 3,
) -> Dict[str, Tuple[ReconFeatures, ExfiltrationFeatures]]:
    """Group flows by entity IP and aggregate window-level features for each entity.

    An entity IP is any IP appearing as src_ip or dst_ip in the provided flows.
    Exfiltration direction is evaluated relative to each entity_ip:
    - src_ip == entity_ip -> outbound
    - dst_ip == entity_ip -> inbound
    - neither -> direction unavailable

    Returns:
        Mapping of {entity_ip: (ReconFeatures, ExfiltrationFeatures)}
    """
    if not flows:
        t_start = _to_epoch_seconds(window_start)
        t_end = _to_epoch_seconds(window_end)
        window_duration_sec = t_end - t_start
        if window_duration_sec <= 0:
            raise ValueError(
                f"Invalid window duration: {window_duration_sec}s. window_end must be greater than window_start."
            )
        return {}

    # Extract all distinct entity IPs present in flows
    entity_ips = set()
    for f in flows:
        entity_ips.add(f.src_ip)
        entity_ips.add(f.dst_ip)

    results: Dict[str, Tuple[ReconFeatures, ExfiltrationFeatures]] = {}
    for entity_ip in sorted(entity_ips):
        entity_flows = [
            f for f in flows if f.src_ip == entity_ip or f.dst_ip == entity_ip
        ]
        results[entity_ip] = aggregate_window(
            flows=entity_flows,
            entity_ip=entity_ip,
            window_start=window_start,
            window_end=window_end,
            min_flows_required=min_flows_required,
        )

    return results


def create_detection_context(
    entity_ip: str,
    recon_feats: ReconFeatures,
    exfil_feats: ExfiltrationFeatures,
    observation_count: int = 0,
    timestamp_iso: Optional[str] = None,
    feature_vector: Optional[FeatureVector] = None,
) -> DetectionContext:
    """Create engine-internal DetectionContext for UnifiedM2Orchestrator."""
    if timestamp_iso is None:
        timestamp_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return DetectionContext(
        source_entity=entity_ip,
        timestamp_iso=timestamp_iso,
        feature_vector=feature_vector,
        observation_count=observation_count,
        recon_features=recon_feats,
        exfil_features=exfil_feats,
    )


def process_window_for_orchestrator(
    orchestrator: UnifiedM2Orchestrator,
    flows: List[M1FlowEvent],
    window_start: Union[float, int, datetime],
    window_end: Union[float, int, datetime],
    timestamp_iso: Optional[str] = None,
) -> List[DetectionSignal]:
    """Process a window of M1 FlowEvents through the adapter and orchestrator.

    Generates DetectionContext for each entity in the window and evaluates
    them strictly via UnifiedM2Orchestrator.evaluate().
    """
    batch_res = batch_aggregate(flows, window_start, window_end)
    signals: List[DetectionSignal] = []

    for entity_ip, (recon_feats, exfil_feats) in batch_res.items():
        entity_flows = [
            f for f in flows if f.src_ip == entity_ip or f.dst_ip == entity_ip
        ]
        ctx = create_detection_context(
            entity_ip=entity_ip,
            recon_feats=recon_feats,
            exfil_feats=exfil_feats,
            observation_count=len(entity_flows),
            timestamp_iso=timestamp_iso,
        )
        entity_signals = orchestrator.evaluate(ctx)
        signals.extend(entity_signals)

    return signals
