"""
Window-level Reconnaissance Feature Aggregation Module.

This module aggregates multiple FlowEvent records belonging to the SAME source
entity and analysis window into ReconFeatures — a dedicated internal structure
that captures scanning behaviour indicators.

DESIGN DECISION:
    Single-flow features (FlowFeatures) capture per-flow velocity metrics.
    Window/entity features (ReconFeatures) capture cross-flow aggregation.
    These are intentionally kept separate; ReconFeatures is NOT pushed into the
    shared FlowFeatures or FeatureVector schemas because those are single-flow.

HEURISTICS DOCUMENTED:
    Zero-byte / SYN-only connections are used as a proxy for failed connection
    attempts (e.g., RST-closed ports). This is a documented heuristic, NOT
    ground-truth connection success/failure, since FlowEvent does not carry an
    explicit success flag.
"""

from dataclasses import dataclass, field
from typing import List, Set, Optional
from schemas import FlowEvent


@dataclass
class ReconFeatures:
    """
    Window-level aggregated reconnaissance indicators derived from a batch
    of FlowEvents belonging to one source entity in one analysis window.
    """
    flow_count: int = 0
    unique_dst_ip_count: int = 0
    unique_dst_port_count: int = 0
    unique_dst_ips: Set[str] = field(default_factory=set)
    unique_dst_ports: Set[int] = field(default_factory=set)
    # Scan type labels (set during aggregation for detector use)
    is_horizontal: bool = False   # many IPs, few ports
    is_vertical: bool = False     # many ports, few IPs
    is_broad: bool = False        # many IPs AND many ports
    # Connection attempt proxy (heuristic: SYN-only or zero-byte flows)
    failed_connection_count: int = 0
    failed_connection_ratio: Optional[float] = None
    # Rate
    window_duration_sec: float = 0.0
    connection_rate_per_sec: Optional[float] = None
    # Evidence sufficiency
    sufficient_evidence: bool = False


def _is_likely_failed(event: FlowEvent) -> bool:
    """
    HEURISTIC: A flow is considered a likely failed connection attempt if:
    - byte_count == 0 (no data transferred), OR
    - tcp_flags are present and rst_count > 0 with no data (RST received)

    This is a proxy, NOT ground truth. Documented per task requirement.
    """
    if event.byte_count == 0:
        return True
    if event.tcp_flags and event.tcp_flags.rst_count > 0 and event.byte_count < 64:
        return True
    return False


def aggregate_recon_features(
    flows: List[FlowEvent],
    window_duration_sec: float = 60.0,
    min_flows_required: int = 3,
    horizontal_ip_threshold: int = 5,
    vertical_port_threshold: int = 5,
) -> ReconFeatures:
    """
    Aggregate a list of FlowEvents into ReconFeatures for a single entity window.

    Args:
        flows: FlowEvents from a single source entity in one analysis window.
        window_duration_sec: Duration of the analysis window in seconds.
        min_flows_required: Minimum flows required for sufficient evidence.
        horizontal_ip_threshold: Min unique dst IPs to classify horizontal scan.
        vertical_port_threshold: Min unique dst ports to classify vertical scan.

    Returns:
        ReconFeatures populated with window-level aggregated indicators.
    """
    rf = ReconFeatures()
    rf.window_duration_sec = window_duration_sec

    if not flows:
        return rf

    rf.flow_count = len(flows)

    dst_ips: Set[str] = set()
    dst_ports: Set[int] = set()
    failed = 0

    for evt in flows:
        dst_ips.add(evt.dst_ip)
        dst_ports.add(evt.dst_port)
        if _is_likely_failed(evt):
            failed += 1

    rf.unique_dst_ips = dst_ips
    rf.unique_dst_ip_count = len(dst_ips)
    rf.unique_dst_ports = dst_ports
    rf.unique_dst_port_count = len(dst_ports)
    rf.failed_connection_count = failed
    rf.failed_connection_ratio = failed / float(rf.flow_count) if rf.flow_count > 0 else None

    # Connection rate
    if window_duration_sec > 0:
        rf.connection_rate_per_sec = rf.flow_count / window_duration_sec

    # Scan classification (non-exclusive)
    h_scan = rf.unique_dst_ip_count >= horizontal_ip_threshold
    v_scan = rf.unique_dst_port_count >= vertical_port_threshold

    if h_scan and v_scan:
        rf.is_broad = True
    elif h_scan:
        rf.is_horizontal = True
    elif v_scan:
        rf.is_vertical = True

    rf.sufficient_evidence = rf.flow_count >= min_flows_required

    return rf
