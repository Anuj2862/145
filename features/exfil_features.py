"""
Window-level Data Exfiltration Feature Aggregation Module.

DIRECTION HANDLING:
    FlowEvent does NOT contain an explicit direction field.
    For this module, the caller must designate the 'entity IP' being profiled.
    - If a flow's src_ip matches the entity_ip → treated as OUTBOUND.
    - If a flow's dst_ip matches the entity_ip → treated as INBOUND.
    - If neither matches (possible in some aggregation contexts), the flow is
      counted toward totals but excluded from directional breakdowns.
    This is a documented architectural assumption, not ground truth.

WINDOW DURATION:
    Derived from min(start_time_iso) and max(end_time_iso) across all flows.
    If timestamps cannot be parsed or produce a non-positive duration, the
    configurable fallback window_duration_sec parameter is used.

LARGE TRANSFER THRESHOLD:
    Default: 1,000,000 bytes (1 MB) per flow.
    This is a temporary development baseline. It will be calibrated against
    representative traffic profiles during the evaluation milestone.

FALSE-POSITIVE DISCLAIMER:
    High outbound volume is produced legitimately by:
    - Cloud backup (OneDrive, iCloud, Google Drive, S3, etc.)
    - File synchronisation services
    - Video / content uploads
    - Software update servers
    - CI/CD build artefact pushes
    - Legitimate bulk data processing pipelines
    The detector produces a SUSPICION SIGNAL, not a verdict.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timezone
from schemas import FlowEvent


@dataclass
class ExfiltrationFeatures:
    """
    Window-level exfiltration behavioural indicators derived from a batch
    of FlowEvents belonging to one entity in one analysis window.
    """
    flow_count: int = 0
    outbound_flow_count: int = 0
    inbound_flow_count: int = 0
    total_outbound_bytes: int = 0
    total_inbound_bytes: int = 0
    outbound_bytes_ratio: Optional[float] = None   # outbound / total bytes
    upload_download_ratio: Optional[float] = None  # outbound / inbound bytes
    outbound_bytes_per_sec: Optional[float] = None
    maximum_single_flow_bytes: int = 0
    large_transfer_count: int = 0
    destination_count: int = 0
    # Window info
    window_duration_sec: float = 0.0
    window_derived_from_timestamps: bool = False
    # Evidence quality
    sufficient_evidence: bool = False
    direction_available: bool = True  # False if entity_ip had no matches


def _parse_iso(ts: str) -> Optional[datetime]:
    """Parse ISO 8601 string; return None on any error."""
    try:
        # Python 3.11+ handles Z suffix natively
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def aggregate_exfil_features(
    flows: List[FlowEvent],
    entity_ip: str,
    window_duration_sec: float = 60.0,
    min_flows_required: int = 3,
    large_transfer_bytes: int = 1_000_000,  # 1 MB — development threshold
) -> ExfiltrationFeatures:
    """
    Aggregate a list of FlowEvents into ExfiltrationFeatures for a single entity.

    Args:
        flows:               FlowEvents from one entity in one analysis window.
        entity_ip:           The IP being profiled (used to determine direction).
        window_duration_sec: Fallback window duration if timestamps unavailable.
        min_flows_required:  Minimum flows needed for sufficient evidence.
        large_transfer_bytes: Per-flow byte threshold for "large transfer" label.

    Returns:
        ExfiltrationFeatures with all derivable indicators populated.
    """
    ef = ExfiltrationFeatures()

    if not flows:
        return ef

    ef.flow_count = len(flows)

    # --- Direction-aware byte accumulation ---
    total_bytes = 0
    outbound_bytes = 0
    inbound_bytes = 0
    direction_matched = 0

    dst_ips = set()

    for evt in flows:
        b = evt.byte_count
        total_bytes += b

        if evt.src_ip == entity_ip:
            outbound_bytes += b
            ef.outbound_flow_count += 1
            direction_matched += 1
            dst_ips.add(evt.dst_ip)
        elif evt.dst_ip == entity_ip:
            inbound_bytes += b
            ef.inbound_flow_count += 1
            direction_matched += 1
        # else: neither side is entity_ip — counted in totals only

        if b > ef.maximum_single_flow_bytes:
            ef.maximum_single_flow_bytes = b
        if b >= large_transfer_bytes:
            ef.large_transfer_count += 1

    ef.total_outbound_bytes = outbound_bytes
    ef.total_inbound_bytes = inbound_bytes
    ef.destination_count = len(dst_ips)

    ef.direction_available = direction_matched > 0

    # Ratios — only compute when valid totals are available
    if total_bytes > 0:
        ef.outbound_bytes_ratio = outbound_bytes / float(total_bytes)

    if inbound_bytes > 0:
        ef.upload_download_ratio = outbound_bytes / float(inbound_bytes)
    else:
        ef.upload_download_ratio = None  # denominator is 0 — unavailable

    # --- Window duration from timestamps ---
    starts = [_parse_iso(f.start_time_iso) for f in flows]
    ends   = [_parse_iso(f.end_time_iso)   for f in flows]
    valid_starts = [t for t in starts if t is not None]
    valid_ends   = [t for t in ends   if t is not None]

    if valid_starts and valid_ends:
        obs_window = (max(valid_ends) - min(valid_starts)).total_seconds()
        if obs_window > 0:
            ef.window_duration_sec = obs_window
            ef.window_derived_from_timestamps = True

    if not ef.window_derived_from_timestamps:
        ef.window_duration_sec = window_duration_sec  # configured fallback

    # Outbound bytes per second
    if ef.window_duration_sec > 0 and ef.direction_available:
        ef.outbound_bytes_per_sec = ef.total_outbound_bytes / ef.window_duration_sec

    ef.sufficient_evidence = ef.flow_count >= min_flows_required

    return ef
