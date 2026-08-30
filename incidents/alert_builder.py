"""Alert Builder component for Member 3 (Milestone 1).

Responsible for converting raw DetectionSignal instances produced by threat
detectors into standardized, validated Alert objects conforming to schemas.Alert.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from schemas import (
    DetectionSignal,
    Alert,
    ThreatClass,
    Severity,
)


def _generate_alert_id(prefix: str = "ALT") -> str:
    """Generate a unique timestamped alert ID."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    short_uuid = uuid.uuid4().hex[:6]
    return f"{prefix}-{now_str}-{short_uuid}"


def _generate_alert_summary(signal: DetectionSignal) -> str:
    """Construct an interpretable human-readable summary from signal metadata."""
    threat_name = signal.threat_class.value.replace("_", " ").title()
    src = signal.source_entity
    dst = signal.target_entity or "external infrastructure"

    indicators = signal.indicators or {}
    evidence_snippets: List[str] = []

    if "packets_per_sec" in indicators:
        evidence_snippets.append(f"{indicators['packets_per_sec']:.1f} pps")
    if "syn_ratio" in indicators:
        evidence_snippets.append(f"SYN ratio {indicators['syn_ratio']:.2f}")
    if "periodicity_score" in indicators:
        evidence_snippets.append(f"periodicity {indicators['periodicity_score']:.2f}")
    if "jitter_pct" in indicators:
        evidence_snippets.append(f"jitter {indicators['jitter_pct']:.1f}%")
    if "entropy_mean" in indicators:
        evidence_snippets.append(f"DNS entropy {indicators['entropy_mean']:.2f}")

    if evidence_snippets:
        details = " (" + ", ".join(evidence_snippets) + ")"
    else:
        details = ""

    return f"{threat_name} activity detected from {src} toward {dst}{details}."


def build_alert_from_signal(
    signal: DetectionSignal,
    alert_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    protocol: Optional[int] = None,
    custom_summary: Optional[str] = None,
) -> Alert:
    """Convert a DetectionSignal into a validated Alert conforming to schemas.Alert.

    Args:
        signal: Validated DetectionSignal produced by detectors/ (Member 2).
        alert_id: Optional explicit alert identifier; auto-generated if None.
        incident_id: Optional linked incident ID if grouped by fusion/ (Member 3).
        protocol: Optional IP protocol integer (e.g. 6 for TCP, 17 for UDP).
        custom_summary: Optional override for human-readable alert summary.

    Returns:
        Validated Alert Pydantic model.

    Raises:
        ValueError: If signal is invalid or conversion fails validation.
    """
    if not isinstance(signal, DetectionSignal):
        raise TypeError(f"Expected DetectionSignal instance, got {type(signal).__name__}")

    generated_id = alert_id or _generate_alert_id()
    summary = custom_summary or _generate_alert_summary(signal)
    
    # Calculate evidence item count from indicators
    evidence_count = max(1, len(signal.indicators)) if signal.indicators else 1

    alert = Alert(
        alert_id=generated_id,
        incident_id=incident_id,
        timestamp_iso=signal.timestamp_iso,
        threat_class=signal.threat_class,
        severity=signal.severity,
        confidence=signal.confidence,
        source_ip=signal.source_entity,
        destination_ip=signal.target_entity,
        protocol=protocol,
        summary=summary,
        evidence_count=evidence_count,
    )
    return alert
