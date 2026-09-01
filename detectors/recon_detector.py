"""Deterministic Reconnaissance / Port-Scan Baseline Detector (Member 2 / M15).

Consumes window-level ReconFeatures or entity state and produces a DetectionSignal
supporting horizontal, vertical, broad, and slow reconnaissance scans.
A single flow cannot trigger high fan-out.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from schemas import (
    DetectionSignal,
    DetectorType,
    EvidenceItem,
    Severity,
    SignalProvenance,
    ThreatClass,
)
from features.recon_features import ReconFeatures

MIN_EVIDENCE_FLOWS = 3

IP_FAN_MIN = 3.0
IP_FAN_MAX = 30.0

PORT_FAN_MIN = 5.0
PORT_FAN_MAX = 100.0

RATE_MIN = 0.5      # connections/sec
RATE_MAX = 20.0

FAIL_RATIO_MIN = 0.3
FAIL_RATIO_MAX = 0.9

W_IP_FAN = 0.35
W_PORT_FAN = 0.35
W_RATE = 0.20
W_FAIL = 0.10


def _norm(value: float, min_val: float, max_val: float) -> float:
    """Normalize a raw value to [0.0, 1.0]."""
    if value <= min_val:
        return 0.0
    if value >= max_val:
        return 1.0
    return (value - min_val) / (max_val - min_val)


class ReconDetector:
    """Deterministic baseline detector for Reconnaissance / Port-Scan behaviour."""

    def __init__(self, detector_id: str = "ReconDetector", version: str = "1.0.0"):
        self.detector_id = detector_id
        self.detector_version = version

    def evaluate(
        self,
        rf: Union[ReconFeatures, Any],
        source_entity: str = "unknown",
        timestamp_iso: Optional[str] = None,
        entity_profile: Optional[Any] = None,
        emit_benign: bool = True,
    ) -> Optional[DetectionSignal]:
        """Evaluate ReconFeatures and entity window state for scanning patterns."""
        if timestamp_iso is None:
            timestamp_iso = datetime.now(timezone.utc).isoformat()

        # Handle duck typing for ReconFeatures or raw dict
        flow_count = getattr(rf, "flow_count", 0)
        unique_dst_ips = getattr(rf, "unique_dst_ip_count", 0)
        unique_dst_ports = getattr(rf, "unique_dst_port_count", 0)
        failed_count = getattr(rf, "failed_connection_count", 0)
        failed_ratio = getattr(rf, "failed_connection_ratio", 0.0)
        conn_rate = getattr(rf, "connection_rate_per_sec", 0.0)
        sufficient = getattr(rf, "sufficient_evidence", flow_count >= MIN_EVIDENCE_FLOWS)
        is_horiz = getattr(rf, "is_horizontal", unique_dst_ips >= 5)
        is_vert = getattr(rf, "is_vertical", unique_dst_ports >= 5)
        is_broad = getattr(rf, "is_broad", is_horiz and is_vert)

        indicators: Dict[str, Any] = {
            "flow_count": flow_count,
            "unique_dst_ip_count": unique_dst_ips,
            "unique_dst_port_count": unique_dst_ports,
            "failed_connection_count": failed_count,
            "failed_connection_ratio": failed_ratio,
            "connection_rate_per_sec": conn_rate,
            "sufficient_evidence": sufficient,
            "is_horizontal": is_horiz,
            "is_vertical": is_vert,
            "is_broad": is_broad,
        }

        if is_broad:
            scan_type = "BROAD"
        elif is_horiz:
            scan_type = "HORIZONTAL"
        elif is_vert:
            scan_type = "VERTICAL"
        else:
            scan_type = "NONE"
        indicators["scan_type"] = scan_type

        evidence_items: List[EvidenceItem] = []
        decision_reasons: List[str] = []

        # Single flow cannot trigger high fan-out
        if flow_count < MIN_EVIDENCE_FLOWS or not sufficient:
            indicators["reason"] = f"Insufficient flows ({flow_count} < {MIN_EVIDENCE_FLOWS})"
            if not emit_benign:
                return None
            return self._build_signal(
                rf, source_entity, 0.0, 0.1, Severity.INFO, indicators, evidence_items, decision_reasons, timestamp_iso
            )

        # Component scores
        c_ip = _norm(float(unique_dst_ips), IP_FAN_MIN, IP_FAN_MAX)
        c_port = _norm(float(unique_dst_ports), PORT_FAN_MIN, PORT_FAN_MAX)
        c_rate = _norm(float(conn_rate or 0.0), RATE_MIN, RATE_MAX)
        c_fail = _norm(float(failed_ratio or 0.0), FAIL_RATIO_MIN, FAIL_RATIO_MAX)

        indicators["comp_ip_fanout"] = c_ip
        indicators["comp_port_fanout"] = c_port
        indicators["comp_rate"] = c_rate
        indicators["comp_fail_ratio"] = c_fail

        if c_ip > 0.0:
            decision_reasons.append("horizontal_scan_fanout")
            decision_reasons.append("horizontal_destination_ip_sweep")
            evidence_items.append(
                EvidenceItem(
                    feature_name="unique_dst_ip_count",
                    value=unique_dst_ips,
                    baseline=1,
                    deviation=unique_dst_ips - 1,
                    interpretation=f"Horizontal scan sweep across {unique_dst_ips} unique destination IPs",
                )
            )

        if c_port > 0.0:
            decision_reasons.append("vertical_port_scan_fanout")
            decision_reasons.append("vertical_port_scan_sweep")
            evidence_items.append(
                EvidenceItem(
                    feature_name="unique_dst_port_count",
                    value=unique_dst_ports,
                    baseline=1,
                    deviation=unique_dst_ports - 1,
                    interpretation=f"Vertical port scan across {unique_dst_ports} unique destination ports",
                )
            )

        if failed_ratio and failed_ratio >= FAIL_RATIO_MIN:
            decision_reasons.append("high_failed_connection_ratio")
            evidence_items.append(
                EvidenceItem(
                    feature_name="failed_connection_ratio",
                    value=round(failed_ratio, 2),
                    baseline=0.05,
                    deviation=round(failed_ratio / 0.05, 1),
                    interpretation=f"High connection failure ratio ({failed_ratio*100:.1f}%) confirms non-responsive scan probes",
                )
            )

        score = (c_ip * W_IP_FAN) + (c_port * W_PORT_FAN) + (c_rate * W_RATE) + (c_fail * W_FAIL)
        score = min(score, 1.0)
        indicators["recon_suspicion_score"] = score

        evidence_factor = min(flow_count / max(MIN_EVIDENCE_FLOWS, 1), 1.0)
        confidence = score * evidence_factor * 0.90
        confidence = min(confidence, 1.0)

        if confidence >= 0.7:
            severity = Severity.HIGH
        elif confidence >= 0.4:
            severity = Severity.MEDIUM
        elif confidence >= 0.1:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        if confidence <= 0.0 and not emit_benign:
            return None

        return self._build_signal(
            rf, source_entity, score, confidence, severity, indicators, evidence_items, decision_reasons, timestamp_iso
        )

    def _build_signal(
        self,
        rf: Any,
        source_entity: str,
        score: float,
        confidence: float,
        severity: Severity,
        indicators: dict,
        evidence_items: List[EvidenceItem],
        decision_reasons: List[str],
        timestamp_iso: str,
    ) -> DetectionSignal:
        signal_id = f"sig-rec-{uuid.uuid4().hex[:8]}"
        now_ts = datetime.now(timezone.utc).isoformat()

        observable_features = {
            "unique_dst_ip_count": indicators.get("unique_dst_ip_count", 0),
            "unique_dst_port_count": indicators.get("unique_dst_port_count", 0),
            "failed_connection_ratio": indicators.get("failed_connection_ratio", 0.0),
            "connection_rate_per_sec": indicators.get("connection_rate_per_sec", 0.0),
            "scan_type": indicators.get("scan_type", "NONE"),
        }

        prov = SignalProvenance(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            decision_reason=decision_reasons,
            observable_features=observable_features,
            window_start_iso=timestamp_iso,
            window_end_iso=now_ts,
        )

        return DetectionSignal(
            signal_id=signal_id,
            threat_class=ThreatClass.RECON_PORT_SCAN,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            score=score,
            severity=severity,
            source_entity=source_entity,
            entity_id=source_entity,
            timestamp_iso=now_ts,
            evidence=evidence_items,
            indicators=indicators,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            decision_reason=decision_reasons,
            observable_features=observable_features,
            provenance=prov,
        )
