"""
Deterministic Reconnaissance / Port-Scan Baseline Detector.

Consumes window-level ReconFeatures and produces a DetectionSignal.

COMPONENT WEIGHTS (development baselines — subject to calibration):
    Horizontal fan-out  (unique dst IPs):    0.35
    Vertical fan-out    (unique dst ports):  0.35
    Connection rate:                         0.20
    Failed connection ratio:                 0.10

NORMALIZATION THRESHOLDS (temporary baselines):
    IP fan-out:     [3 suspicious] → [30 critical]
    Port fan-out:   [5 suspicious] → [100 critical]
    Rate (conn/s):  [0.5 suspicious] → [20 critical]
    Fail ratio:     [0.3 suspicious] → [0.9 critical]

CONFIDENCE LOGIC:
    Base confidence = score × evidence_factor × 0.90
    evidence_factor = min(flow_count / MIN_EVIDENCE_FLOWS, 1.0)
    Missing evidence hard-caps max confidence at 0.30.
"""

import uuid
from datetime import datetime, timezone
from schemas import DetectionSignal, ThreatClass, DetectorType, Severity
from features.recon_features import ReconFeatures

# Minimum flows before a meaningful signal can fire
MIN_EVIDENCE_FLOWS = 3

# --- Normalization thresholds (development baselines) ---
IP_FAN_MIN = 3.0
IP_FAN_MAX = 30.0

PORT_FAN_MIN = 5.0
PORT_FAN_MAX = 100.0

RATE_MIN = 0.5      # connections/sec
RATE_MAX = 20.0

FAIL_RATIO_MIN = 0.3
FAIL_RATIO_MAX = 0.9

# --- Component weights ---
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
    """
    Deterministic baseline detector for Reconnaissance / Port-Scan behaviour.

    Consumes: ReconFeatures (window-level aggregation)
    Produces: DetectionSignal
    """

    def evaluate(
        self,
        rf: ReconFeatures,
        source_entity: str,
        timestamp_iso: str = None,
    ) -> DetectionSignal:
        if timestamp_iso is None:
            timestamp_iso = datetime.now(timezone.utc).isoformat()

        indicators: dict = {
            "flow_count": rf.flow_count,
            "unique_dst_ip_count": rf.unique_dst_ip_count,
            "unique_dst_port_count": rf.unique_dst_port_count,
            "failed_connection_count": rf.failed_connection_count,
            "failed_connection_ratio": rf.failed_connection_ratio,
            "connection_rate_per_sec": rf.connection_rate_per_sec,
            "window_duration_sec": rf.window_duration_sec,
            "sufficient_evidence": rf.sufficient_evidence,
            "is_horizontal": rf.is_horizontal,
            "is_vertical": rf.is_vertical,
            "is_broad": rf.is_broad,
        }

        # Derive scan type label
        if rf.is_broad:
            scan_type = "BROAD"
        elif rf.is_horizontal:
            scan_type = "HORIZONTAL"
        elif rf.is_vertical:
            scan_type = "VERTICAL"
        else:
            scan_type = "NONE"
        indicators["scan_type"] = scan_type

        # Insufficient evidence → low score + penalised confidence
        if not rf.sufficient_evidence:
            indicators["reason"] = f"Insufficient flows ({rf.flow_count} < {MIN_EVIDENCE_FLOWS})"
            return self._build_signal(
                rf, source_entity, 0.0, 0.1, Severity.INFO, indicators, timestamp_iso
            )

        # --- Component scores ---
        c_ip = _norm(float(rf.unique_dst_ip_count), IP_FAN_MIN, IP_FAN_MAX)
        c_port = _norm(float(rf.unique_dst_port_count), PORT_FAN_MIN, PORT_FAN_MAX)
        c_rate = _norm(rf.connection_rate_per_sec or 0.0, RATE_MIN, RATE_MAX)
        c_fail = _norm(rf.failed_connection_ratio or 0.0, FAIL_RATIO_MIN, FAIL_RATIO_MAX)

        indicators["comp_ip_fanout"] = c_ip
        indicators["comp_port_fanout"] = c_port
        indicators["comp_rate"] = c_rate
        indicators["comp_fail_ratio"] = c_fail

        # Weighted sum → score in [0,1]
        score = (c_ip * W_IP_FAN) + (c_port * W_PORT_FAN) + (c_rate * W_RATE) + (c_fail * W_FAIL)
        score = min(score, 1.0)
        indicators["recon_suspicion_score"] = score

        # --- Confidence ---
        # Scales with both score strength and how much evidence we have.
        evidence_factor = min(rf.flow_count / max(MIN_EVIDENCE_FLOWS, 1), 1.0)
        confidence = score * evidence_factor * 0.90
        confidence = min(confidence, 1.0)

        # --- Severity ---
        if confidence >= 0.7:
            severity = Severity.HIGH
        elif confidence >= 0.4:
            severity = Severity.MEDIUM
        elif confidence >= 0.1:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        return self._build_signal(
            rf, source_entity, score, confidence, severity, indicators, timestamp_iso
        )

    def _build_signal(
        self,
        rf: ReconFeatures,
        source_entity: str,
        score: float,
        confidence: float,
        severity: Severity,
        indicators: dict,
        timestamp_iso: str,
    ) -> DetectionSignal:
        if "recon_suspicion_score" not in indicators:
            indicators["recon_suspicion_score"] = score

        decision_reasons = []
        if rf.unique_dst_port_count >= PORT_FAN_MIN:
            decision_reasons.append("vertical_port_scan_fanout")
        if rf.unique_dst_ip_count >= IP_FAN_MIN:
            decision_reasons.append("horizontal_host_sweep_fanout")
        if rf.connection_rate_per_sec and rf.connection_rate_per_sec >= RATE_MIN:
            decision_reasons.append("elevated_connection_attempt_rate")
        if rf.failed_connection_ratio and rf.failed_connection_ratio >= FAIL_RATIO_MIN:
            decision_reasons.append("high_failed_connection_ratio")

        observable_features = {
            "unique_dst_ip_count": rf.unique_dst_ip_count,
            "unique_dst_port_count": rf.unique_dst_port_count,
            "connection_rate_per_sec": rf.connection_rate_per_sec,
            "failed_connection_ratio": rf.failed_connection_ratio,
            "flow_count": rf.flow_count,
        }

        from schemas import SignalProvenance
        prov = SignalProvenance(
            detector_id="ReconDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            window_start_iso=timestamp_iso,
            window_end_iso=timestamp_iso,
        )

        return DetectionSignal(
            signal_id=f"sig-recon-{uuid.uuid4().hex[:8]}",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            severity=severity,
            source_entity=source_entity,
            target_entity=None,
            timestamp_iso=timestamp_iso,
            indicators=indicators,
            detector_id="ReconDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            provenance=prov,
        )
