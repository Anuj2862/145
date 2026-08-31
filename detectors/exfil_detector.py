"""
Deterministic Data Exfiltration Baseline Detector.

Consumes ExfiltrationFeatures (window-level aggregation) and produces a
DetectionSignal using an interpretable weighted suspicion score.

SCORING FORMULA:
    score = (c_vol   × W_VOL)
          + (c_rate  × W_RATE)
          + (c_ratio × W_RATIO)
          + (c_large × W_LARGE)
    clipped to [0.0, 1.0]

COMPONENT WEIGHTS (development baselines — must be calibrated):
    Outbound volume      (c_vol):   0.35
    Outbound rate        (c_rate):  0.30
    Upload/DL imbalance  (c_ratio): 0.25
    Large-transfer freq  (c_large): 0.10

NORMALIZATION THRESHOLDS (temporary baselines):
    Outbound volume    : [10 MB suspicious] → [500 MB critical]
    Outbound rate      : [100 KB/s suspicious] → [10 MB/s critical]
    Upload/DL ratio    : [2× suspicious] → [50× critical]
    Large-transfer cnt : [1 suspicious] → [10 critical]

CONFIDENCE LOGIC:
    confidence = score × evidence_factor × feature_completeness × 0.90
    evidence_factor      = min(flow_count / MIN_EVIDENCE_FLOWS, 1.0)
    feature_completeness = fraction of the four components that had real data

FALSE-POSITIVE DISCLAIMER:
    Large outbound traffic is NORMAL for cloud backup, video upload, CDN
    seeding, CI/CD pushes, and similar workloads. This signal must be
    combined with contextual entity intelligence before acting on it.
"""

import uuid
from datetime import datetime, timezone
from schemas import DetectionSignal, ThreatClass, DetectorType, Severity
from features.exfil_features import ExfiltrationFeatures

# Minimum flow count before a meaningful signal
MIN_EVIDENCE_FLOWS = 3

# --- Normalization thresholds (development baselines) ---
VOL_MIN   = 10_000_000       # 10 MB
VOL_MAX   = 500_000_000      # 500 MB

RATE_MIN  = 100_000          # 100 KB/s
RATE_MAX  = 10_000_000       # 10 MB/s

RATIO_MIN = 2.0              # 2× upload vs download
RATIO_MAX = 50.0

LARGE_CNT_MIN = 1.0
LARGE_CNT_MAX = 10.0

# --- Component weights ---
W_VOL   = 0.35
W_RATE  = 0.30
W_RATIO = 0.25
W_LARGE = 0.10


def _norm(value: float, min_val: float, max_val: float) -> float:
    if value <= min_val:
        return 0.0
    if value >= max_val:
        return 1.0
    return (value - min_val) / (max_val - min_val)


class ExfiltrationDetector:
    """
    Deterministic baseline detector for suspicious data-exfiltration behaviour.

    Consumes: ExfiltrationFeatures (window-level)
    Produces: DetectionSignal (ThreatClass.DATA_EXFILTRATION)
    """

    def evaluate(
        self,
        ef: ExfiltrationFeatures,
        source_entity: str,
        timestamp_iso: str = None,
    ) -> DetectionSignal:
        if timestamp_iso is None:
            timestamp_iso = datetime.now(timezone.utc).isoformat()

        indicators: dict = {
            "flow_count": ef.flow_count,
            "total_outbound_bytes": ef.total_outbound_bytes,
            "total_inbound_bytes": ef.total_inbound_bytes,
            "outbound_bytes_ratio": ef.outbound_bytes_ratio,
            "upload_download_ratio": ef.upload_download_ratio,
            "outbound_bytes_per_sec": ef.outbound_bytes_per_sec,
            "maximum_single_flow_bytes": ef.maximum_single_flow_bytes,
            "large_transfer_count": ef.large_transfer_count,
            "destination_count": ef.destination_count,
            "window_duration_sec": ef.window_duration_sec,
            "window_derived_from_timestamps": ef.window_derived_from_timestamps,
            "direction_available": ef.direction_available,
            "sufficient_evidence": ef.sufficient_evidence,
        }

        # Insufficient evidence guard
        if not ef.sufficient_evidence:
            indicators["reason"] = (
                f"Insufficient flows ({ef.flow_count} < {MIN_EVIDENCE_FLOWS})"
            )
            return self._build_signal(
                ef, source_entity, 0.0, 0.0, Severity.INFO, indicators, timestamp_iso
            )

        # If no directional info, confidence is fundamentally limited
        if not ef.direction_available:
            indicators["reason"] = "Direction unavailable — entity_ip matched no flows"
            return self._build_signal(
                ef, source_entity, 0.0, 0.0, Severity.INFO, indicators, timestamp_iso
            )

        # --- Component scores ---
        components_available = 0
        weighted_sum = 0.0

        # 1. Outbound volume
        c_vol = _norm(float(ef.total_outbound_bytes), VOL_MIN, VOL_MAX)
        weighted_sum += c_vol * W_VOL
        components_available += 1
        indicators["comp_outbound_volume"] = c_vol

        # 2. Outbound rate
        if ef.outbound_bytes_per_sec is not None:
            c_rate = _norm(ef.outbound_bytes_per_sec, RATE_MIN, RATE_MAX)
            weighted_sum += c_rate * W_RATE
            components_available += 1
            indicators["comp_outbound_rate"] = c_rate
        else:
            indicators["comp_outbound_rate"] = None

        # 3. Upload/download imbalance
        if ef.upload_download_ratio is not None:
            c_ratio = _norm(ef.upload_download_ratio, RATIO_MIN, RATIO_MAX)
            weighted_sum += c_ratio * W_RATIO
            components_available += 1
            indicators["comp_ul_dl_ratio"] = c_ratio
        else:
            indicators["comp_ul_dl_ratio"] = None

        # 4. Large transfer frequency
        c_large = _norm(float(ef.large_transfer_count), LARGE_CNT_MIN, LARGE_CNT_MAX)
        weighted_sum += c_large * W_LARGE
        components_available += 1
        indicators["comp_large_transfer"] = c_large

        # Normalize by total possible weight to handle missing components
        total_possible_weight = W_VOL + W_RATE + W_RATIO + W_LARGE  # 1.0
        actual_weight = (
            W_VOL
            + (W_RATE  if ef.outbound_bytes_per_sec is not None else 0.0)
            + (W_RATIO if ef.upload_download_ratio  is not None else 0.0)
            + W_LARGE
        )
        if actual_weight > 0:
            score = weighted_sum / actual_weight
        else:
            score = 0.0
        score = min(score, 1.0)
        indicators["exfil_suspicion_score"] = score

        # --- Confidence ---
        evidence_factor = min(ef.flow_count / max(MIN_EVIDENCE_FLOWS, 1), 1.0)
        feature_completeness = actual_weight / total_possible_weight
        confidence = score * evidence_factor * feature_completeness * 0.90
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
            ef, source_entity, score, confidence, severity, indicators, timestamp_iso
        )

    def _build_signal(
        self,
        ef: ExfiltrationFeatures,
        source_entity: str,
        score: float,
        confidence: float,
        severity: Severity,
        indicators: dict,
        timestamp_iso: str,
    ) -> DetectionSignal:
        if "exfil_suspicion_score" not in indicators:
            indicators["exfil_suspicion_score"] = score

        decision_reasons = []
        if ef.total_outbound_bytes >= VOL_MIN:
            decision_reasons.append("high_outbound_byte_volume")
        if ef.upload_download_ratio and ef.upload_download_ratio >= RATIO_MIN:
            decision_reasons.append("high_upload_to_download_imbalance")
        if ef.outbound_bytes_per_sec and ef.outbound_bytes_per_sec >= RATE_MIN:
            decision_reasons.append("elevated_outbound_byte_rate")
        if ef.large_transfer_count >= LARGE_CNT_MIN:
            decision_reasons.append("large_transfer_frequency_observed")

        observable_features = {
            "total_outbound_bytes": ef.total_outbound_bytes,
            "total_inbound_bytes": ef.total_inbound_bytes,
            "upload_download_ratio": ef.upload_download_ratio,
            "outbound_bytes_per_sec": ef.outbound_bytes_per_sec,
            "maximum_single_flow_bytes": ef.maximum_single_flow_bytes,
            "destination_count": ef.destination_count,
        }

        from schemas import SignalProvenance
        prov = SignalProvenance(
            detector_id="ExfiltrationDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            window_start_iso=timestamp_iso,
            window_end_iso=timestamp_iso,
        )

        return DetectionSignal(
            signal_id=f"sig-exfil-{uuid.uuid4().hex[:8]}",
            threat_class=ThreatClass.DATA_EXFILTRATION,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            severity=severity,
            source_entity=source_entity,
            target_entity=None,
            timestamp_iso=timestamp_iso,
            indicators=indicators,
            detector_id="ExfiltrationDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            provenance=prov,
        )
