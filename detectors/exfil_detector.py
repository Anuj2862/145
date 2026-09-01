"""Deterministic Data Exfiltration Baseline Detector (Member 2 / M15).

Consumes ExfiltrationFeatures or entity state and produces a DetectionSignal.
Handles unidirectional flow cases where inbound_bytes == 0 explicitly and safely.
Differentiates legitimate uploads/backups from exfiltration using entity baseline z-scores and novelty.
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
from features.exfil_features import ExfiltrationFeatures

MIN_EVIDENCE_FLOWS = 3

VOL_MIN = 10_000_000       # 10 MB
VOL_MAX = 500_000_000      # 500 MB

RATE_MIN = 100_000          # 100 KB/s
RATE_MAX = 10_000_000       # 10 MB/s

RATIO_MIN = 2.0              # 2× upload vs download
RATIO_MAX = 50.0

LARGE_CNT_MIN = 1.0
LARGE_CNT_MAX = 10.0

W_VOL = 0.35
W_RATE = 0.30
W_RATIO = 0.25
W_LARGE = 0.10


def _norm(value: float, min_val: float, max_val: float) -> float:
    if value <= min_val:
        return 0.0
    if value >= max_val:
        return 1.0
    return (value - min_val) / (max_val - min_val)


class ExfiltrationDetector:
    """Deterministic baseline detector for suspicious data-exfiltration behaviour."""

    def __init__(self, detector_id: str = "ExfiltrationDetector", version: str = "1.0.0"):
        self.detector_id = detector_id
        self.detector_version = version

    def evaluate(
        self,
        ef: Union[ExfiltrationFeatures, Any],
        source_entity: str = "unknown",
        timestamp_iso: Optional[str] = None,
        entity_profile: Optional[Any] = None,
        emit_benign: bool = True,
    ) -> Optional[DetectionSignal]:
        """Evaluate ExfiltrationFeatures and directional entity context."""
        if timestamp_iso is None:
            timestamp_iso = datetime.now(timezone.utc).isoformat()

        flow_count = getattr(ef, "flow_count", 0)
        out_bytes = getattr(ef, "total_outbound_bytes", 0)
        in_bytes = getattr(ef, "total_inbound_bytes", 0)
        out_ratio = getattr(ef, "outbound_bytes_ratio", 0.0)
        up_dl_ratio = getattr(ef, "upload_download_ratio", None)
        out_rate = getattr(ef, "outbound_bytes_per_sec", None)
        max_flow_bytes = getattr(ef, "maximum_single_flow_bytes", 0)
        large_count = getattr(ef, "large_transfer_count", 0)
        dest_count = getattr(ef, "destination_count", 0)
        dir_avail = getattr(ef, "direction_available", True)
        sufficient = getattr(ef, "sufficient_evidence", flow_count >= MIN_EVIDENCE_FLOWS)

        indicators: Dict[str, Any] = {
            "flow_count": flow_count,
            "total_outbound_bytes": out_bytes,
            "total_inbound_bytes": in_bytes,
            "outbound_bytes_ratio": out_ratio,
            "upload_download_ratio": up_dl_ratio,
            "outbound_bytes_per_sec": out_rate,
            "maximum_single_flow_bytes": max_flow_bytes,
            "large_transfer_count": large_count,
            "destination_count": dest_count,
            "direction_available": dir_avail,
            "sufficient_evidence": sufficient,
        }

        evidence_items: List[EvidenceItem] = []
        decision_reasons: List[str] = []

        # Insufficient evidence guard
        if not sufficient or flow_count < MIN_EVIDENCE_FLOWS or not dir_avail:
            indicators["reason"] = f"Insufficient flows ({flow_count} < {MIN_EVIDENCE_FLOWS}) or missing directional data"
            if not emit_benign:
                return None
            return self._build_signal(
                ef, source_entity, 0.0, 0.0, Severity.INFO, indicators, evidence_items, decision_reasons, timestamp_iso
            )

        # 1. Outbound Volume Component
        c_vol = _norm(float(out_bytes), VOL_MIN, VOL_MAX)
        indicators["comp_outbound_volume"] = c_vol

        if c_vol > 0.0:
            decision_reasons.append("high_outbound_byte_volume")
            decision_reasons.append("massive_outbound_data_transfer")
            evidence_items.append(
                EvidenceItem(
                    feature_name="total_outbound_bytes",
                    value=out_bytes,
                    baseline=VOL_MIN,
                    deviation=round(out_bytes / VOL_MIN, 2),
                    interpretation=f"Large outbound transfer volume ({out_bytes / (1024*1024):.2f} MB)",
                )
            )

        # 2. Outbound Rate Component
        c_rate = 0.0
        if out_rate is not None:
            c_rate = _norm(float(out_rate), RATE_MIN, RATE_MAX)
            indicators["comp_outbound_rate"] = c_rate
            if c_rate > 0.0:
                decision_reasons.append("high_outbound_transfer_rate")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="outbound_bytes_per_sec",
                        value=round(out_rate, 2),
                        baseline=RATE_MIN,
                        deviation=round(out_rate / RATE_MIN, 2),
                        interpretation=f"High outbound transfer rate ({out_rate / 1024.0:.1f} KB/s)",
                    )
                )

        # 3. Upload / Download Ratio (Safe zero-inbound handling)
        c_ratio = 0.0
        if in_bytes == 0 and out_bytes > VOL_MIN:
            # Unidirectional upload burst with zero response traffic
            c_ratio = 0.8
            indicators["zero_inbound_traffic"] = True
            decision_reasons.append("high_upload_to_download_imbalance")
            decision_reasons.append("unidirectional_outbound_burst_zero_inbound")
            evidence_items.append(
                EvidenceItem(
                    feature_name="upload_download_ratio",
                    value="INF",
                    baseline=1.0,
                    deviation="INF",
                    interpretation=f"Pure unidirectional outbound transmission ({out_bytes / (1024*1024):.2f} MB) with 0 inbound bytes",
                )
            )
        elif up_dl_ratio is not None:
            c_ratio = _norm(float(up_dl_ratio), RATIO_MIN, RATIO_MAX)
            indicators["comp_upload_download_ratio"] = c_ratio
            if c_ratio > 0.0:
                decision_reasons.append("high_upload_to_download_imbalance")
                decision_reasons.append("upload_download_volume_imbalance")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="upload_download_ratio",
                        value=round(up_dl_ratio, 2),
                        baseline=1.0,
                        deviation=round(up_dl_ratio, 2),
                        interpretation=f"Severe upload-to-download volume imbalance ({up_dl_ratio:.1f}x upload ratio)",
                    )
                )

        # 4. Large Transfer Count Component
        c_large = _norm(float(large_count), LARGE_CNT_MIN, LARGE_CNT_MAX)
        indicators["comp_large_transfer_count"] = c_large
        indicators["comp_large_transfer"] = c_large

        score = (c_vol * W_VOL) + (c_rate * W_RATE) + (c_ratio * W_RATIO) + (c_large * W_LARGE)
        score = min(score, 1.0)
        indicators["exfil_suspicion_score"] = score

        # Adaptive Entity Baseline Check
        if entity_profile is not None and hasattr(entity_profile, "compute_outbound_rate_z"):
            z_score = entity_profile.compute_outbound_rate_z(out_rate or 0.0)
            indicators["outbound_rate_z"] = round(z_score, 2)
            if z_score > 3.5:
                score = min(score + 0.2, 1.0)
                decision_reasons.append("outbound_rate_deviates_from_entity_baseline")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="entity_outbound_rate_z",
                        value=round(out_rate or 0.0, 2),
                        baseline=round(entity_profile.outbound_rate_baseline.ewma_mean, 2),
                        deviation=round(z_score, 2),
                        interpretation=f"Outbound transfer rate deviates by {z_score:.1f} sigma from entity baseline",
                    )
                )

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
            ef, source_entity, score, confidence, severity, indicators, evidence_items, decision_reasons, timestamp_iso
        )

    def _build_signal(
        self,
        ef: Any,
        source_entity: str,
        score: float,
        confidence: float,
        severity: Severity,
        indicators: dict,
        evidence_items: List[EvidenceItem],
        decision_reasons: List[str],
        timestamp_iso: str,
    ) -> DetectionSignal:
        signal_id = f"sig-exf-{uuid.uuid4().hex[:8]}"
        now_ts = datetime.now(timezone.utc).isoformat()

        observable_features = {
            "total_outbound_bytes": indicators.get("total_outbound_bytes", 0),
            "total_inbound_bytes": indicators.get("total_inbound_bytes", 0),
            "outbound_bytes_per_sec": indicators.get("outbound_bytes_per_sec", 0.0),
            "upload_download_ratio": indicators.get("upload_download_ratio", 1.0),
            "large_transfer_count": indicators.get("large_transfer_count", 0),
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
            threat_class=ThreatClass.DATA_EXFILTRATION,
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
