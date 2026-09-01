"""Deterministic baseline detector for Botnet C2 Beaconing (Member 2 / M15).

Evaluates temporal inter-arrival patterns, periodicity scores, jitter percentages,
destination persistence, and entity novelty to identify Command & Control beaconing.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from schemas import (
    DetectionSignal,
    DetectorType,
    EvidenceItem,
    FeatureVector,
    Severity,
    SignalProvenance,
    ThreatClass,
)


class C2BeaconDetector:
    """Deterministic baseline detector for Botnet C2 Beaconing communications."""

    MIN_OBSERVATIONS_REQUIRED = 5   # Requires >= 5 intervals to assess periodicity
    PERIODICITY_HIGH = 0.85         # High periodicity threshold
    JITTER_LOW = 15.0               # Low jitter percentage threshold (<=15%)

    def __init__(self, detector_id: str = "C2BeaconDetector", version: str = "1.0.0"):
        self.detector_id = detector_id
        self.detector_version = version

    def evaluate(
        self,
        fv: Union[FeatureVector, Any],
        observation_count: int = 0,
        entity_profile: Optional[Any] = None,
        emit_benign: bool = True,
    ) -> Optional[DetectionSignal]:
        """Evaluate temporal features and destination context for beaconing signatures."""
        score = 0.0
        confidence = 0.0
        indicators: Dict[str, Any] = {}
        evidence_items: List[EvidenceItem] = []
        decision_reasons: List[str] = []

        tf = getattr(fv, "temporal_features", None)
        entity_ip = getattr(fv, "entity_ip", getattr(fv, "source_entity", "unknown"))
        flow_id = getattr(fv, "flow_id", None)
        timestamp_iso = getattr(fv, "timestamp_iso", datetime.now(timezone.utc).isoformat())

        # If temporal features are missing or incomplete, handle safely
        if not tf or tf.periodicity_score is None or tf.jitter_pct is None:
            indicators["reason"] = "Missing temporal features"
            if not emit_benign:
                return None
            return self._build_signal(
                fv, 0.0, 0.0, Severity.INFO, indicators, evidence_items, decision_reasons, timestamp_iso, flow_id, entity_ip
            )

        periodicity = float(tf.periodicity_score)
        jitter = float(tf.jitter_pct)
        iat_mean = float(tf.inter_arrival_mean_ms or 0.0)
        iat_std = float(tf.inter_arrival_std_ms or 0.0)

        indicators["periodicity_score"] = periodicity
        indicators["jitter_pct"] = jitter
        indicators["inter_arrival_mean_ms"] = iat_mean
        indicators["inter_arrival_std_ms"] = iat_std
        indicators["observation_count"] = observation_count

        # 1. Base Periodicity Scoring (0.0 to 0.6)
        periodicity_contrib = min(periodicity * 0.6, 0.6)
        score += periodicity_contrib
        indicators["score_component_periodicity"] = periodicity_contrib

        if periodicity >= 0.8:
            decision_reasons.append("high_temporal_periodicity_observed")
            evidence_items.append(
                EvidenceItem(
                    feature_name="periodicity_score",
                    value=round(periodicity, 3),
                    baseline=0.0,
                    deviation=round(periodicity, 3),
                    interpretation=f"High connection regularity: periodicity score {periodicity:.2f} / 1.00",
                )
            )

        # 2. Jitter Scoring (0.0 to 0.4)
        jitter_contrib = 0.0
        if jitter < 50.0:
            jitter_contrib = 0.4 * (1.0 - (jitter / 50.0))
        score += jitter_contrib
        indicators["score_component_jitter"] = jitter_contrib

        if jitter <= self.JITTER_LOW:
            decision_reasons.append("low_inter_arrival_jitter_beacon")
            evidence_items.append(
                EvidenceItem(
                    feature_name="jitter_pct",
                    value=round(jitter, 2),
                    baseline=50.0,
                    deviation=round(50.0 - jitter, 2),
                    interpretation=f"Low timing jitter ({jitter:.1f}%) indicates automated callback scheduler",
                )
            )

        evidence_items.append(
            EvidenceItem(
                feature_name="inter_arrival_mean_ms",
                value=round(iat_mean, 2),
                interpretation=f"Mean inter-arrival interval: {iat_mean / 1000.0:.2f}s (std: {iat_std / 1000.0:.2f}s)",
            )
        )

        # 3. Multi-Signal Agreement (Destination Persistence & Novelty Context)
        if entity_profile is not None:
            dest_count = len(getattr(entity_profile, "known_destinations", []))
            if dest_count > 0:
                indicators["destination_persistence"] = dest_count
                decision_reasons.append("destination_persistence_confirmed")

        # 4. Minimum Observation Handling
        if observation_count < self.MIN_OBSERVATIONS_REQUIRED:
            indicators["insufficient_observations_penalty"] = True
            indicators["reason"] = "Insufficient temporal observations for high confidence."
            decision_reasons.append("insufficient_observations_penalty_applied")
            score = min(score, 0.4)
            confidence = min(score, 0.3)
        else:
            confidence = min(score, 0.85)

        # Determine Severity
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
            fv, score, confidence, severity, indicators, evidence_items, decision_reasons, timestamp_iso, flow_id, entity_ip
        )

    def _build_signal(
        self,
        fv: Any,
        score: float,
        confidence: float,
        severity: Severity,
        indicators: dict,
        evidence_items: List[EvidenceItem],
        decision_reasons: List[str],
        timestamp_iso: str,
        flow_id: Optional[str],
        entity_ip: str,
    ) -> DetectionSignal:
        signal_id = f"sig-c2-{uuid.uuid4().hex[:8]}"
        indicators["c2_suspicion_score"] = score
        now_ts = datetime.now(timezone.utc).isoformat()

        target_entity = None
        if flow_id:
            try:
                target_entity = flow_id.split("-")[1].split(":")[0]
            except Exception:
                pass

        tf = getattr(fv, "temporal_features", None)
        observable_features = {
            "periodicity_score": getattr(tf, "periodicity_score", None) if tf else None,
            "jitter_pct": getattr(tf, "jitter_pct", None) if tf else None,
            "inter_arrival_mean_ms": getattr(tf, "inter_arrival_mean_ms", None) if tf else None,
            "inter_arrival_std_ms": getattr(tf, "inter_arrival_std_ms", None) if tf else None,
            "observation_count": indicators.get("observation_count", 0),
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
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            score=score,
            severity=severity,
            source_entity=entity_ip,
            entity_id=entity_ip,
            target_entity=target_entity,
            flow_id=flow_id,
            timestamp_iso=now_ts,
            evidence=evidence_items,
            indicators=indicators,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            decision_reason=decision_reasons,
            observable_features=observable_features,
            provenance=prov,
        )
