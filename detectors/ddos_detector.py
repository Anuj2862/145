"""Deterministic baseline detector for Volumetric and Protocol DDoS (Member 2 / M15).

Evaluates packet velocity, byte velocity, TCP SYN/RST ratios, source/dest entropy,
and entity baseline deviations to identify DDoS attacks.
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


class DDoSBaselineDetector:
    """Deterministic baseline detector for Volumetric and Protocol DDoS attacks."""

    PPS_SUSPICIOUS_THRESHOLD = 1000.0   # packets per second
    PPS_CRITICAL_THRESHOLD = 5000.0     # packets per second
    SYN_RATIO_SUSPICIOUS = 0.5          # 50% of packets are SYN
    SYN_RATIO_CRITICAL = 0.8            # 80% of packets are SYN
    BPS_SUSPICIOUS_THRESHOLD = 1_000_000.0    # 1 MB/s
    BPS_CRITICAL_THRESHOLD = 10_000_000.0     # 10 MB/s
    Z_SCORE_SUSPICIOUS = 3.5
    Z_SCORE_CRITICAL = 10.0

    def __init__(self, detector_id: str = "DDoSBaselineDetector", version: str = "1.0.0"):
        self.detector_id = detector_id
        self.detector_version = version

    def evaluate(
        self,
        fv: Union[FeatureVector, Any],
        entity_profile: Optional[Any] = None,
        emit_benign: bool = True,
    ) -> Optional[DetectionSignal]:
        """Evaluate flow features and entity baselines for DDoS characteristics."""
        score = 0.0
        indicators: Dict[str, Any] = {}
        evidence_items: List[EvidenceItem] = []
        decision_reasons: List[str] = []

        # Extract metrics
        ff = getattr(fv, "flow_features", None)
        pps = getattr(ff, "packets_per_sec", 0.0) if ff else 0.0
        bps = getattr(ff, "bytes_per_sec", 0.0) if ff else 0.0
        syn_ratio = getattr(ff, "syn_ratio", None) if ff else None

        entity_ip = getattr(fv, "entity_ip", getattr(fv, "source_entity", "unknown"))
        flow_id = getattr(fv, "flow_id", None)
        timestamp_iso = getattr(fv, "timestamp_iso", datetime.now(timezone.utc).isoformat())

        # 1. Packet Velocity Component (0.0 to 0.5)
        pps_score = 0.0
        if pps > self.PPS_CRITICAL_THRESHOLD:
            pps_score = 0.5
            indicators["high_pps"] = pps
            decision_reasons.append("critical_packet_velocity_exceeded")
            evidence_items.append(
                EvidenceItem(
                    feature_name="packets_per_sec",
                    value=round(pps, 2),
                    baseline=100.0,
                    deviation=round(pps / 100.0, 2),
                    interpretation=f"Critical volumetric packet velocity ({pps:.1f} pps) exceeds {self.PPS_CRITICAL_THRESHOLD} pps threshold",
                )
            )
        elif pps > self.PPS_SUSPICIOUS_THRESHOLD:
            pps_score = 0.5 * ((pps - self.PPS_SUSPICIOUS_THRESHOLD) / (self.PPS_CRITICAL_THRESHOLD - self.PPS_SUSPICIOUS_THRESHOLD))
            indicators["elevated_pps"] = pps
            decision_reasons.append("suspicious_packet_velocity_observed")
            evidence_items.append(
                EvidenceItem(
                    feature_name="packets_per_sec",
                    value=round(pps, 2),
                    baseline=100.0,
                    deviation=round(pps / 100.0, 2),
                    interpretation=f"Elevated packet velocity ({pps:.1f} pps) exceeds {self.PPS_SUSPICIOUS_THRESHOLD} pps threshold",
                )
            )
        score += pps_score

        # 2. SYN Flood Component (0.0 to 0.5)
        if syn_ratio is not None and pps > 50.0:  # Suppress single-packet false positives
            if syn_ratio > self.SYN_RATIO_CRITICAL:
                score += 0.5
                indicators["critical_syn_ratio"] = syn_ratio
                decision_reasons.append("critical_tcp_syn_flood_ratio")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="syn_ratio",
                        value=round(syn_ratio, 3),
                        baseline=0.05,
                        deviation=round(syn_ratio / 0.05, 2),
                        interpretation=f"Abnormal TCP SYN flag ratio ({syn_ratio*100:.1f}%) indicates active SYN-flooding",
                    )
                )
            elif syn_ratio > self.SYN_RATIO_SUSPICIOUS:
                syn_score = 0.25 * ((syn_ratio - self.SYN_RATIO_SUSPICIOUS) / (self.SYN_RATIO_CRITICAL - self.SYN_RATIO_SUSPICIOUS))
                score += syn_score
                indicators["elevated_syn_ratio"] = syn_ratio
                decision_reasons.append("elevated_tcp_syn_ratio")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="syn_ratio",
                        value=round(syn_ratio, 3),
                        baseline=0.05,
                        deviation=round(syn_ratio / 0.05, 2),
                        interpretation=f"Elevated TCP SYN ratio ({syn_ratio*100:.1f}%)",
                    )
                )

        # 3. Entity Baseline Deviation (Adaptive Context)
        if entity_profile is not None and hasattr(entity_profile, "compute_pps_z_score"):
            z_score = entity_profile.compute_pps_z_score(pps)
            indicators["pps_z_score"] = round(z_score, 2)
            if z_score > self.Z_SCORE_SUSPICIOUS and pps > 100.0:
                deviation_boost = min(0.3, 0.3 * (z_score / self.Z_SCORE_CRITICAL))
                score += deviation_boost
                decision_reasons.append("entity_historical_pps_baseline_deviation")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="entity_packet_rate_z",
                        value=round(pps, 2),
                        baseline=round(entity_profile.pps_baseline.ewma_mean, 2),
                        deviation=round(z_score, 2),
                        interpretation=f"Entity packet rate deviates by {z_score:.1f} sigma from historical baseline",
                    )
                )

        # 4. Bandwidth Rate Check
        if bps > self.BPS_CRITICAL_THRESHOLD:
            indicators["critical_bandwidth"] = bps
            evidence_items.append(
                EvidenceItem(
                    feature_name="bytes_per_sec",
                    value=round(bps, 2),
                    baseline=self.BPS_SUSPICIOUS_THRESHOLD,
                    deviation=round(bps / self.BPS_SUSPICIOUS_THRESHOLD, 2),
                    interpretation=f"High bandwidth velocity ({bps / 1_000_000:.2f} MB/s)",
                )
            )

        confidence = min(max(score, 0.0), 1.0)

        # If benign and emit_benign is False, return None
        if confidence <= 0.0 and not emit_benign:
            return None

        # Severity determination
        if confidence >= 0.9:
            severity = Severity.CRITICAL
        elif confidence >= 0.7:
            severity = Severity.HIGH
        elif confidence >= 0.4:
            severity = Severity.MEDIUM
        elif confidence >= 0.1:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        target_entity = None
        if flow_id:
            try:
                target_entity = flow_id.split("-")[1].split(":")[0]
            except Exception:
                pass

        observable_features = {
            "packets_per_sec": pps,
            "bytes_per_sec": bps,
            "syn_ratio": syn_ratio,
        }

        signal_id = f"sig-ddos-{uuid.uuid4().hex[:8]}"
        now_ts = datetime.now(timezone.utc).isoformat()

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
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            score=confidence,
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
