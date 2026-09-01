"""Deterministic baseline detector for Encrypted Malware communications (Member 2 / M15).

Operates strictly on observable metadata (TLS/QUIC handshake parameters, fingerprints,
timing, packet size sequences). Performs ZERO payload decryption and ZERO active probing.
JA3/JA4 fingerprints alone are never a sole verdict.
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


class EncryptedThreatDetector:
    """Deterministic baseline detector for Encrypted Malware communications."""

    WEIGHT_METADATA_ANOMALY = 0.3
    WEIGHT_BEHAVIOURAL_CONTEXT = 0.7

    def __init__(self, detector_id: str = "EncryptedThreatDetector", version: str = "1.0.0"):
        self.detector_id = detector_id
        self.detector_version = version

    def evaluate(
        self,
        fv: Union[FeatureVector, Any],
        entity_profile: Optional[Any] = None,
        emit_benign: bool = True,
    ) -> Optional[DetectionSignal]:
        """Evaluate observable TLS/QUIC metadata and behavioral context for threat indicators."""
        score = 0.0
        confidence = 0.0
        indicators: Dict[str, Any] = {}
        evidence_items: List[EvidenceItem] = []
        decision_reasons: List[str] = []

        tf = getattr(fv, "tls_features", None)
        entity_ip = getattr(fv, "entity_ip", getattr(fv, "source_entity", "unknown"))
        flow_id = getattr(fv, "flow_id", None)
        timestamp_iso = getattr(fv, "timestamp_iso", datetime.now(timezone.utc).isoformat())

        has_tls = tf and (getattr(tf, "ja3_hash", None) or getattr(tf, "ja4_hash", None) or getattr(tf, "sni", None) or getattr(tf, "alpn", None))
        if not has_tls:
            indicators["reason"] = "No TLS metadata present"
            if not emit_benign:
                return None
            return self._build_signal(
                fv, 0.0, 0.0, Severity.INFO, indicators, evidence_items, decision_reasons, timestamp_iso, flow_id, entity_ip
            )

        ja3 = getattr(tf, "ja3_hash", None)
        ja4 = getattr(tf, "ja4_hash", None)
        sni = getattr(tf, "sni", None)
        alpn = getattr(tf, "alpn", None)

        available_fields = sum(1 for x in [ja3, ja4, sni, alpn] if x)
        completeness_ratio = available_fields / 4.0

        indicators["tls_completeness"] = completeness_ratio
        indicators["has_ja3"] = bool(ja3)
        indicators["has_ja4"] = bool(ja4)
        indicators["has_sni"] = bool(sni)
        indicators["has_alpn"] = bool(alpn)

        if ja3:
            evidence_items.append(
                EvidenceItem(
                    feature_name="ja3_hash",
                    value=ja3,
                    interpretation=f"Observable client TLS JA3 fingerprint: {ja3[:12]}...",
                )
            )
        if ja4:
            evidence_items.append(
                EvidenceItem(
                    feature_name="ja4_hash",
                    value=ja4,
                    interpretation=f"Observable client TLS JA4 fingerprint: {ja4[:12]}...",
                )
            )

        # Structural anomaly heuristics (max 1.0)
        # Bare IP connections lack SNI when establishing complex TLS handshakes
        metadata_anomaly = 0.0
        if ja3 and not sni:
            metadata_anomaly += 0.5
            decision_reasons.append("bare_ip_tls_connection_no_sni")
            evidence_items.append(
                EvidenceItem(
                    feature_name="sni",
                    value="None",
                    interpretation="TLS handshake lacks Server Name Indication (SNI) for IP-based session",
                )
            )
        if sni and not alpn:
            metadata_anomaly += 0.2

        metadata_anomaly = min(metadata_anomaly, 1.0)
        indicators["comp_metadata_anomaly"] = metadata_anomaly

        # Contextual Behavioural Scoring
        behavioural_suspicion = 0.0
        temp_feat = getattr(fv, "temporal_features", None)
        if temp_feat and getattr(temp_feat, "periodicity_score", None) is not None:
            periodicity = float(temp_feat.periodicity_score)
            jitter = float(getattr(temp_feat, "jitter_pct", 0.0) or 0.0)

            temp_score = min(periodicity * 0.7, 0.7)
            if jitter < 50.0:
                temp_score += 0.3 * (1.0 - (jitter / 50.0))

            behavioural_suspicion = min(temp_score, 1.0)
            indicators["context_temporal_used"] = True
            indicators["periodicity_score"] = periodicity
            if periodicity >= 0.8:
                decision_reasons.append("correlated_temporal_periodicity_observed")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="periodicity_score",
                        value=round(periodicity, 2),
                        baseline=0.0,
                        deviation=round(periodicity, 2),
                        interpretation=f"Encrypted session exhibits periodic callback timing ({periodicity:.2f})",
                    )
                )
        else:
            indicators["context_temporal_used"] = False

        # Entity Fingerprint Novelty
        if entity_profile is not None:
            known_fps = getattr(entity_profile, "known_ja3", set())
            if ja3 and ja3 not in known_fps:
                behavioural_suspicion = min(behavioural_suspicion + 0.3, 1.0)
                decision_reasons.append("first_seen_tls_fingerprint_for_entity")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="entity_tls_novelty",
                        value=1.0,
                        baseline=0.0,
                        deviation=1.0,
                        interpretation="TLS fingerprint is newly observed for this entity",
                    )
                )

        indicators["comp_behavioural"] = behavioural_suspicion

        score = (metadata_anomaly * self.WEIGHT_METADATA_ANOMALY) + (behavioural_suspicion * self.WEIGHT_BEHAVIOURAL_CONTEXT)
        confidence = score * completeness_ratio * 0.85

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
        signal_id = f"sig-enc-{uuid.uuid4().hex[:8]}"
        indicators["encrypted_threat_score"] = score
        now_ts = datetime.now(timezone.utc).isoformat()

        target_entity = None
        if flow_id:
            try:
                target_entity = flow_id.split("-")[1].split(":")[0]
            except Exception:
                pass

        tf = getattr(fv, "tls_features", None)
        observable_features = {
            "ja3_hash": getattr(tf, "ja3_hash", None) if tf else None,
            "ja4_hash": getattr(tf, "ja4_hash", None) if tf else None,
            "sni": getattr(tf, "sni", None) if tf else None,
            "alpn": getattr(tf, "alpn", None) if tf else None,
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
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
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
