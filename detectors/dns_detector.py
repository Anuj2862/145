"""Deterministic baseline detector for DGA (Domain Generation Algorithms) and DNS Tunnelling (Member 2 / M15).

Evaluates domain entropy, query string lengths, NXDOMAIN failure rates, TXT record ratios,
subdomain cardinality, and lexical features to differentiate DGA and DNS Tunnelling.
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


class DNSAnomalyDetector:
    """Deterministic baseline detector for DGA and DNS Tunnelling behaviours."""

    # Entropy thresholds (Shannon entropy of domain string)
    ENTROPY_MIN_SUSPICIOUS = 3.0
    ENTROPY_MAX_CRITICAL = 4.5

    # Query length thresholds (average character length of queries)
    LENGTH_MIN_SUSPICIOUS = 20.0
    LENGTH_MAX_CRITICAL = 50.0

    # NXDOMAIN count thresholds
    NXDOMAIN_MIN_SUSPICIOUS = 2.0
    NXDOMAIN_MAX_CRITICAL = 20.0

    # TXT record ratio thresholds (0.0 to 1.0)
    TXT_RATIO_MIN_SUSPICIOUS = 0.1
    TXT_RATIO_MAX_CRITICAL = 0.8

    # Subdomain count thresholds
    SUBDOMAIN_MIN_SUSPICIOUS = 5.0
    SUBDOMAIN_MAX_CRITICAL = 30.0

    # Component weights
    WEIGHT_ENTROPY = 0.30
    WEIGHT_LENGTH = 0.25
    WEIGHT_NXDOMAIN = 0.20
    WEIGHT_TXT = 0.15
    WEIGHT_SUBDOMAIN = 0.10

    def __init__(self, detector_id: str = "DNSAnomalyDetector", version: str = "1.0.0"):
        self.detector_id = detector_id
        self.detector_version = version

    def _normalize(self, value: float, min_val: float, max_val: float) -> float:
        """Normalize a raw value to a [0.0, 1.0] suspicion score."""
        if value <= min_val:
            return 0.0
        if value >= max_val:
            return 1.0
        return (value - min_val) / (max_val - min_val)

    def evaluate(
        self,
        fv: Union[FeatureVector, Any],
        entity_profile: Optional[Any] = None,
        emit_benign: bool = True,
    ) -> Optional[DetectionSignal]:
        """Evaluate DNS features and produce a DetectionSignal."""
        score = 0.0
        confidence = 0.0
        indicators: Dict[str, Any] = {}
        evidence_items: List[EvidenceItem] = []
        decision_reasons: List[str] = []

        df = getattr(fv, "dns_features", None)
        entity_ip = getattr(fv, "entity_ip", getattr(fv, "source_entity", "unknown"))
        flow_id = getattr(fv, "flow_id", None)
        timestamp_iso = getattr(fv, "timestamp_iso", datetime.now(timezone.utc).isoformat())

        # Safely handle missing entirely or all-None features
        if not df:
            indicators["reason"] = "No DNS features present"
            if not emit_benign:
                return None
            return self._build_signal(
                fv, 0.0, 0.0, Severity.INFO, indicators, evidence_items, decision_reasons, timestamp_iso, flow_id, entity_ip
            )

        valid_weight_sum = 0.0
        weighted_score_sum = 0.0

        entropy_val = getattr(df, "entropy_mean", None)
        length_val = getattr(df, "query_length_mean", None)
        nxdomain_val = getattr(df, "nxdomain_count", 0)
        txt_ratio_val = getattr(df, "txt_record_ratio", None)
        subdomain_val = getattr(df, "subdomain_count", None)

        # 1. Entropy Component
        if entropy_val is not None:
            c_score = self._normalize(float(entropy_val), self.ENTROPY_MIN_SUSPICIOUS, self.ENTROPY_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_ENTROPY
            valid_weight_sum += self.WEIGHT_ENTROPY
            indicators["entropy_mean"] = entropy_val
            indicators["comp_entropy"] = c_score
            if entropy_val >= self.ENTROPY_MIN_SUSPICIOUS:
                decision_reasons.append("high_shannon_domain_entropy")
                decision_reasons.append("elevated_domain_entropy_observed")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="domain_entropy",
                        value=round(float(entropy_val), 2),
                        baseline=2.5,
                        deviation=round(float(entropy_val) - 2.5, 2),
                        interpretation=f"Elevated domain character entropy ({entropy_val:.2f}) indicates algorithmic randomization",
                    )
                )

        # 2. Query Length Component
        if length_val is not None:
            c_score = self._normalize(float(length_val), self.LENGTH_MIN_SUSPICIOUS, self.LENGTH_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_LENGTH
            valid_weight_sum += self.WEIGHT_LENGTH
            indicators["query_length_mean"] = length_val
            indicators["comp_length"] = c_score
            if length_val >= self.LENGTH_MIN_SUSPICIOUS:
                decision_reasons.append("elevated_dns_query_length")
                decision_reasons.append("long_dns_query_string_observed")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="query_length_mean",
                        value=round(float(length_val), 1),
                        baseline=15.0,
                        deviation=round(float(length_val) - 15.0, 1),
                        interpretation=f"Abnormal DNS query string length (mean {length_val:.1f} chars)",
                    )
                )

        # 3. NXDOMAIN Component
        if nxdomain_val is not None:
            c_score = self._normalize(float(nxdomain_val), self.NXDOMAIN_MIN_SUSPICIOUS, self.NXDOMAIN_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_NXDOMAIN
            valid_weight_sum += self.WEIGHT_NXDOMAIN
            indicators["nxdomain_count"] = nxdomain_val
            indicators["comp_nxdomain"] = c_score
            if nxdomain_val >= self.NXDOMAIN_MIN_SUSPICIOUS:
                decision_reasons.append("burst_nxdomain_responses")
                decision_reasons.append("high_nxdomain_frequency")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="nxdomain_count",
                        value=int(nxdomain_val),
                        baseline=0,
                        deviation=int(nxdomain_val),
                        interpretation=f"Elevated NXDOMAIN failures ({nxdomain_val} resolution errors) characteristic of DGA lookups",
                    )
                )

        # 4. TXT Record Ratio Component
        if txt_ratio_val is not None:
            c_score = self._normalize(float(txt_ratio_val), self.TXT_RATIO_MIN_SUSPICIOUS, self.TXT_RATIO_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_TXT
            valid_weight_sum += self.WEIGHT_TXT
            indicators["txt_record_ratio"] = txt_ratio_val
            indicators["comp_txt"] = c_score
            if txt_ratio_val >= self.TXT_RATIO_MIN_SUSPICIOUS:
                decision_reasons.append("elevated_txt_query_ratio_tunnel")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="txt_record_ratio",
                        value=round(float(txt_ratio_val), 3),
                        baseline=0.01,
                        deviation=round(float(txt_ratio_val) / 0.01, 1),
                        interpretation=f"High TXT record request ratio ({txt_ratio_val*100:.1f}%) suggests DNS data encapsulation",
                    )
                )

        # 5. Subdomain Count Component
        if subdomain_val is not None:
            c_score = self._normalize(float(subdomain_val), self.SUBDOMAIN_MIN_SUSPICIOUS, self.SUBDOMAIN_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_SUBDOMAIN
            valid_weight_sum += self.WEIGHT_SUBDOMAIN
            indicators["subdomain_count"] = subdomain_val
            indicators["comp_subdomain"] = c_score
            if subdomain_val >= self.SUBDOMAIN_MIN_SUSPICIOUS:
                decision_reasons.append("high_subdomain_cardinality_tunnel")
                evidence_items.append(
                    EvidenceItem(
                        feature_name="subdomain_count",
                        value=int(subdomain_val),
                        baseline=1,
                        deviation=int(subdomain_val) - 1,
                        interpretation=f"High unique subdomain cardinality ({subdomain_val} unique labels) indicative of tunnel payload chunks",
                    )
                )

        # Subtype discrimination: DGA vs Tunnel
        is_tunnel = (txt_ratio_val is not None and txt_ratio_val >= self.TXT_RATIO_MIN_SUSPICIOUS) or \
                    (subdomain_val is not None and subdomain_val >= self.SUBDOMAIN_MIN_SUSPICIOUS) or \
                    (length_val is not None and length_val >= 35.0)
        indicators["dns_subtype"] = "DNS_TUNNELLING" if is_tunnel else "DGA"

        # Final Score Calculation
        if valid_weight_sum > 0.0:
            score = weighted_score_sum / valid_weight_sum
            max_confidence_possible = valid_weight_sum * 0.9
            confidence = score * max_confidence_possible
        else:
            score = 0.0
            confidence = 0.0
            indicators["reason"] = "All DNS features were None/empty"

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
        signal_id = f"sig-dns-{uuid.uuid4().hex[:8]}"
        indicators["dns_suspicion_score"] = score
        now_ts = datetime.now(timezone.utc).isoformat()

        target_entity = None
        if flow_id:
            try:
                target_entity = flow_id.split("-")[1].split(":")[0]
            except Exception:
                pass

        df = getattr(fv, "dns_features", None)
        observable_features = {
            "entropy_mean": getattr(df, "entropy_mean", None) if df else None,
            "query_length_mean": getattr(df, "query_length_mean", None) if df else None,
            "nxdomain_count": getattr(df, "nxdomain_count", 0) if df else 0,
            "txt_record_ratio": getattr(df, "txt_record_ratio", None) if df else None,
            "subdomain_count": getattr(df, "subdomain_count", None) if df else None,
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
            threat_class=ThreatClass.DGA_DNS_TUNNELLING,
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
