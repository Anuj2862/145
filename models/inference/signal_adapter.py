"""DetectionSignal Adapter and FeatureVector Converter for UniGuard ML Inference (Member 2).

Converts ML inference results into standardized DetectionSignal schema objects for Member 3
fusion ingestion, enforcing severity conventions and benign traffic handling.
"""

import uuid
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
import numpy as np

from schemas import (
    DetectionSignal,
    ThreatClass,
    DetectorType,
    Severity,
    FeatureVector,
)
from models.inference.ml_inference import (
    ClassificationResult,
    AnomalyResult,
    UnifiedMLResult,
    EXPECTED_FEATURE_NAMES,
)


def calculate_severity(confidence: float) -> Severity:
    """Calculate threat severity rating according to UniGuard system convention.
    
    Rule:
      confidence >= 0.7 -> Severity.HIGH
      confidence >= 0.4 -> Severity.MEDIUM
      confidence >= 0.1 -> Severity.LOW
      confidence < 0.1  -> Severity.INFO
    """
    if confidence >= 0.7:
        return Severity.HIGH
    elif confidence >= 0.4:
        return Severity.MEDIUM
    elif confidence >= 0.1:
        return Severity.LOW
    else:
        return Severity.INFO


class SignalAdapter:
    """Adapts ML classification and anomaly inference outputs to DetectionSignal contract."""

    @staticmethod
    def to_detection_signal(
        ml_result: Union[ClassificationResult, UnifiedMLResult],
        source_entity: Optional[str] = None,
        target_entity: Optional[str] = None,
        timestamp_iso: Optional[str] = None,
    ) -> Optional[DetectionSignal]:
        """Convert ML inference result into a valid DetectionSignal.
        
        BENIGN Traffic Handling:
          If the primary model predicts BENIGN (class 0) and no anomaly is detected,
          this method returns None. Benign traffic MUST NOT generate false threat signals.
          
        Anomaly + Classifier Coexistence:
          If LightGBM predicts BENIGN but Isolation Forest flags an ANOMALY, a DetectionSignal
          is produced with ThreatClass.UNKNOWN_ANOMALY and DetectorType.UNSUPERVISED_ANOMALY
          for Member 3 fusion reasoning.
        """
        if not timestamp_iso:
            timestamp_iso = datetime.now(timezone.utc).isoformat()

        # Handle ClassificationResult
        if isinstance(ml_result, ClassificationResult):
            if not ml_result.is_threat or ml_result.threat_class is None:
                # BENIGN flow - do not emit threat signal
                return None

            src = source_entity if source_entity else "unknown"
            sig_id = f"sig_ml_{uuid.uuid4().hex[:12]}"
            sev = calculate_severity(ml_result.confidence)

            indicators = {
                "predicted_class": ml_result.predicted_class_name,
                "class_probabilities": ml_result.probabilities,
                "model_name": ml_result.model_name,
                "confidence": ml_result.confidence,
                "top_probability": ml_result.confidence,
                "inference_latency_ms": ml_result.inference_latency_ms,
            }

            # Build Phase 2C Provenance
            from schemas import SignalProvenance
            decision_reasons = [
                f"ml_multiclass_prediction_{ml_result.predicted_class_name.lower()}",
                "classification_confidence_threshold_met",
            ]
            observable_features = {
                "top_probability": ml_result.confidence,
                "model_name": ml_result.model_name,
                "inference_latency_ms": ml_result.inference_latency_ms,
            }
            prov = SignalProvenance(
                detector_id=ml_result.model_name or "LightGBMClassifier",
                detector_version="1.0.0",
                decision_reason=decision_reasons,
                observable_features=observable_features,
                window_start_iso=timestamp_iso,
                window_end_iso=timestamp_iso,
            )

            return DetectionSignal(
                signal_id=sig_id,
                threat_class=ml_result.threat_class,
                detector_type=DetectorType.LIGHTWEIGHT_ML,
                confidence=ml_result.confidence,
                severity=sev,
                source_entity=src,
                target_entity=target_entity,
                timestamp_iso=timestamp_iso,
                indicators=indicators,
                detector_id=ml_result.model_name or "LightGBMClassifier",
                detector_version="1.0.0",
                decision_reason=decision_reasons,
                observable_features=observable_features,
                provenance=prov,
            )

        # Handle UnifiedMLResult
        elif isinstance(ml_result, UnifiedMLResult):
            clf = ml_result.classification
            anom = ml_result.anomaly

            src = source_entity if source_entity else ml_result.source_entity
            tgt = target_entity if target_entity else ml_result.target_entity
            ts = timestamp_iso if timestamp_iso else ml_result.timestamp_iso

            from schemas import SignalProvenance

            # Case A: Supervised model detected a known threat class (1..6)
            if clf.is_threat and clf.threat_class is not None:
                sig_id = f"sig_ml_clf_{uuid.uuid4().hex[:12]}"
                sev = calculate_severity(clf.confidence)

                indicators = {
                    "predicted_class": clf.predicted_class_name,
                    "class_probabilities": clf.probabilities,
                    "model_name": clf.model_name,
                    "confidence": clf.confidence,
                    "top_probability": clf.confidence,
                    "inference_latency_ms": clf.inference_latency_ms,
                    "is_anomaly": anom.is_anomaly,
                    "anomaly_score": anom.anomaly_score,
                    "anomaly_model": anom.model_name,
                }

                decision_reasons = [
                    f"ml_multiclass_prediction_{clf.predicted_class_name.lower()}",
                    "classification_confidence_threshold_met",
                ]
                observable_features = {
                    "top_probability": clf.confidence,
                    "model_name": clf.model_name,
                    "inference_latency_ms": clf.inference_latency_ms,
                }
                prov = SignalProvenance(
                    detector_id=clf.model_name or "LightGBMClassifier",
                    detector_version="1.0.0",
                    decision_reason=decision_reasons,
                    observable_features=observable_features,
                    window_start_iso=ts,
                    window_end_iso=ts,
                )

                return DetectionSignal(
                    signal_id=sig_id,
                    threat_class=clf.threat_class,
                    detector_type=DetectorType.LIGHTWEIGHT_ML,
                    confidence=clf.confidence,
                    severity=sev,
                    source_entity=src,
                    target_entity=tgt,
                    timestamp_iso=ts,
                    indicators=indicators,
                    detector_id=clf.model_name or "LightGBMClassifier",
                    detector_version="1.0.0",
                    decision_reason=decision_reasons,
                    observable_features=observable_features,
                    provenance=prov,
                )

            # Case B: Supervised model predicts BENIGN, but Isolation Forest flags ANOMALY
            elif anom.is_anomaly:
                sig_id = f"sig_ml_anom_{uuid.uuid4().hex[:12]}"
                sev = calculate_severity(anom.normalized_confidence)

                indicators = {
                    "predicted_class": "UNKNOWN_ANOMALY",
                    "classifier_predicted_benign": True,
                    "classifier_confidence": clf.confidence,
                    "is_anomaly": True,
                    "anomaly_score": anom.anomaly_score,
                    "anomaly_confidence": anom.normalized_confidence,
                    "anomaly_model": anom.model_name,
                    "inference_latency_ms": anom.inference_latency_ms,
                    "note": anom.note,
                }

                decision_reasons = [
                    "isolation_forest_negative_anomaly_score",
                    "unsupervised_multivariate_outlier_detected",
                ]
                observable_features = {
                    "anomaly_score": anom.anomaly_score,
                    "anomaly_model": anom.model_name,
                    "inference_latency_ms": anom.inference_latency_ms,
                }
                prov = SignalProvenance(
                    detector_id=anom.model_name or "IsolationForestAnomaly",
                    detector_version="1.0.0",
                    decision_reason=decision_reasons,
                    observable_features=observable_features,
                    window_start_iso=ts,
                    window_end_iso=ts,
                )

                return DetectionSignal(
                    signal_id=sig_id,
                    threat_class=ThreatClass.UNKNOWN_ANOMALY,
                    detector_type=DetectorType.UNSUPERVISED_ANOMALY,
                    confidence=anom.normalized_confidence,
                    severity=sev,
                    source_entity=src,
                    target_entity=tgt,
                    timestamp_iso=ts,
                    indicators=indicators,
                    detector_id=anom.model_name or "IsolationForestAnomaly",
                    detector_version="1.0.0",
                    decision_reason=decision_reasons,
                    observable_features=observable_features,
                    provenance=prov,
                )

            # Case C: Both classifier and anomaly detector predict BENIGN
            else:
                return None

        else:
            raise TypeError(f"Unsupported ML result type for SignalAdapter: {type(ml_result)}")


class FeatureVectorAdapter:
    """Adapter boundary for converting FeatureVector or dict objects into 52 ML features.
    
    Enforces strict feature ordering matching training metadata.
    """

    @staticmethod
    def dict_to_features(data: Dict[str, Any]) -> np.ndarray:
        """Convert a feature dictionary into a 52-feature C-contiguous np.ndarray (1, 52).
        
        Fills missing values with 0.0 or default medians as appropriate.
        """
        feats = []
        for name in EXPECTED_FEATURE_NAMES:
            val = data.get(name, 0.0)
            if val is None or np.isnan(val) or np.isinf(val):
                val = 0.0
            feats.append(float(val))
        return np.array(feats, dtype=np.float64).reshape(1, -1)

    @staticmethod
    @staticmethod
    def context_to_features(ctx: Any) -> np.ndarray:
        """Extract 52 ML features from a DetectionContext contract instance.
        
        Bridges single-flow FeatureVector and multi-flow/entity context features
        into the strict 52-feature vector expected by LightGBM and Isolation Forest.
        """
        data: Dict[str, float] = {}
        fv = getattr(ctx, "feature_vector", None)
        if fv:
            # 1. Flow features
            if getattr(fv, "flow_features", None):
                ff = fv.flow_features
                data["duration"] = float(getattr(ff, "duration", getattr(ff, "duration_sec", 0.0)) or 0.0)
                data["total_packets"] = float(getattr(ff, "total_packets", getattr(ff, "packet_count", 0.0)) or 0.0)
                data["total_bytes"] = float(getattr(ff, "total_bytes", getattr(ff, "byte_count", 0.0)) or 0.0)
                data["bytes_forward"] = float(getattr(ff, "bytes_fwd", getattr(ff, "bytes_forward", 0.0)) or 0.0)
                data["bytes_backward"] = float(getattr(ff, "bytes_bwd", getattr(ff, "bytes_backward", 0.0)) or 0.0)
                data["packets_per_sec"] = float(getattr(ff, "packets_per_sec", 0.0) or 0.0)
                data["bytes_per_sec"] = float(getattr(ff, "bytes_per_sec", 0.0) or 0.0)
                data["packet_size_mean"] = float(getattr(ff, "avg_packet_size", getattr(ff, "packet_size_mean", 0.0)) or 0.0)

            # 2. Temporal features
            if getattr(fv, "temporal_features", None):
                tf = fv.temporal_features
                data["iat_mean"] = float(getattr(tf, "iat_mean_ms", getattr(tf, "iat_mean", 0.0)) or 0.0)
                data["iat_std"] = float(getattr(tf, "iat_std_ms", getattr(tf, "iat_std", 0.0)) or 0.0)
                data["periodicity_score"] = float(getattr(tf, "periodicity_score", 0.0) or 0.0)
                data["jitter"] = float(getattr(tf, "jitter_pct", getattr(tf, "jitter", 0.0)) or 0.0)
                data["burst_rate"] = float(getattr(tf, "burst_rate", 0.0) or 0.0)

            # 3. DNS features
            if getattr(fv, "dns_features", None):
                df = fv.dns_features
                data["dns_query_count"] = float(getattr(df, "dns_query_count", 0.0) or 0.0)
                data["unique_domain_count"] = float(getattr(df, "unique_domains", getattr(df, "unique_domain_count", 0.0)) or 0.0)
                data["domain_length_mean"] = float(getattr(df, "avg_domain_len", getattr(df, "domain_length_mean", 0.0)) or 0.0)
                data["domain_entropy"] = float(getattr(df, "domain_entropy", getattr(df, "entropy_mean", 0.0)) or 0.0)
                data["ngram_score"] = float(getattr(df, "subdomain_entropy", getattr(df, "ngram_score", 0.0)) or 0.0)
                data["dns_query_rate"] = float(getattr(df, "dns_query_rate", 0.0) or 0.0)

            # 4. TLS features
            if getattr(fv, "tls_features", None):
                tlf = fv.tls_features
                data["session_resumption"] = 1.0 if getattr(tlf, "session_reused", False) else 0.0
                data["tls_packet_size_mean"] = float(getattr(tlf, "tls_packet_size_mean", 0.0) or 0.0)
                ja3 = getattr(tlf, "ja3_hash", None)
                if ja3:
                    ja3_val = f"ja3_JA3_{ja3.upper()}"
                    if ja3_val in EXPECTED_FEATURE_NAMES:
                        data[ja3_val] = 1.0
                ja4 = getattr(tlf, "ja4_hash", None)
                if ja4:
                    ja4_val = f"ja4_JA4_{ja4.upper()}"
                    if ja4_val in EXPECTED_FEATURE_NAMES:
                        data[ja4_val] = 1.0
                tls_v = getattr(tlf, "tls_version", None)
                if tls_v:
                    tls_ver = f"tls_version_{tls_v.upper()}"
                    if tls_ver in EXPECTED_FEATURE_NAMES:
                        data[tls_ver] = 1.0

            # 5. Entity features from FeatureVector
            if getattr(fv, "entity_features", None):
                ef = fv.entity_features
                data["entity_avg_connection_interval"] = float(getattr(ef, "entity_avg_connection_interval", 0.0) or 0.0)
                data["entity_periodicity"] = float(getattr(ef, "entity_periodicity", 0.0) or 0.0)

        # 6. Entity Reconnaissance Features from DetectionContext
        rf = getattr(ctx, "recon_features", None)
        if rf:
            data["unique_dst_ips"] = float(getattr(rf, "unique_dst_ip_count", 0.0) or 0.0)
            data["unique_dst_ports"] = float(getattr(rf, "unique_dst_port_count", 0.0) or 0.0)
            data["connection_attempt_rate"] = float(getattr(rf, "connection_rate_per_sec", 0.0) or 0.0)
            data["failed_connection_ratio"] = float(getattr(rf, "failed_connection_ratio", 0.0) or 0.0)
            data["fan_out"] = float(getattr(rf, "unique_dst_ip_count", 0.0) + getattr(rf, "unique_dst_port_count", 0.0))
            data["entity_flow_count_1m"] = float(getattr(rf, "flow_count", 0.0) or 0.0)
            data["entity_unique_destinations_1m"] = float(getattr(rf, "unique_dst_ip_count", 0.0) or 0.0)

        # 7. Entity Exfiltration Features from DetectionContext
        exf = getattr(ctx, "exfil_features", None)
        if exf:
            data["outbound_bytes"] = float(getattr(exf, "total_outbound_bytes", 0.0) or 0.0)
            data["outbound_rate"] = float(getattr(exf, "outbound_bytes_per_sec", 0.0) or 0.0)
            data["upload_download_ratio"] = float(getattr(exf, "upload_download_ratio", 0.0) or 0.0)
            data["destination_count"] = float(getattr(exf, "destination_count", 0.0) or 0.0)
            data["large_transfer_score"] = float(getattr(exf, "large_transfer_count", 0.0) or 0.0)

        return FeatureVectorAdapter.dict_to_features(data)

    @staticmethod
    def feature_vector_to_features(fv: FeatureVector) -> np.ndarray:
        """Extract 52 ML features from a Pydantic FeatureVector contract schema."""
        class DummyCtx:
            def __init__(self, feature_vector: FeatureVector):
                self.feature_vector = feature_vector
                self.recon_features = None
                self.exfil_features = None

        return FeatureVectorAdapter.context_to_features(DummyCtx(fv))
