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
            )

        # Handle UnifiedMLResult
        elif isinstance(ml_result, UnifiedMLResult):
            clf = ml_result.classification
            anom = ml_result.anomaly

            src = source_entity if source_entity else ml_result.source_entity
            tgt = target_entity if target_entity else ml_result.target_entity
            ts = timestamp_iso if timestamp_iso else ml_result.timestamp_iso

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
    def feature_vector_to_features(fv: FeatureVector) -> np.ndarray:
        """Extract 52 ML features from a Pydantic FeatureVector contract schema.
        
        Reads across flow, dns, tls, temporal, and entity feature sub-objects.
        Fills unextracted or None values with default 0.0.
        """
        data = {}

        # 1. Flow features
        if fv.flow_features:
            ff = fv.flow_features
            data["duration"] = getattr(ff, "duration", getattr(ff, "duration_sec", 0.0))
            data["total_packets"] = getattr(ff, "total_packets", getattr(ff, "packet_count", 0.0))
            data["total_bytes"] = getattr(ff, "total_bytes", getattr(ff, "byte_count", 0.0))
            data["bytes_forward"] = getattr(ff, "bytes_fwd", getattr(ff, "bytes_forward", 0.0))
            data["bytes_backward"] = getattr(ff, "bytes_bwd", getattr(ff, "bytes_backward", 0.0))
            data["packets_per_sec"] = getattr(ff, "packets_per_sec", 0.0)
            data["bytes_per_sec"] = getattr(ff, "bytes_per_sec", 0.0)
            data["packet_size_mean"] = getattr(ff, "avg_packet_size", getattr(ff, "packet_size_mean", 0.0))

        # 2. Temporal features
        if fv.temporal_features:
            tf = fv.temporal_features
            data["iat_mean"] = getattr(tf, "iat_mean_ms", getattr(tf, "iat_mean", 0.0))
            data["iat_std"] = getattr(tf, "iat_std_ms", getattr(tf, "iat_std", 0.0))
            data["periodicity_score"] = getattr(tf, "periodicity_score", 0.0)
            data["jitter"] = getattr(tf, "jitter_pct", getattr(tf, "jitter", 0.0))
            data["burst_rate"] = getattr(tf, "burst_rate", 0.0)

        # 3. DNS features
        if fv.dns_features:
            df = fv.dns_features
            data["dns_query_count"] = getattr(df, "dns_query_count", 0.0)
            data["unique_domain_count"] = getattr(df, "unique_domains", getattr(df, "unique_domain_count", 0.0))
            data["domain_length_mean"] = getattr(df, "avg_domain_len", getattr(df, "domain_length_mean", 0.0))
            data["domain_entropy"] = getattr(df, "domain_entropy", getattr(df, "entropy_mean", 0.0))
            data["ngram_score"] = getattr(df, "subdomain_entropy", getattr(df, "ngram_score", 0.0))
            data["dns_query_rate"] = getattr(df, "dns_query_rate", 0.0)

        # 4. TLS features
        if fv.tls_features:
            tlf = fv.tls_features
            data["session_resumption"] = 1.0 if tlf.session_reused else 0.0
            data["tls_packet_size_mean"] = getattr(tlf, "tls_packet_size_mean", 0.0)
            if tlf.ja3_hash:
                ja3_val = f"ja3_JA3_{tlf.ja3_hash.upper()}"
                if ja3_val in EXPECTED_FEATURE_NAMES:
                    data[ja3_val] = 1.0
            if tlf.ja4_hash:
                ja4_val = f"ja4_JA4_{tlf.ja4_hash.upper()}"
                if ja4_val in EXPECTED_FEATURE_NAMES:
                    data[ja4_val] = 1.0
            if tlf.tls_version:
                tls_ver = f"tls_version_{tlf.tls_version.upper()}"
                if tls_ver in EXPECTED_FEATURE_NAMES:
                    data[tls_ver] = 1.0

        # 5. Entity features
        if fv.entity_features:
            ef = fv.entity_features
            data["entity_avg_connection_interval"] = getattr(ef, "entity_avg_connection_interval", 0.0)
            data["entity_periodicity"] = getattr(ef, "entity_periodicity", 0.0)

        return FeatureVectorAdapter.dict_to_features(data)
