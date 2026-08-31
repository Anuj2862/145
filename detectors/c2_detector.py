import uuid
from datetime import datetime, timezone
from schemas import FeatureVector, DetectionSignal, ThreatClass, DetectorType, Severity

class C2BeaconDetector:
    """
    Deterministic baseline detector for Botnet C2 Beaconing.
    Evaluates temporal features (periodicity and jitter) to identify highly regular
    and repetitive communication patterns indicative of beaconing behavior.
    """
    
    # --- Configuration / Constants ---
    MIN_OBSERVATIONS_REQUIRED = 5   # Need at least 5 intervals to confidently assess periodicity
    PERIODICITY_HIGH = 0.9          # High periodicity threshold
    JITTER_LOW = 10.0               # Low jitter percentage threshold (<=10%)

    def evaluate(self, fv: FeatureVector, observation_count: int = 0) -> DetectionSignal:
        """
        Evaluate the feature vector and produce a DetectionSignal.
        
        Args:
            fv: The FeatureVector containing TemporalFeatures.
            observation_count: The number of flows observed to generate the temporal features.
        """
        score = 0.0
        confidence = 0.0
        indicators = {}
        
        tf = fv.temporal_features
        
        # If temporal features are missing or incomplete, return a zero-confidence signal
        if not tf or tf.periodicity_score is None or tf.jitter_pct is None:
            indicators["reason"] = "Missing temporal features"
            return self._build_signal(fv, score, confidence, Severity.INFO, indicators)
            
        indicators["periodicity_score"] = tf.periodicity_score
        indicators["jitter_pct"] = tf.jitter_pct
        indicators["inter_arrival_mean_ms"] = tf.inter_arrival_mean_ms
        indicators["inter_arrival_std_ms"] = tf.inter_arrival_std_ms
        indicators["observation_count"] = observation_count
        
        # 1. Base Scoring based on Periodicity (0.0 to 1.0)
        # We linearly scale periodicity score (which is already in 0-1).
        # We'll give it a max contribution of 0.6
        score += min(tf.periodicity_score * 0.6, 0.6)
        
        # 2. Scoring based on Jitter (0.0 to 0.4)
        # If jitter is very low, we increase the score.
        # Max contribution of 0.4 when jitter is 0.0, scaling down to 0.0 when jitter >= 50%
        jitter_contribution = 0.0
        if tf.jitter_pct < 50.0:
            jitter_contribution = 0.4 * (1.0 - (tf.jitter_pct / 50.0))
        score += jitter_contribution
        
        indicators["score_component_periodicity"] = min(tf.periodicity_score * 0.6, 0.6)
        indicators["score_component_jitter"] = jitter_contribution
        
        # 3. Minimum Observation Handling
        if observation_count < self.MIN_OBSERVATIONS_REQUIRED:
            indicators["insufficient_observations_penalty"] = True
            indicators["reason"] = "Insufficient temporal observations for high confidence."
            # Limit score and confidence
            score = min(score, 0.4) 
            confidence = min(score, 0.3)
        else:
            # If we have enough observations, confidence scales closely with the score itself
            # C2 beaconing cannot be 100% confirmed by timing alone (legitimate apps poll too)
            # So max confidence is capped at 0.85
            confidence = min(score, 0.85)
            
        # 4. Determine Severity based on score and confidence
        if confidence >= 0.7:
            severity = Severity.HIGH
        elif confidence >= 0.4:
            severity = Severity.MEDIUM
        elif confidence >= 0.1:
            severity = Severity.LOW
        else:
            severity = Severity.INFO
            
        return self._build_signal(fv, score, confidence, severity, indicators)
        
    def _build_signal(self, fv: FeatureVector, score: float, confidence: float, 
                      severity: Severity, indicators: dict) -> DetectionSignal:
        signal_id = f"sig-c2-{uuid.uuid4().hex[:8]}"
        indicators["c2_suspicion_score"] = score
        now_ts = datetime.now(timezone.utc).isoformat()
        
        target_entity = None
        if fv.flow_id:
            try:
                target_entity = fv.flow_id.split("-")[1].split(":")[0]
            except Exception:
                pass

        decision_reasons = []
        tf = fv.temporal_features
        if tf and tf.periodicity_score is not None and tf.periodicity_score >= 0.8:
            decision_reasons.append("high_temporal_periodicity_observed")
        if tf and tf.jitter_pct is not None and tf.jitter_pct <= 15.0:
            decision_reasons.append("low_inter_arrival_jitter_beacon")
        if indicators.get("insufficient_observations_penalty"):
            decision_reasons.append("insufficient_observations_penalty_applied")

        observable_features = {
            "periodicity_score": getattr(tf, "periodicity_score", None) if tf else None,
            "jitter_pct": getattr(tf, "jitter_pct", None) if tf else None,
            "inter_arrival_mean_ms": getattr(tf, "inter_arrival_mean_ms", None) if tf else None,
            "inter_arrival_std_ms": getattr(tf, "inter_arrival_std_ms", None) if tf else None,
            "observation_count": indicators.get("observation_count", 0),
        }

        from schemas import SignalProvenance
        prov = SignalProvenance(
            detector_id="C2BeaconDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            window_start_iso=fv.timestamp_iso,
            window_end_iso=now_ts,
        )
                
        return DetectionSignal(
            signal_id=signal_id,
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            severity=severity,
            source_entity=fv.entity_ip,
            target_entity=target_entity,
            timestamp_iso=now_ts,
            indicators=indicators,
            detector_id="C2BeaconDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            provenance=prov,
        )
