import uuid
from datetime import datetime, timezone
from schemas import FeatureVector, DetectionSignal, ThreatClass, DetectorType, Severity

class EncryptedThreatDetector:
    """
    Deterministic baseline detector for Encrypted Malware communications.
    
    This detector operates strictly on observable metadata (TLS/QUIC handshake parameters)
    and behavioral context (timing/flow velocity). 
    
    PRIVACY GUARANTEE:
    - Does NOT decrypt TLS traffic.
    - Does NOT inspect payload content.
    - Does NOT use private keys or MITM interception.
    - Treats fingerprints (JA3/JA4) as identifiers, not automatic verdicts.
    - Performs no external domain or fingerprint reputation lookups.
    """
    
    def __init__(self):
        # Component Weights
        self.WEIGHT_METADATA_ANOMALY = 0.3
        self.WEIGHT_BEHAVIOURAL_CONTEXT = 0.7

    def evaluate(self, fv: FeatureVector) -> DetectionSignal:
        score = 0.0
        confidence = 0.0
        indicators = {}
        
        tf = fv.tls_features
        
        # 1. Verify TLS presence
        has_tls = tf and (tf.ja3_hash or tf.ja4_hash or tf.sni or tf.alpn)
        if not has_tls:
            indicators["reason"] = "No TLS metadata present"
            return self._build_signal(fv, 0.0, 0.0, Severity.INFO, indicators)
            
        # 2. Assess TLS metadata completeness & basic structural anomalies
        # Missing metadata is NOT inherently malicious, but certain patterns 
        # (like lacking SNI when negotiating complex modern ciphers/JA3) can be slightly suspicious
        # for standard web traffic. However, this is heavily contextual.
        available_fields = 0
        metadata_anomaly = 0.0
        
        if tf.ja3_hash: available_fields += 1
        if tf.ja4_hash: available_fields += 1
        if tf.sni: available_fields += 1
        if tf.alpn: available_fields += 1
        
        completeness_ratio = available_fields / 4.0
        indicators["tls_completeness"] = completeness_ratio
        indicators["has_ja3"] = bool(tf.ja3_hash)
        indicators["has_ja4"] = bool(tf.ja4_hash)
        indicators["has_sni"] = bool(tf.sni)
        indicators["has_alpn"] = bool(tf.alpn)
        
        # Structural anomaly heuristics (max 1.0)
        # E.g., Bare IP connections lack SNI. Some malware lacks SNI intentionally.
        if tf.ja3_hash and not tf.sni:
            metadata_anomaly += 0.5
        if tf.sni and not tf.alpn:
            metadata_anomaly += 0.2
            
        metadata_anomaly = min(metadata_anomaly, 1.0)
        indicators["comp_metadata_anomaly"] = metadata_anomaly
        
        # 3. Contextual Behavioural Scoring
        # An encrypted channel is normal. An encrypted channel that beacons with high periodicity
        # or transfers massive byte volumes (relative to time) is suspicious.
        behavioural_suspicion = 0.0
        
        if fv.temporal_features and fv.temporal_features.periodicity_score is not None:
            # High periodicity over TLS suggests encrypted C2 polling
            periodicity = fv.temporal_features.periodicity_score
            jitter = fv.temporal_features.jitter_pct or 0.0
            
            # Similar heuristic to C2 beaconing
            temp_score = min(periodicity * 0.7, 0.7)
            if jitter < 50.0:
                temp_score += 0.3 * (1.0 - (jitter / 50.0))
                
            behavioural_suspicion = min(temp_score, 1.0)
            indicators["context_temporal_used"] = True
            indicators["periodicity_score"] = periodicity
        else:
            indicators["context_temporal_used"] = False
            
        indicators["comp_behavioural"] = behavioural_suspicion
        
        # 4. Final Score Calculation
        score = (metadata_anomaly * self.WEIGHT_METADATA_ANOMALY) + \
                (behavioural_suspicion * self.WEIGHT_BEHAVIOURAL_CONTEXT)
                
        # 5. Confidence Calculation
        # Confidence requires evidence. Missing TLS metadata heavily penalizes confidence.
        # If we have very little TLS data, even a high score is low confidence.
        # Max confidence is 0.85 (deterministic baseline limit).
        confidence = score * completeness_ratio * 0.85
        
        # 6. Severity Logic
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
        signal_id = f"sig-enc-{uuid.uuid4().hex[:8]}"
        indicators["encrypted_threat_score"] = score
        
        target_entity = None
        if fv.flow_id:
            try:
                target_entity = fv.flow_id.split("-")[1].split(":")[0]
            except Exception:
                pass
                
        return DetectionSignal(
            signal_id=signal_id,
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            severity=severity,
            source_entity=fv.entity_ip,
            target_entity=target_entity,
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            indicators=indicators
        )
