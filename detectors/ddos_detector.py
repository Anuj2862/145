import uuid
from datetime import datetime, timezone
from schemas import FeatureVector, DetectionSignal, ThreatClass, DetectorType, Severity

class DDoSBaselineDetector:
    """
    Deterministic baseline detector for Volumetric DDoS.
    Evaluates a FeatureVector for extremely high packet/byte velocities
    or TCP SYN-flooding characteristics.
    """
    
    # --- Configuration / Constants ---
    # These thresholds are temporary development baselines and will be 
    # calibrated on real datasets later.
    PPS_SUSPICIOUS_THRESHOLD = 1000.0   # packets per second
    PPS_CRITICAL_THRESHOLD = 5000.0     # packets per second
    SYN_RATIO_SUSPICIOUS = 0.5          # 50% of packets are SYN
    SYN_RATIO_CRITICAL = 0.8            # 80% of packets are SYN

    def __init__(self):
        pass
        
    def evaluate(self, fv: FeatureVector) -> DetectionSignal:
        """
        Evaluate the feature vector and produce a DetectionSignal.
        Returns a signal even if benign, where confidence will reflect the threat likelihood.
        """
        score = 0.0
        indicators = {}
        
        pps = fv.flow_features.packets_per_sec
        syn_ratio = fv.flow_features.syn_ratio
        
        # 1. Packet Rate Scoring (0.0 to 0.5 max contribution)
        if pps > self.PPS_CRITICAL_THRESHOLD:
            score += 0.5
            indicators["high_pps"] = pps
        elif pps > self.PPS_SUSPICIOUS_THRESHOLD:
            # Linear scaling between suspicious and critical
            pps_score = 0.5 * ((pps - self.PPS_SUSPICIOUS_THRESHOLD) / 
                              (self.PPS_CRITICAL_THRESHOLD - self.PPS_SUSPICIOUS_THRESHOLD))
            score += pps_score
            indicators["elevated_pps"] = pps
            
        # 2. SYN Ratio Scoring (0.0 to 0.5 max contribution)
        if syn_ratio is not None:
            if syn_ratio > self.SYN_RATIO_CRITICAL:
                score += 0.5
                indicators["critical_syn_ratio"] = syn_ratio
        # Determine specific decision reasons based on threshold triggers
        decision_reasons = []
        if pps > self.PPS_CRITICAL_THRESHOLD:
            decision_reasons.append("critical_packet_velocity_exceeded")
        elif pps > self.PPS_SUSPICIOUS_THRESHOLD:
            decision_reasons.append("suspicious_packet_velocity_observed")

        if syn_ratio is not None:
            if syn_ratio > self.SYN_RATIO_CRITICAL:
                decision_reasons.append("critical_tcp_syn_flood_ratio")
            elif syn_ratio > self.SYN_RATIO_SUSPICIOUS:
                decision_reasons.append("elevated_tcp_syn_ratio")

        observable_features = {
            "packets_per_sec": pps,
            "bytes_per_sec": fv.flow_features.bytes_per_sec,
            "syn_ratio": syn_ratio,
        }

        # Normalize score to [0.0, 1.0]
        confidence = min(max(score, 0.0), 1.0)

        # Determine Severity based on confidence
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
            
        signal_id = f"sig-ddos-{uuid.uuid4().hex[:8]}"
        now_ts = datetime.now(timezone.utc).isoformat()
        
        from schemas import SignalProvenance
        prov = SignalProvenance(
            detector_id="DDoSBaselineDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            window_start_iso=fv.timestamp_iso,
            window_end_iso=now_ts,
        )

        return DetectionSignal(
            signal_id=signal_id,
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            severity=severity,
            source_entity=fv.entity_ip,
            target_entity=fv.flow_id.split("-")[1].split(":")[0] if fv.flow_id else None,
            timestamp_iso=now_ts,
            indicators=indicators,
            detector_id="DDoSBaselineDetector",
            detector_version="1.0.0",
            decision_reason=decision_reasons,
            observable_features=observable_features,
            provenance=prov,
        )
