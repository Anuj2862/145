import uuid
from datetime import datetime, timezone
from schemas import FeatureVector, DetectionSignal, ThreatClass, DetectorType, Severity

class DNSAnomalyDetector:
    """
    Deterministic baseline detector for DGA (Domain Generation Algorithms)
    and DNS Tunnelling behaviours.
    Evaluates DNSFeatures utilizing configurable heuristic thresholds.
    """
    
    # --- Configuration / Constants ---
    # These thresholds are temporary development baselines and will be 
    # calibrated against real benchmark datasets in later milestones.
    
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
    
    # Subdomain count thresholds (absolute count of queries with subdomains in window)
    SUBDOMAIN_MIN_SUSPICIOUS = 5.0
    SUBDOMAIN_MAX_CRITICAL = 30.0

    # Component weights (Relative importance)
    WEIGHT_ENTROPY = 0.3
    WEIGHT_LENGTH = 0.25
    WEIGHT_NXDOMAIN = 0.2
    WEIGHT_TXT = 0.15
    WEIGHT_SUBDOMAIN = 0.1

    def __init__(self):
        pass
        
    def _normalize(self, value: float, min_val: float, max_val: float) -> float:
        """Normalize a raw value to a [0.0, 1.0] suspicion score."""
        if value <= min_val:
            return 0.0
        if value >= max_val:
            return 1.0
        return (value - min_val) / (max_val - min_val)

    def evaluate(self, fv: FeatureVector) -> DetectionSignal:
        """
        Evaluate the feature vector for DNS threats and produce a DetectionSignal.
        """
        score = 0.0
        confidence = 0.0
        indicators = {}
        
        df = fv.dns_features
        
        # Safely handle missing entirely or all-None features
        if not df:
            indicators["reason"] = "No DNS features present"
            return self._build_signal(fv, 0.0, 0.0, Severity.INFO, indicators)
            
        valid_weight_sum = 0.0
        weighted_score_sum = 0.0
        
        # 1. Entropy Component
        if df.entropy_mean is not None:
            c_score = self._normalize(df.entropy_mean, self.ENTROPY_MIN_SUSPICIOUS, self.ENTROPY_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_ENTROPY
            valid_weight_sum += self.WEIGHT_ENTROPY
            indicators["entropy_mean"] = df.entropy_mean
            indicators["comp_entropy"] = c_score

        # 2. Query Length Component
        if df.query_length_mean is not None:
            c_score = self._normalize(df.query_length_mean, self.LENGTH_MIN_SUSPICIOUS, self.LENGTH_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_LENGTH
            valid_weight_sum += self.WEIGHT_LENGTH
            indicators["query_length_mean"] = df.query_length_mean
            indicators["comp_length"] = c_score
            
        # 3. NXDOMAIN Component
        if df.nxdomain_count is not None: # It's an int, defaults to 0
            c_score = self._normalize(float(df.nxdomain_count), self.NXDOMAIN_MIN_SUSPICIOUS, self.NXDOMAIN_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_NXDOMAIN
            valid_weight_sum += self.WEIGHT_NXDOMAIN
            indicators["nxdomain_count"] = df.nxdomain_count
            indicators["comp_nxdomain"] = c_score
            
        # 4. TXT Record Ratio Component
        if df.txt_record_ratio is not None:
            c_score = self._normalize(df.txt_record_ratio, self.TXT_RATIO_MIN_SUSPICIOUS, self.TXT_RATIO_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_TXT
            valid_weight_sum += self.WEIGHT_TXT
            indicators["txt_record_ratio"] = df.txt_record_ratio
            indicators["comp_txt"] = c_score
            
        # 5. Subdomain Count Component
        if df.subdomain_count is not None:
            c_score = self._normalize(float(df.subdomain_count), self.SUBDOMAIN_MIN_SUSPICIOUS, self.SUBDOMAIN_MAX_CRITICAL)
            weighted_score_sum += c_score * self.WEIGHT_SUBDOMAIN
            valid_weight_sum += self.WEIGHT_SUBDOMAIN
            indicators["subdomain_count"] = df.subdomain_count
            indicators["comp_subdomain"] = c_score

        # Final Score Calculation
        if valid_weight_sum > 0.0:
            # Scale score by the available valid evidence weight so missing fields don't
            # unfairly drag the score to 0, but rather reduce confidence.
            score = weighted_score_sum / valid_weight_sum
            
            # Confidence logic:
            # Maximum achievable confidence scales with how much valid evidence weight was available.
            # E.g., if only NXDOMAIN was present (weight 0.2), max confidence is low.
            # Also, since it's a baseline heuristic, max possible confidence is capped at 0.9.
            max_confidence_possible = valid_weight_sum * 0.9
            confidence = score * max_confidence_possible
        else:
            score = 0.0
            confidence = 0.0
            indicators["reason"] = "All DNS features were None/empty"
            
        # Determine Severity based on confidence
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
        signal_id = f"sig-dns-{uuid.uuid4().hex[:8]}"
        indicators["dns_suspicion_score"] = score
        
        target_entity = None
        if fv.flow_id:
            try:
                target_entity = fv.flow_id.split("-")[1].split(":")[0]
            except Exception:
                pass
                
        return DetectionSignal(
            signal_id=signal_id,
            threat_class=ThreatClass.DGA_DNS_TUNNELLING,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=confidence,
            severity=severity,
            source_entity=fv.entity_ip,
            target_entity=target_entity,
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            indicators=indicators
        )
