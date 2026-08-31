from typing import List, Optional
import math
from datetime import datetime
from schemas import FlowEvent, TemporalFeatures

def extract_temporal_features(flows: List[FlowEvent]) -> TemporalFeatures:
    """
    Extract temporal features from a sequence of FlowEvents belonging to the same entity.
    
    Mathematical Definitions:
    - IAT (Inter-Arrival Time): Time difference in milliseconds between consecutive flow start_time_iso.
    - Mean IAT: Arithmetic mean of all IAT values.
    - IAT standard deviation: Sample standard deviation of IAT values.
    - Jitter percentage: (Std IAT / Mean IAT) * 100, representing relative variation.
    - Periodicity score: 1.0 - min(1.0, Std IAT / Mean IAT). Highly regular (low std dev relative to mean) approaches 1.0. Irregular approaches 0.0.
    """
    if not flows or len(flows) < 2:
        return TemporalFeatures(
            inter_arrival_mean_ms=None,
            inter_arrival_std_ms=None,
            periodicity_score=None,
            jitter_pct=None
        )

    # 1. Parse timestamps and sort chronologically
    valid_timestamps = []
    for f in flows:
        try:
            # Handle standard ISO format parsing. Replace 'Z' with '+00:00' for safe parsing if needed.
            ts_str = f.start_time_iso.replace('Z', '+00:00')
            dt = datetime.fromisoformat(ts_str)
            valid_timestamps.append(dt)
        except (ValueError, AttributeError):
            # Skip malformed timestamps
            continue
            
    if len(valid_timestamps) < 2:
        return TemporalFeatures(
            inter_arrival_mean_ms=None,
            inter_arrival_std_ms=None,
            periodicity_score=None,
            jitter_pct=None
        )

    valid_timestamps.sort()

    # 2. Calculate IAT in milliseconds
    iats = []
    for i in range(1, len(valid_timestamps)):
        delta = valid_timestamps[i] - valid_timestamps[i-1]
        iats.append(delta.total_seconds() * 1000.0)

    # 3. Calculate Mean IAT
    n = len(iats)
    mean_iat = sum(iats) / n

    # 4. Calculate IAT standard deviation
    if n > 1:
        variance = sum((x - mean_iat) ** 2 for x in iats) / (n - 1)
        std_iat = math.sqrt(variance)
    else:
        std_iat = 0.0

    # 5. Calculate Jitter percentage
    if mean_iat > 0:
        jitter_pct = (std_iat / mean_iat) * 100.0
    else:
        jitter_pct = 0.0

    # 6. Calculate Periodicity score
    if mean_iat > 0:
        cv = std_iat / mean_iat # Coefficient of variation
        periodicity_score = max(0.0, 1.0 - cv)
    else:
        # If mean is 0, they all arrived at the exact same time (0 variance). 
        # Highly "regular" mathematically but practically anomalous.
        periodicity_score = 1.0

    return TemporalFeatures(
        inter_arrival_mean_ms=mean_iat,
        inter_arrival_std_ms=std_iat,
        periodicity_score=periodicity_score,
        jitter_pct=jitter_pct
    )
