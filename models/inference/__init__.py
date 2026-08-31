"""Production ML Inference Layer for UniGuard Threat Detection System (Member 2).

Provides unified model loading, feature contract validation, classification, anomaly detection,
and DetectionSignal adapter mapping for downstream integration.
"""

from models.inference.ml_inference import (
    MLInferenceEngine,
    ClassificationResult,
    AnomalyResult,
    UnifiedMLResult,
    EXPECTED_FEATURE_NAMES,
    LABEL_MAPPING,
)
from models.inference.signal_adapter import (
    SignalAdapter,
    FeatureVectorAdapter,
    calculate_severity,
)

__all__ = [
    "MLInferenceEngine",
    "ClassificationResult",
    "AnomalyResult",
    "UnifiedMLResult",
    "SignalAdapter",
    "FeatureVectorAdapter",
    "calculate_severity",
    "EXPECTED_FEATURE_NAMES",
    "LABEL_MAPPING",
]
