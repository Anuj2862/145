"""
Canonical System-Wide Version & Provenance Definitions (PS 26145 Enclave)
Provides a single source of truth for runtime metadata, feature contracts,
and loaded model artifact versions.
"""

from __future__ import annotations
from typing import Any, Dict, Final

# Canonical Feature Schema Version & Dimension
FEATURE_SCHEMA_VERSION: Final[str] = "feature-schema-v2.1.0"
FEATURE_COUNT: Final[int] = 56

# Canonical ML Model & Detector Versions
MODEL_VERSION: Final[str] = "v2.1.0-calibrated-lgb"
DETECTOR_VERSION: Final[str] = "v2.1.0"
ANOMALY_MODEL_VERSION: Final[str] = "v2.1.0-isolation-forest"
CALIBRATOR_VERSION: Final[str] = "v2.1.0-sigmoid-calibrator"

# Multi-Detector Mapping
DETECTOR_VERSIONS: Final[Dict[str, str]] = {
    "lightweight_ml": "v2.1.0",
    "deterministic": "v2.1.0",
    "isolation_forest": "v2.1.0",
}

# Multi-Model Artifact Mapping
MODEL_VERSIONS: Final[Dict[str, str]] = {
    "lightgbm": "v2.1.0-calibrated-lgb",
    "isolation_forest": "v2.1.0-isolation-forest",
    "random_forest": "v2.1.0-rf-baseline",
    "calibrator": "v2.1.0-sigmoid-calibrator",
}

# Legacy Feature Schema (for backward compatibility adapters only)
LEGACY_FEATURE_SCHEMA_VERSION: Final[str] = "feature-schema-v2.0.0"
LEGACY_MODEL_FEATURE_SCHEMA_VERSION: Final[str] = "legacy-52-from-feature-schema-v2.0.0"


def get_runtime_provenance() -> Dict[str, Any]:
    """Return dictionary of canonical runtime provenance and version metadata."""
    return {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "model_version": MODEL_VERSION,
        "detector_version": DETECTOR_VERSION,
        "anomaly_model_version": ANOMALY_MODEL_VERSION,
        "calibrator_version": CALIBRATOR_VERSION,
        "detector_versions": dict(DETECTOR_VERSIONS),
        "model_versions": dict(MODEL_VERSIONS),
    }
