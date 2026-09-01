"""Model Utility Helpers for UniGuard ML Infrastructure.

Provides reproducible seed setting, model artifact serialization, configuration recording,
and metadata persistence.
"""

import os
import json
import random
from typing import Dict, Any, List, Optional
import numpy as np

from features.feature_contract import MODEL_FEATURE_SCHEMA_VERSION


def set_random_seed(seed: int = 42) -> None:
    """Set random seed across standard library and numpy for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)


def save_model_artifact(model: Any, filepath: str) -> str:
    """Serialize and save a trained model artifact using joblib."""
    import joblib
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    joblib.dump(model, filepath)
    return filepath


def load_model_artifact(filepath: str) -> Any:
    """Load a serialized model artifact using joblib."""
    import joblib
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Model artifact file not found at '{filepath}'")
    return joblib.load(filepath)


def save_json(data: Dict[str, Any], filepath: str) -> str:
    """Save a dictionary structure to a JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    return filepath


def load_json(filepath: str) -> Dict[str, Any]:
    """Load a dictionary structure from a JSON file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"JSON metadata file not found at '{filepath}'")
    with open(filepath, "r") as f:
        return json.load(f)


def create_experiment_metadata(
    model_name: str,
    hyperparams: Dict[str, Any],
    feature_names: List[str],
    label_map: Dict[str, int],
    random_seed: int = 42,
    additional_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construct a standardized experiment metadata record."""
    metadata = {
        "model_name": model_name,
        "model_version": "1.0.0",
        "random_seed": random_seed,
        "num_features": len(feature_names),
        "feature_names": feature_names,
        "feature_schema_version": MODEL_FEATURE_SCHEMA_VERSION,
        "compatibility_status": "current",
        "label_map": label_map,
        "hyperparameters": hyperparams,
    }
    if additional_info:
        metadata["additional_info"] = additional_info
    return metadata
