"""Processed Dataset Loader and Data Quality Validator for UniGuard ML Pipelines.

Loads training, validation, and test datasets from dataset/processed/, verifying schema
integrity, feature count (52), range/numeric bounds, and zero-leakage enforcement.
"""

import os
import json
from typing import Tuple, List, Dict, Any
import numpy as np
import pandas as pd

from features.feature_contract import LEGACY_MODEL_FEATURE_NAMES, validate_feature_schema


EXPECTED_FEATURE_COUNT = len(LEGACY_MODEL_FEATURE_NAMES)

FORBIDDEN_COLUMNS = [
    "recent_risk",
    "baseline_deviation",
    "entity_id",
    "src_ip",
    "dst_ip",
    "timestamp",
    "scenario_id",
    "dataset_source",
    "split",
    "attack_stage",
]

EXPECTED_LABEL_RANGE = set(range(7))  # 0..6


def validate_feature_matrix(df: pd.DataFrame, split_name: str) -> List[str]:
    """Validate data quality, feature ordering, non-leakage, and numerical integrity."""
    # 1. Separate features from target label column if present
    feature_cols = [c for c in df.columns if c != "label"]

    # 2. Check for forbidden leakage / identifier columns
    forbidden_found = set(feature_cols).intersection(FORBIDDEN_COLUMNS)
    if forbidden_found:
        raise ValueError(
            f"Forbidden leakage/metadata column(s) detected in split '{split_name}': {forbidden_found}"
        )

    # 3. Check feature count
    if len(feature_cols) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            f"Dataset split '{split_name}' contains {len(feature_cols)} features, "
            f"expected exactly {EXPECTED_FEATURE_COUNT} features."
        )

    # 4. Check for NaN / missing values
    null_counts = df[feature_cols].isnull().sum().sum()
    if null_counts > 0:
        raise ValueError(
            f"Dataset split '{split_name}' contains {null_counts} missing/NaN values across features."
        )

    # 5. Check for Infinite values
    inf_counts = np.isinf(df[feature_cols].select_dtypes(include=[np.number])).sum().sum()
    if inf_counts > 0:
        raise ValueError(
            f"Dataset split '{split_name}' contains {inf_counts} infinite (Inf/-Inf) values."
        )

    # 6. Verify all feature columns are numeric
    non_numeric = [c for c in feature_cols if not np.issubdtype(df[c].dtype, np.number)]
    if non_numeric:
        raise ValueError(
            f"Non-numeric feature column(s) detected in split '{split_name}': {non_numeric}"
        )

    validate_feature_schema(
        actual_feature_names=feature_cols,
        expected_feature_names=LEGACY_MODEL_FEATURE_NAMES,
    ).raise_for_error()

    return feature_cols


def load_processed_dataset(
    data_dir: str = "dataset/processed"
) -> Tuple[pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray, List[str], Dict[str, int]]:
    """Load and validate train, val, and test feature matrices and target labels.
    
    Returns:
        (X_train, y_train, X_val, y_val, X_test, y_test, feature_names, label_map)
    """
    train_path = os.path.join(data_dir, "train.csv")
    val_path = os.path.join(data_dir, "val.csv")
    test_path = os.path.join(data_dir, "test.csv")
    manifest_path = os.path.join(data_dir, "dataset_manifest.json")

    for p in [train_path, val_path, test_path]:
        if not os.path.exists(p):
            raise FileNotFoundError(
                f"Processed dataset file not found at '{p}'. "
                f"Please run 'python -m dataset.prepare_dataset' first."
            )

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    # Validate feature matrices
    train_features = validate_feature_matrix(train_df, "train")
    val_features = validate_feature_matrix(val_df, "val")
    test_features = validate_feature_matrix(test_df, "test")

    # Verify deterministic feature ordering across all splits
    if train_features != val_features or train_features != test_features:
        raise ValueError("Feature ordering mismatch detected across train, val, and test splits.")

    # Validate labels
    for name, df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        if "label" not in df.columns:
            raise KeyError(f"Target column 'label' missing from '{name}' split.")
        labels = set(df["label"].unique())
        if not labels.issubset(EXPECTED_LABEL_RANGE):
            raise ValueError(
                f"Invalid label(s) detected in '{name}' split: {labels - EXPECTED_LABEL_RANGE}. "
                f"Expected integer labels in 0..6."
            )

    # Extract X and y
    X_train = train_df[train_features].copy()
    y_train = train_df["label"].to_numpy(dtype=np.int64)

    X_val = val_df[val_features].copy()
    y_val = val_df["label"].to_numpy(dtype=np.int64)

    X_test = test_df[test_features].copy()
    y_test = test_df["label"].to_numpy(dtype=np.int64)

    label_map = {
        "BENIGN": 0,
        "VOLUMETRIC_DDOS": 1,
        "BOTNET_C2_BEACONING": 2,
        "DGA_DNS_TUNNELLING": 3,
        "ENCRYPTED_MALWARE": 4,
        "RECON_PORT_SCAN": 5,
        "DATA_EXFILTRATION": 6,
    }

    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
            if "label_map" in manifest:
                label_map = manifest["label_map"]

    return X_train, y_train, X_val, y_val, X_test, y_test, train_features, label_map
