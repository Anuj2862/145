"""LightGBM Multiclass Classifier Training Pipeline for UniGuard Threat Detection.

Trains a 7-class LightGBM Gradient Boosted Decision Tree model on processed features.
Detects dependency availability, uses validation data for early stopping, and exports artifacts.
"""

# IMPORTANT: lightgbm MUST be imported before numpy, sklearn, and any module that imports
# sklearn (e.g. models.evaluation.metrics) to avoid Windows DLL initialization order crash
# (access violation in LGBM_DatasetSetField). This is a known LightGBM + sklearn interaction
# on Windows when sklearn initializes its BLAS/OpenMP handles before LightGBM's C extension.
try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    lgb = None
    LIGHTGBM_AVAILABLE = False

import os
import json
import argparse
import time
from typing import Dict, Any, Tuple, Optional, Any as AnyType

import numpy as np
import pandas as pd

from models.utils.model_utils import (
    set_random_seed,
    save_model_artifact,
    save_json,
    create_experiment_metadata,
)
from features.feature_contract import LEGACY_MODEL_FEATURE_NAMES, validate_feature_schema

FORBIDDEN_COLUMNS = {"recent_risk", "baseline_deviation"}
EXPECTED_FEATURE_COUNT = len(LEGACY_MODEL_FEATURE_NAMES)
EXPECTED_LABEL_RANGE = set(range(7))

DEFAULT_LABEL_MAP: Dict[str, int] = {
    "BENIGN": 0,
    "VOLUMETRIC_DDOS": 1,
    "BOTNET_C2_BEACONING": 2,
    "DGA_DNS_TUNNELLING": 3,
    "ENCRYPTED_MALWARE": 4,
    "RECON_PORT_SCAN": 5,
    "DATA_EXFILTRATION": 6,
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "random_seed": 42,
    "objective": "multiclass",
    "num_class": 7,
    "n_estimators": 100,
    "learning_rate": 0.05,
    "num_leaves": 31,
    "max_depth": -1,
    "early_stopping_rounds": 10,
    "num_threads": 1,
}


def check_lightgbm_available() -> None:
    """Verify that lightgbm is installed, raising a clear error if missing."""
    if not LIGHTGBM_AVAILABLE:
        raise ImportError(
            "LightGBM is not installed in the current Python environment.\n"
            "To train LightGBM models, please install it via:\n"
            "    pip install lightgbm\n"
            "All non-LightGBM features and baseline models remain fully operational."
        )


def build_lightgbm_model(config: Optional[Dict[str, Any]] = None) -> AnyType:
    """Instantiate a LightGBM LGBMClassifier with reproducible parameters."""
    check_lightgbm_available()

    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)

    n_jobs = cfg.get("num_threads", cfg.get("n_jobs", 1))
    if n_jobs == -1:
        n_jobs = 1

    return lgb.LGBMClassifier(
        objective=cfg["objective"],
        num_class=cfg["num_class"],
        n_estimators=cfg["n_estimators"],
        learning_rate=cfg["learning_rate"],
        num_leaves=cfg["num_leaves"],
        max_depth=cfg["max_depth"],
        random_state=cfg["random_seed"],
        n_jobs=n_jobs,
    )


def train_lightgbm(
    data_dir: str = "dataset/processed",
    artifact_dir: str = "models/artifacts",
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[AnyType, Dict[str, Any], Dict[str, Any]]:
    """Execute LightGBM training pipeline."""
    check_lightgbm_available()

    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)

    set_random_seed(cfg["random_seed"])

    train_path = os.path.join(data_dir, "train.csv")
    val_path = os.path.join(data_dir, "val.csv")
    test_path = os.path.join(data_dir, "test.csv")
    manifest_path = os.path.join(data_dir, "dataset_manifest.json")

    if not os.path.exists(train_path):
        raise FileNotFoundError(f"Processed train dataset split not found at '{train_path}'.")
    if not os.path.exists(val_path):
        raise FileNotFoundError(f"Processed val dataset split not found at '{val_path}'.")
    if not os.path.exists(test_path):
        raise FileNotFoundError(f"Processed test dataset split not found at '{test_path}'.")

    # Read CSVs directly into pandas DataFrames
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    if "label" not in train_df.columns:
        raise KeyError("Column 'label' missing from train split.")
    if "label" not in val_df.columns:
        raise KeyError("Column 'label' missing from val split.")

    feature_cols = [c for c in train_df.columns if c != "label"]

    forbidden = set(feature_cols) & FORBIDDEN_COLUMNS
    if forbidden:
        raise ValueError(f"Forbidden leakage column(s) in dataset: {forbidden}")
    if len(feature_cols) != EXPECTED_FEATURE_COUNT:
        raise ValueError(f"Dataset has {len(feature_cols)} features, expected {EXPECTED_FEATURE_COUNT}.")
    validate_feature_schema(
        actual_feature_names=feature_cols,
        expected_feature_names=LEGACY_MODEL_FEATURE_NAMES,
    ).raise_for_error()

    # Direct NumPy array allocation with C-contiguous layout
    X_train_np = np.array(train_df[feature_cols].values, dtype=np.float64, order="C")
    y_train_np = np.array(train_df["label"].values, dtype=np.float32, order="C")
    X_val_np = np.array(val_df[feature_cols].values, dtype=np.float64, order="C")
    y_val_np = np.array(val_df["label"].values, dtype=np.float32, order="C")

    label_map = DEFAULT_LABEL_MAP.copy()
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
            if "label_map" in manifest:
                label_map = manifest["label_map"]

    dtrain = lgb.Dataset(X_train_np, label=y_train_np, feature_name=feature_cols, free_raw_data=False)
    dval = lgb.Dataset(X_val_np, label=y_val_np, feature_name=feature_cols, reference=dtrain, free_raw_data=False)

    params = {
        "objective": cfg["objective"],
        "num_class": cfg["num_class"],
        "learning_rate": cfg["learning_rate"],
        "num_leaves": cfg["num_leaves"],
        "seed": cfg["random_seed"],
        "num_threads": 1,
        "verbose": -1,
    }

    callbacks = [lgb.early_stopping(stopping_rounds=cfg["early_stopping_rounds"], verbose=False)]

    t0 = time.time()
    booster = lgb.train(
        params,
        dtrain,
        num_boost_round=cfg["n_estimators"],
        valid_sets=[dval],
        callbacks=callbacks,
    )
    training_time = time.time() - t0

    best_iteration = int(booster.best_iteration)

    model = build_lightgbm_model(cfg)
    model._booster = booster
    model._n_classes = cfg["num_class"]
    model._classes = np.arange(cfg["num_class"])
    model.fitted_ = True

    val_proba = booster.predict(X_val_np, num_iteration=best_iteration)
    y_val_pred = np.argmax(val_proba, axis=1).astype(np.int32)
    y_val_int = y_val_np.astype(np.int32)

    from models.evaluation.metrics import compute_classification_metrics
    from models.evaluation.reports import generate_eval_report, save_eval_report

    label_names = list(label_map.keys())
    val_metrics = compute_classification_metrics(y_val_int, y_val_pred, label_names=label_names)

    os.makedirs(artifact_dir, exist_ok=True)
    model_path = os.path.join(artifact_dir, "lgb_multiclass_model.joblib")
    meta_path = os.path.join(artifact_dir, "lgb_multiclass_metadata.json")
    report_path = os.path.join(artifact_dir, "lgb_multiclass_val_report.json")

    save_model_artifact(booster, model_path)

    metadata = create_experiment_metadata(
        model_name="LGBMClassifier",
        hyperparams=cfg,
        feature_names=feature_cols,
        label_map=label_map,
        random_seed=cfg["random_seed"],
        additional_info={
            "best_iteration": best_iteration,
            "training_time_seconds": round(training_time, 4),
        },
    )
    save_json(metadata, meta_path)

    eval_report = generate_eval_report(
        model_name="LGBMClassifier",
        metrics=val_metrics,
        config=cfg,
        split_evaluated="validation",
    )
    save_eval_report(eval_report, report_path)

    return model, val_metrics, metadata


def main():
    """CLI entry point for training LightGBM model."""
    parser = argparse.ArgumentParser(description="Train LightGBM Model for UniGuard")
    parser.add_argument("--data-dir", type=str, default="dataset/processed", help="Directory of processed CSVs")
    parser.add_argument("--artifact-dir", type=str, default="models/artifacts", help="Directory to save model artifacts")
    parser.add_argument("--learning-rate", type=float, default=0.05, help="Learning rate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    cfg = {
        "random_seed": args.seed,
        "learning_rate": args.learning_rate,
    }

    try:
        check_lightgbm_available()
    except ImportError as e:
        print(f"Error: {e}")
        return

    print(f"Starting LightGBM training pipeline (seed={args.seed})...")
    model, val_metrics, metadata = train_lightgbm(
        data_dir=args.data_dir,
        artifact_dir=args.artifact_dir,
        config=cfg,
    )
    print("LightGBM Training Complete!")
    print(f"  Best Iteration:       {metadata['additional_info']['best_iteration']}")
    print(f"  Training Time:        {metadata['additional_info']['training_time_seconds']}s")
    print(f"  Validation Accuracy:  {val_metrics['accuracy']:.4f}")
    print(f"  Validation Macro F1:  {val_metrics['macro_f1']:.4f}")


if __name__ == "__main__":
    main()
