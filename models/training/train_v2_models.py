"""Native Feature-Schema-v2 Model Training and Validation Pipeline (M16).

Trains:
1. Model A: LightGBM Multiclass Classifier (Primary) with early stopping and class weighting.
2. Model B: Random Forest Multiclass Classifier (Baseline).
3. Model C: Isolation Forest Anomaly Detector (trained on Benign train data).
4. Probability Calibration: Fitted strictly on Validation split (Brier score & ECE evaluation).
Exports versioned artifacts into models/artifacts/ with full metadata registries.
"""

from __future__ import annotations

# Import lightgbm before sklearn to prevent Windows DLL initialization collision
import lightgbm as lgb

import os
import json
import time
import math
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    brier_score_loss,
    confusion_matrix,
    roc_auc_score,
)

from features.model_features_v2 import (
    MODEL_V2_FEATURE_NAMES,
    MODEL_V2_FEATURE_SCHEMA_VERSION,
    V2FeaturePreprocessor,
    V2PreprocessingState,
)
from dataset.generate_v2_dataset import LABEL_MAP
from models.training.calibration import (
    ValidationProbabilityCalibrator,
    compute_ece,
)


def train_all_v2_models(
    data_dir: str = "dataset/processed_v2",
    artifact_dir: str = "models/artifacts",
    random_seed: int = 42,
) -> Dict[str, Any]:
    """Train, calibrate, evaluate, and save all native v2 models."""
    os.makedirs(artifact_dir, exist_ok=True)

    # 1. Load datasets
    train_df = pd.read_csv(os.path.join(data_dir, "train_v2.csv"))
    val_df = pd.read_csv(os.path.join(data_dir, "val_v2.csv"))
    test_df = pd.read_csv(os.path.join(data_dir, "test_v2.csv"))

    feature_cols = list(MODEL_V2_FEATURE_NAMES)
    
    # 2. Fit train-only preprocessor
    preprocessor = V2FeaturePreprocessor()
    preprocessor.fit(train_df[feature_cols])

    X_train = preprocessor.transform_df(train_df[feature_cols])
    y_train = train_df["label"].to_numpy(dtype=np.int64)

    X_val = preprocessor.transform_df(val_df[feature_cols])
    y_val = val_df["label"].to_numpy(dtype=np.int64)

    X_test = preprocessor.transform_df(test_df[feature_cols])
    y_test = test_df["label"].to_numpy(dtype=np.int64)

    # Save Preprocessor Artifact
    joblib.dump(preprocessor, os.path.join(artifact_dir, "v2_preprocessor.joblib"))

    results: Dict[str, Any] = {}

    # -----------------------------------------------------------------------
    # 3. Model A: LightGBM Multiclass Classifier
    # -----------------------------------------------------------------------
    print("Training Model A: LightGBM v2 Multiclass Classifier...")
    t0 = time.time()
    lgb_clf = lgb.LGBMClassifier(
        objective="multiclass",
        num_class=7,
        n_estimators=100,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=-1,
        class_weight="balanced",
        random_state=random_seed,
        n_jobs=1,
    )
    lgb_clf.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(stopping_rounds=10, verbose=False)],
    )
    lgb_train_time = time.time() - t0

    # Probability Calibration on Validation Split
    print("Calibrating LightGBM probabilities on validation split...")
    val_probs_raw = lgb_clf.predict_proba(X_val)
    calibrator = ValidationProbabilityCalibrator()
    calibrator.fit(val_probs_raw, y_val)

    # Evaluate LightGBM on Validation & Test
    val_probs_cal = calibrator.calibrate(val_probs_raw)
    val_preds = np.argmax(val_probs_cal, axis=1)

    val_acc = float(accuracy_score(y_val, val_preds))
    val_prec, val_rec, val_f1, _ = precision_recall_fscore_support(y_val, val_preds, average="macro", zero_division=0)
    val_brier = float(brier_score_loss((y_val == val_preds).astype(int), np.max(val_probs_cal, axis=1)))
    val_ece = compute_ece(y_val, val_probs_cal)

    test_probs_raw = lgb_clf.predict_proba(X_test)
    test_probs_cal = calibrator.calibrate(test_probs_raw)
    test_preds = np.argmax(test_probs_cal, axis=1)
    test_acc = float(accuracy_score(y_test, test_preds))
    test_prec, test_rec, test_f1, _ = precision_recall_fscore_support(y_test, test_preds, average="macro", zero_division=0)

    # Save LightGBM Artifacts
    joblib.dump(lgb_clf, os.path.join(artifact_dir, "lgb_multiclass_v2.joblib"))
    joblib.dump(calibrator, os.path.join(artifact_dir, "lgb_calibrator_v2.joblib"))

    lgb_meta = {
        "model_id": "lgb_multiclass_v2",
        "model_name": "LGBMClassifier",
        "model_version": "2.1.0",
        "feature_schema_version": MODEL_V2_FEATURE_SCHEMA_VERSION,
        "num_features": len(MODEL_V2_FEATURE_NAMES),
        "feature_names": list(MODEL_V2_FEATURE_NAMES),
        "label_map": LABEL_MAP,
        "training_time_sec": round(lgb_train_time, 3),
        "calibration": {
            "method": "sigmoid",
            "val_brier_score": round(val_brier, 4),
            "val_ece": round(val_ece, 4),
        },
        "validation_metrics": {
            "accuracy": round(val_acc, 4),
            "macro_precision": round(val_prec, 4),
            "macro_recall": round(val_rec, 4),
            "macro_f1": round(val_f1, 4),
        },
        "test_metrics": {
            "accuracy": round(test_acc, 4),
            "macro_f1": round(test_f1, 4),
        },
        "created_at_iso": pd.Timestamp.now(tz="UTC").isoformat(),
    }
    with open(os.path.join(artifact_dir, "lgb_multiclass_v2_metadata.json"), "w") as f:
        json.dump(lgb_meta, f, indent=2)

    results["lightgbm"] = lgb_meta

    # -----------------------------------------------------------------------
    # 4. Model B: Random Forest Baseline Classifier
    # -----------------------------------------------------------------------
    print("Training Model B: Random Forest v2 Baseline Classifier...")
    t0 = time.time()
    rf_clf = RandomForestClassifier(
        n_estimators=50,
        max_depth=15,
        class_weight="balanced",
        random_state=random_seed,
        n_jobs=1,
    )
    rf_clf.fit(X_train, y_train)
    rf_train_time = time.time() - t0

    rf_val_preds = rf_clf.predict(X_val)
    rf_val_acc = accuracy_score(y_val, rf_val_preds)
    rf_val_f1 = precision_recall_fscore_support(y_val, rf_val_preds, average="macro", zero_division=0)[2]

    joblib.dump(rf_clf, os.path.join(artifact_dir, "rf_baseline_v2.joblib"))

    rf_meta = {
        "model_id": "rf_baseline_v2",
        "model_name": "RandomForestClassifier",
        "model_version": "2.1.0",
        "feature_schema_version": MODEL_V2_FEATURE_SCHEMA_VERSION,
        "num_features": len(MODEL_V2_FEATURE_NAMES),
        "feature_names": list(MODEL_V2_FEATURE_NAMES),
        "label_map": LABEL_MAP,
        "training_time_sec": round(rf_train_time, 3),
        "validation_metrics": {
            "accuracy": round(rf_val_acc, 4),
            "macro_f1": round(rf_val_f1, 4),
        },
        "created_at_iso": pd.Timestamp.now(tz="UTC").isoformat(),
    }
    with open(os.path.join(artifact_dir, "rf_baseline_v2_metadata.json"), "w") as f:
        json.dump(rf_meta, f, indent=2)

    results["random_forest"] = rf_meta

    # -----------------------------------------------------------------------
    # 5. Model C: Isolation Forest Anomaly Model (Trained on Benign Data)
    # -----------------------------------------------------------------------
    print("Training Model C: Isolation Forest v2 Anomaly Model...")
    t0 = time.time()
    benign_mask = (y_train == 0)
    X_train_benign = X_train[benign_mask]

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=random_seed,
        n_jobs=1,
    )
    iso_forest.fit(X_train_benign)
    if_train_time = time.time() - t0

    # Decision function on validation set
    val_scores = iso_forest.decision_function(X_val)
    val_anomalies = (iso_forest.predict(X_val) == -1)
    val_is_threat = (y_val > 0)
    threat_detection_rate = float(np.mean(val_anomalies[val_is_threat])) if np.sum(val_is_threat) > 0 else 0.0
    benign_false_alarm_rate = float(np.mean(val_anomalies[~val_is_threat])) if np.sum(~val_is_threat) > 0 else 0.0

    joblib.dump(iso_forest, os.path.join(artifact_dir, "isolation_forest_v2.joblib"))

    if_meta = {
        "model_id": "isolation_forest_v2",
        "model_name": "IsolationForest",
        "model_version": "2.1.0",
        "feature_schema_version": MODEL_V2_FEATURE_SCHEMA_VERSION,
        "num_features": len(MODEL_V2_FEATURE_NAMES),
        "feature_names": list(MODEL_V2_FEATURE_NAMES),
        "training_time_sec": round(if_train_time, 3),
        "validation_metrics": {
            "threat_detection_rate": round(threat_detection_rate, 4),
            "benign_false_alarm_rate": round(benign_false_alarm_rate, 4),
            "mean_anomaly_score": round(float(np.mean(val_scores)), 4),
        },
        "created_at_iso": pd.Timestamp.now(tz="UTC").isoformat(),
    }
    with open(os.path.join(artifact_dir, "isolation_forest_v2_metadata.json"), "w") as f:
        json.dump(if_meta, f, indent=2)

    results["isolation_forest"] = if_meta

    print("All native v2 models trained and registered successfully!")
    return results


if __name__ == "__main__":
    train_all_v2_models()
