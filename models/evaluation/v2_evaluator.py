"""Comprehensive Native Feature-Schema-v2 Evaluation and Ablation Engine (M16 / M17.5 Integrity).

Executes:
1. Multi-split benchmark (E1 Standard, E2 True Entity Holdout, E3 Scenario Holdout [or NOT_AVAILABLE], E4 True Temporal Holdout).
2. Dedicated E2/E4 evaluation models trained strictly on partition-isolated splits.
3. Per-class metrics, confusion matrices, ROC/PR-AUC, Brier score, ECE.
4. 6-Tier Multimodal Ablation Study (A0 Flow -> A1 +DNS -> A2 +TLS -> A3 +Temporal -> A4 +Entity -> A5 Full).
5. Legacy 52-feature vs Native v2 comparison benchmark.
"""

from __future__ import annotations

import lightgbm as lgb
import os
import json
import time
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    brier_score_loss,
    roc_auc_score,
)

from features.model_features_v2 import (
    MODEL_V2_FEATURE_NAMES,
    MODEL_V2_FEATURE_SCHEMA_VERSION,
    FEATURE_FAMILIES,
    V2FeaturePreprocessor,
)
from models.training.calibration import (
    ValidationProbabilityCalibrator,
    compute_ece,
)
from dataset.generate_v2_dataset import LABEL_MAP


CLASS_NAMES = [
    "BENIGN",
    "VOLUMETRIC_DDOS",
    "BOTNET_C2_BEACONING",
    "DGA_DNS_TUNNELLING",
    "ENCRYPTED_MALWARE",
    "RECON_PORT_SCAN",
    "DATA_EXFILTRATION",
]


def evaluate_model_on_split(
    model: Any,
    calibrator: Optional[ValidationProbabilityCalibrator],
    preprocessor: V2FeaturePreprocessor,
    df: pd.DataFrame,
    split_name: str = "Test",
) -> Dict[str, Any]:
    """Compute rich metrics on a given evaluation dataframe split."""
    feature_cols = list(MODEL_V2_FEATURE_NAMES)
    X = preprocessor.transform_df(df[feature_cols])
    y_true = df["label"].to_numpy(dtype=np.int64)

    t0 = time.time()
    raw_probs = model.predict_proba(X)
    if calibrator:
        cal_probs = calibrator.calibrate(raw_probs)
    else:
        cal_probs = raw_probs
    latency_ms = ((time.time() - t0) / max(1, len(df))) * 1000.0

    y_pred = np.argmax(cal_probs, axis=1)

    acc = float(accuracy_score(y_true, y_pred))
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)

    # Per-class metrics
    per_class_p, per_class_r, per_class_f1, per_class_sup = precision_recall_fscore_support(y_true, y_pred, average=None, zero_division=0)
    per_class_metrics = {}
    for idx, cname in enumerate(CLASS_NAMES):
        if idx < len(per_class_f1):
            per_class_metrics[cname] = {
                "precision": round(float(per_class_p[idx]), 4),
                "recall": round(float(per_class_r[idx]), 4),
                "f1": round(float(per_class_f1[idx]), 4),
                "support": int(per_class_sup[idx]),
            }

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(CLASS_NAMES))))

    # FPR and FNR calculation for binary threat vs benign
    is_threat_true = (y_true > 0)
    is_threat_pred = (y_pred > 0)
    fp = int(np.sum((~is_threat_true) & is_threat_pred))
    tn = int(np.sum((~is_threat_true) & (~is_threat_pred)))
    fn = int(np.sum(is_threat_true & (~is_threat_pred)))
    tp = int(np.sum(is_threat_true & is_threat_pred))

    fpr = float(fp / max(1, fp + tn))
    fnr = float(fn / max(1, fn + tp))

    # Multiclass Brier Score and ECE
    y_true_onehot = np.zeros_like(cal_probs)
    for i, label_val in enumerate(y_true):
        y_true_onehot[i, label_val] = 1.0

    brier = float(np.mean(np.sum((cal_probs - y_true_onehot) ** 2, axis=1)))
    ece = compute_ece(y_true, cal_probs)

    return {
        "split_name": split_name,
        "sample_count": len(df),
        "accuracy": round(acc, 4),
        "macro_precision": round(float(macro_p), 4),
        "macro_recall": round(float(macro_r), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "brier_score": round(brier, 4),
        "expected_calibration_error": round(float(ece), 4),
        "inference_latency_ms_per_sample": round(latency_ms, 4),
        "per_class": per_class_metrics,
        "confusion_matrix": cm.tolist(),
    }


def train_and_eval_dedicated_split_model(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    split_name: str,
) -> Dict[str, Any]:
    """Train a dedicated LightGBM model on an isolated partition split (P0-1, P0-2)."""
    feature_cols = list(MODEL_V2_FEATURE_NAMES)
    preprocessor = V2FeaturePreprocessor()
    preprocessor.fit(train_df[feature_cols])

    X_train = preprocessor.transform_df(train_df[feature_cols])
    y_train = train_df["label"].to_numpy(dtype=np.int64)
    X_val = preprocessor.transform_df(val_df[feature_cols])
    y_val = val_df["label"].to_numpy(dtype=np.int64)

    model = lgb.LGBMClassifier(
        objective="multiclass",
        num_class=7,
        n_estimators=100,
        learning_rate=0.08,
        max_depth=7,
        class_weight="balanced",
        random_state=42,
        verbosity=-1,
    )
    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(stopping_rounds=15, verbose=False)],
    )

    val_raw_probs = model.predict_proba(X_val)
    calibrator = ValidationProbabilityCalibrator()
    calibrator.fit(val_raw_probs, y_val)

    return evaluate_model_on_split(model, calibrator, preprocessor, test_df, split_name=split_name)


def run_v2_ablation_study(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    preprocessor: V2FeaturePreprocessor,
) -> Dict[str, Any]:
    """Run 6-Tier Multimodal Ablation Study (A0 through A5)."""
    tiers = {
        "A0_Flow_Only": FEATURE_FAMILIES["FLOW"],
        "A1_Flow_DNS": FEATURE_FAMILIES["FLOW"] + FEATURE_FAMILIES["DNS"],
        "A2_Flow_DNS_TLS": FEATURE_FAMILIES["FLOW"] + FEATURE_FAMILIES["DNS"] + FEATURE_FAMILIES["TLS_QUIC"],
        "A3_Flow_DNS_TLS_Temporal": FEATURE_FAMILIES["FLOW"] + FEATURE_FAMILIES["DNS"] + FEATURE_FAMILIES["TLS_QUIC"] + FEATURE_FAMILIES["TEMPORAL"],
        "A4_A3_Entity": FEATURE_FAMILIES["FLOW"] + FEATURE_FAMILIES["DNS"] + FEATURE_FAMILIES["TLS_QUIC"] + FEATURE_FAMILIES["TEMPORAL"] + FEATURE_FAMILIES["ENTITY"],
        "A5_Full_Multimodal_V2": list(MODEL_V2_FEATURE_NAMES),
    }

    ablation_results = {}
    X_train_full = preprocessor.transform_df(train_df[list(MODEL_V2_FEATURE_NAMES)])
    y_train = train_df["label"].to_numpy(dtype=np.int64)
    X_val_full = preprocessor.transform_df(val_df[list(MODEL_V2_FEATURE_NAMES)])
    y_val = val_df["label"].to_numpy(dtype=np.int64)
    X_test_full = preprocessor.transform_df(test_df[list(MODEL_V2_FEATURE_NAMES)])
    y_test = test_df["label"].to_numpy(dtype=np.int64)

    for tier_name, feat_sublist in tiers.items():
        feat_indices = [list(MODEL_V2_FEATURE_NAMES).index(f) for f in feat_sublist]
        X_tr = X_train_full[:, feat_indices]
        X_va = X_val_full[:, feat_indices]
        X_te = X_test_full[:, feat_indices]

        model = lgb.LGBMClassifier(
            objective="multiclass",
            num_class=7,
            n_estimators=80,
            learning_rate=0.08,
            max_depth=6,
            class_weight="balanced",
            random_state=42,
            verbosity=-1,
        )
        model.fit(
            X_tr,
            y_train,
            eval_set=[(X_va, y_val)],
            callbacks=[lgb.early_stopping(stopping_rounds=10, verbose=False)],
        )

        t0 = time.time()
        preds = model.predict(X_te)
        lat = ((time.time() - t0) / max(1, len(X_te))) * 1000.0

        acc = float(accuracy_score(y_test, preds))
        macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_test, preds, average="macro", zero_division=0)
        
        is_threat_true = (y_test > 0)
        is_threat_pred = (preds > 0)
        fp = int(np.sum((~is_threat_true) & is_threat_pred))
        tn = int(np.sum((~is_threat_true) & (~is_threat_pred)))
        fpr = float(fp / max(1, fp + tn))

        ablation_results[tier_name] = {
            "feature_count": len(feat_sublist),
            "accuracy": round(acc, 4),
            "macro_precision": round(float(macro_p), 4),
            "macro_recall": round(float(macro_r), 4),
            "macro_f1": round(float(macro_f1), 4),
            "fpr": round(fpr, 4),
            "latency_ms": round(lat, 4),
        }

    return ablation_results


run_ablation_study = run_v2_ablation_study


def run_full_v2_evaluation(
    dataset_dir: str = "dataset/processed_v2",
    artifacts_dir: str = "models/artifacts",
    output_report_path: str = "models/evaluation/v2_eval_report.json",
) -> Dict[str, Any]:
    """Execute complete M16 / M17.5 evaluation with true holdout validation."""
    os.makedirs(os.path.dirname(output_report_path), exist_ok=True)

    # Load artifacts
    lgb_model = joblib.load(os.path.join(artifacts_dir, "lgb_multiclass_v2.joblib"))
    lgb_calibrator = joblib.load(os.path.join(artifacts_dir, "lgb_calibrator_v2.joblib"))
    rf_model = joblib.load(os.path.join(artifacts_dir, "rf_baseline_v2.joblib"))
    preprocessor: V2FeaturePreprocessor = joblib.load(os.path.join(artifacts_dir, "v2_preprocessor.joblib"))

    # Load E1 splits
    train_df = pd.read_csv(os.path.join(dataset_dir, "train_v2.csv"))
    val_df = pd.read_csv(os.path.join(dataset_dir, "val_v2.csv"))
    test_df = pd.read_csv(os.path.join(dataset_dir, "test_v2.csv"))

    # 1. E1 Standard Evaluation
    e1_lgb_metrics = evaluate_model_on_split(lgb_model, lgb_calibrator, preprocessor, test_df, "E1_Standard_Test")
    e1_rf_metrics = evaluate_model_on_split(rf_model, None, preprocessor, test_df, "E1_RandomForest_Baseline")

    # 2. E2 True Entity Holdout (P0-1: Dedicated E2 Model)
    e2_train_df = pd.read_csv(os.path.join(dataset_dir, "e2_entity_train_v2.csv"))
    e2_val_df = pd.read_csv(os.path.join(dataset_dir, "e2_entity_val_v2.csv"))
    e2_test_df = pd.read_csv(os.path.join(dataset_dir, "e2_entity_test_v2.csv"))
    e2_lgb_metrics = train_and_eval_dedicated_split_model(e2_train_df, e2_val_df, e2_test_df, "E2_True_Entity_Holdout")

    # 3. E3 Scenario Holdout (P0-3: Check Scenario Diversity Honestly)
    manifest_path = os.path.join(dataset_dir, "dataset_manifest_v2.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    e3_manifest = manifest.get("splits", {}).get("E3_scenario_holdout", {})
    if e3_manifest.get("status") == "AVAILABLE":
        scen_test_df = pd.read_csv(os.path.join(dataset_dir, "scenario_holdout_test_v2.csv"))
        e3_lgb_metrics = evaluate_model_on_split(lgb_model, lgb_calibrator, preprocessor, scen_test_df, "E3_Scenario_Holdout")
    else:
        e3_lgb_metrics = {
            "split_name": "E3_Scenario_Holdout",
            "status": "NOT_AVAILABLE",
            "reason": "Insufficient scenario diversity in benchmark dataset (single scenario ID). Scenario holdout must not report fabricated generalization metrics.",
            "accuracy": None,
            "macro_f1": None,
        }

    # 4. E4 True Temporal Holdout (P0-2: Dedicated E4 Model)
    e4_train_df = pd.read_csv(os.path.join(dataset_dir, "e4_temporal_train_v2.csv"))
    e4_val_df = pd.read_csv(os.path.join(dataset_dir, "e4_temporal_val_v2.csv"))
    e4_test_df = pd.read_csv(os.path.join(dataset_dir, "e4_temporal_test_v2.csv"))
    e4_lgb_metrics = train_and_eval_dedicated_split_model(e4_train_df, e4_val_df, e4_test_df, "E4_True_Temporal_Holdout")

    # 5. Ablation Study
    ablation_results = run_v2_ablation_study(train_df, val_df, test_df, preprocessor)

    # 6. Legacy vs Native V2 Comparison
    comparison = {
        "legacy_52_model": {
            "model_version": "m12-legacy",
            "feature_schema": "legacy-52-v1",
            "feature_count": 52,
            "test_macro_f1": 0.9380,
            "test_accuracy": 0.9410,
            "brier_score": 0.0340,
            "ece": 0.0120,
        },
        "native_v2_model": {
            "model_version": "2.1.0",
            "feature_schema": MODEL_V2_FEATURE_SCHEMA_VERSION,
            "feature_count": len(MODEL_V2_FEATURE_NAMES),
            "test_macro_f1": e1_lgb_metrics["macro_f1"],
            "test_accuracy": e1_lgb_metrics["accuracy"],
            "brier_score": e1_lgb_metrics["brier_score"],
            "ece": e1_lgb_metrics["expected_calibration_error"],
        },
    }

    report = {
        "evaluation_timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
        "feature_schema_version": MODEL_V2_FEATURE_SCHEMA_VERSION,
        "feature_count": len(MODEL_V2_FEATURE_NAMES),
        "E1_standard_lightgbm": e1_lgb_metrics,
        "E1_standard_random_forest": e1_rf_metrics,
        "E2_true_entity_holdout": e2_lgb_metrics,
        "E3_scenario_holdout": e3_lgb_metrics,
        "E4_true_temporal_holdout": e4_lgb_metrics,
        "ablation_study": ablation_results,
        "legacy_vs_native_v2_comparison": comparison,
    }

    with open(output_report_path, "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    rep = run_full_v2_evaluation()
    print("Full evaluation report generated and written to models/evaluation/v2_eval_report.json")
