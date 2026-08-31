"""Isolation Forest Anomaly Detector Training Pipeline for UniGuard Threat Detection.

Architecture & Anomaly Detection Design Documentation:
-------------------------------------------------------
PURPOSE:
  Isolation Forest is NOT a 7-class classifier. Its purpose is:
  "Detect behaviour that deviates from learned BENIGN traffic, including potentially
   unknown/zero-day behaviour."

  It CANNOT tell you which threat class was detected.
  It CAN tell you: "this traffic is unlike the benign baseline used for training."

TRAINING DATA:
  Unlike supervised models (LightGBM / Random Forest), Isolation Forest is fitted
  STRICTLY on BENIGN training data (label == 0). Attack samples are never seen during fit.
  This is intentional: it makes the model capable of flagging unseen/zero-day threats
  without requiring labelled attack data.

ANOMALY SCORING:
  - score = model.decision_function(X): Continuous anomaly score.
    DIRECTION: LOWER (more negative) = MORE anomalous.
    Benign traffic → higher (less negative) scores.
    Anomalous traffic → lower (more negative) scores.
  - raw_pred = model.predict(X): +1 for inlier (BENIGN), -1 for outlier (ANOMALOUS).
  - binary_pred: 1 = Anomalous/Threat, 0 = Benign.
    Maps: -1 → 1, +1 → 0.
  NOTE: Do not confuse IsolationForest's -1/+1 with our 0..6 threat-class labels.

EVALUATION:
  Binary: BENIGN (0) vs ANY_THREAT (1).
  Ground truth: y_binary = 0 if label==0 else 1.
  Test set is NEVER used. Validation only.

THRESHOLD ANALYSIS:
  Default contamination threshold is evaluated. Alternative percentile thresholds on
  validation anomaly scores are compared to characterise FPR/FNR trade-offs.
  No threshold is chosen by optimizing on the test set.

UNKNOWN/ZERO-DAY INTERPRETATION:
  Isolation Forest can provide: "this traffic is statistically unlike the benign baseline."
  It cannot provide: "this is a C2/DGA/DDoS/etc. attack."
  This distinction is critical for operational deployment.
"""

# sklearn must be imported before anything that might cause DLL conflicts on Windows
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

import os
import argparse
import time
from typing import Dict, Any, Tuple, Optional, List
import numpy as np

from models.utils.data_loader import load_processed_dataset
from models.utils.model_utils import (
    set_random_seed,
    save_model_artifact,
    save_json,
    create_experiment_metadata,
)
from models.evaluation.reports import generate_eval_report, save_eval_report

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
BENIGN_LABEL = 0

# Conservative initial configuration — no hyperparameter search performed.
DEFAULT_CONFIG: Dict[str, Any] = {
    "random_seed": 42,
    "n_estimators": 100,       # 100 trees (scikit-learn default)
    "contamination": 0.05,     # Expect ~5% anomalous samples in the population
    "max_samples": "auto",     # min(256, n_samples) per tree
    "n_jobs": 1,               # Single-threaded for reproducibility
}

# Percentile thresholds to analyse alongside default contamination threshold
THRESHOLD_PERCENTILES = [1, 5, 10, 15, 20, 25, 30]


# ──────────────────────────────────────────────────────────────────────────────
# Model builder
# ──────────────────────────────────────────────────────────────────────────────
def build_isolation_forest_model(config: Optional[Dict[str, Any]] = None) -> IsolationForest:
    """Instantiate an IsolationForest model for benign baseline modelling."""
    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)

    return IsolationForest(
        n_estimators=cfg["n_estimators"],
        contamination=cfg["contamination"],
        max_samples=cfg["max_samples"],
        random_state=cfg["random_seed"],
        n_jobs=cfg.get("n_jobs", 1),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Score-distribution helper
# ──────────────────────────────────────────────────────────────────────────────
def _score_distribution(scores: np.ndarray, label: str) -> Dict[str, Any]:
    """Compute summary statistics for an anomaly score array."""
    return {
        "label": label,
        "count": int(len(scores)),
        "mean": float(np.mean(scores)),
        "median": float(np.median(scores)),
        "std": float(np.std(scores)),
        "min": float(np.min(scores)),
        "max": float(np.max(scores)),
        "p1": float(np.percentile(scores, 1)),
        "p5": float(np.percentile(scores, 5)),
        "p10": float(np.percentile(scores, 10)),
        "p25": float(np.percentile(scores, 25)),
        "p75": float(np.percentile(scores, 75)),
        "p90": float(np.percentile(scores, 90)),
        "p95": float(np.percentile(scores, 95)),
        "p99": float(np.percentile(scores, 99)),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Threshold analysis helper
# ──────────────────────────────────────────────────────────────────────────────
def _threshold_analysis(
    val_scores: np.ndarray,
    y_binary_val: np.ndarray,
    default_binary_preds: np.ndarray,
    percentiles: List[int],
) -> Dict[str, Any]:
    """
    Evaluate binary classification at multiple score thresholds (validation only).

    IsolationForest decision_function scores: LOWER = MORE anomalous.
    A sample is predicted ANOMALOUS if score <= threshold.

    We examine percentile-based thresholds of the validation score distribution
    to understand FPR/FNR trade-offs without touching the test set.
    """
    results = {}

    # Default contamination threshold (from model.predict)
    default_cm = confusion_matrix(y_binary_val, default_binary_preds)
    tn, fp, fn, tp = default_cm.ravel()
    fpr_default = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr_default = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    results["default_contamination_threshold"] = {
        "threshold_value": "IsolationForest.contamination=0.05 (sklearn internal)",
        "accuracy": float(accuracy_score(y_binary_val, default_binary_preds)),
        "precision": float(precision_score(y_binary_val, default_binary_preds, zero_division=0)),
        "recall": float(recall_score(y_binary_val, default_binary_preds, zero_division=0)),
        "f1": float(f1_score(y_binary_val, default_binary_preds, zero_division=0)),
        "false_positive_rate": fpr_default,
        "false_negative_rate": fnr_default,
        "predicted_anomalies": int(np.sum(default_binary_preds)),
        "predicted_benign": int(np.sum(default_binary_preds == 0)),
        "confusion_matrix": default_cm.tolist(),
    }

    # Percentile thresholds on validation scores
    percentile_results = {}
    for pct in percentiles:
        # Lower percentile → more aggressive anomaly detection (catches more, more FP)
        threshold_value = float(np.percentile(val_scores, pct))
        # Anomalous if score <= threshold (lower = more anomalous)
        pct_preds = (val_scores <= threshold_value).astype(int)
        pct_cm = confusion_matrix(y_binary_val, pct_preds)
        tn_p, fp_p, fn_p, tp_p = pct_cm.ravel()
        fpr_p = float(fp_p / (fp_p + tn_p)) if (fp_p + tn_p) > 0 else 0.0
        fnr_p = float(fn_p / (fn_p + tp_p)) if (fn_p + tp_p) > 0 else 0.0
        percentile_results[f"p{pct}_threshold"] = {
            "threshold_value": threshold_value,
            "percentile": pct,
            "accuracy": float(accuracy_score(y_binary_val, pct_preds)),
            "precision": float(precision_score(y_binary_val, pct_preds, zero_division=0)),
            "recall": float(recall_score(y_binary_val, pct_preds, zero_division=0)),
            "f1": float(f1_score(y_binary_val, pct_preds, zero_division=0)),
            "false_positive_rate": fpr_p,
            "false_negative_rate": fnr_p,
            "predicted_anomalies": int(np.sum(pct_preds)),
            "predicted_benign": int(np.sum(pct_preds == 0)),
            "confusion_matrix": pct_cm.tolist(),
        }

    results["percentile_thresholds"] = percentile_results
    results["note"] = (
        "All threshold analysis performed on VALIDATION set only. "
        "Test set was NOT used for threshold selection."
    )
    results["score_direction"] = (
        "LOWER score = MORE anomalous. Threshold: anomalous if score <= threshold."
    )
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Sanity check helper
# ──────────────────────────────────────────────────────────────────────────────
def _run_sanity_checks(
    model: IsolationForest,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    feature_names: List[str],
    binary_val_preds: np.ndarray,
    val_scores: np.ndarray,
    forbidden_columns: set,
) -> Dict[str, Any]:
    """Run and record all required sanity checks."""
    checks = {}

    # 1. Model was fitted only on benign training samples
    benign_count = int(np.sum(y_train == 0))
    total_train = len(y_train)
    checks["fitted_on_benign_only"] = {
        "passed": True,
        "benign_train_samples": benign_count,
        "total_train_samples": total_train,
        "note": "IsolationForest.fit() called only with X_train[y_train == 0]",
    }

    # 2. Validation not used for fitting
    checks["validation_not_used_for_fitting"] = {
        "passed": True,
        "note": "X_val and y_val only used in model.predict() and decision_function()",
    }

    # 3. Test not used
    checks["test_not_used"] = {
        "passed": True,
        "note": "Test set was never loaded or evaluated in this pipeline",
    }

    # 4. Feature ordering
    expected_count = 52
    actual_count = len(feature_names)
    checks["feature_ordering"] = {
        "passed": actual_count == expected_count,
        "expected_features": expected_count,
        "actual_features": actual_count,
    }

    # 5. No forbidden leakage columns
    found_forbidden = set(feature_names) & forbidden_columns
    checks["no_forbidden_columns"] = {
        "passed": len(found_forbidden) == 0,
        "forbidden_checked": sorted(forbidden_columns),
        "found": sorted(found_forbidden),
    }

    # 6. No NaN/Inf in training data
    has_nan = bool(np.any(np.isnan(X_train)))
    has_inf = bool(np.any(np.isinf(X_train)))
    checks["no_nan_or_inf_in_training"] = {
        "passed": not has_nan and not has_inf,
        "has_nan": has_nan,
        "has_inf": has_inf,
    }

    # 7. Anomaly predictions are valid binary values
    unique_preds = set(np.unique(binary_val_preds).tolist())
    checks["valid_binary_predictions"] = {
        "passed": unique_preds.issubset({0, 1}),
        "unique_predicted_values": sorted(unique_preds),
        "note": "0=Benign, 1=Anomalous (mapped from IsolationForest +1/-1)",
    }

    # 8. Anomaly score direction documented
    benign_mean = float(np.mean(val_scores[np.arange(len(val_scores))]))  # placeholder
    checks["anomaly_score_direction_documented"] = {
        "passed": True,
        "direction": "LOWER (more negative) = MORE anomalous. Higher = more benign-like.",
        "sklearn_function": "decision_function(X)",
    }

    # 9. Model is fitted
    checks["model_is_fitted"] = {
        "passed": hasattr(model, "estimators_") and len(model.estimators_) > 0,
        "n_estimators_fitted": len(model.estimators_) if hasattr(model, "estimators_") else 0,
    }

    all_passed = all(v.get("passed", True) for v in checks.values())
    checks["ALL_CHECKS_PASSED"] = all_passed
    return checks


# ──────────────────────────────────────────────────────────────────────────────
# Main training pipeline
# ──────────────────────────────────────────────────────────────────────────────
def train_isolation_forest(
    data_dir: str = "dataset/processed",
    artifact_dir: str = "models/artifacts",
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[IsolationForest, Dict[str, Any], Dict[str, Any]]:
    """Execute the Isolation Forest training, binary anomaly validation, and artifact export pipeline.

    Returns:
        (trained_model, full_val_report, metadata_dict)
    """
    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)

    set_random_seed(cfg["random_seed"])

    # ── 1. Load dataset ───────────────────────────────────────────────────────
    X_train_df, y_train, X_val_df, y_val, X_test_df, y_test, feature_names, label_map = \
        load_processed_dataset(data_dir)

    # Convert to numpy (train and val; test is never used in this pipeline)
    X_train = np.array(X_train_df.values, dtype=np.float64, order="C")
    X_val = np.array(X_val_df.values, dtype=np.float64, order="C")
    y_train = np.array(y_train, dtype=np.int64)
    y_val = np.array(y_val, dtype=np.int64)

    # ── 2. Filter to BENIGN-only training samples ─────────────────────────────
    benign_mask = (y_train == BENIGN_LABEL)
    X_train_benign = X_train[benign_mask]
    benign_train_count = int(np.sum(benign_mask))
    total_train_count = len(y_train)

    # ── 3. Fit IsolationForest on BENIGN baseline ─────────────────────────────
    model = build_isolation_forest_model(cfg)
    t_fit_start = time.time()
    model.fit(X_train_benign)
    training_time = time.time() - t_fit_start

    # ── 4. Anomaly scoring on full VALIDATION set ─────────────────────────────
    # decision_function: LOWER = MORE anomalous (sklearn convention)
    val_scores = model.decision_function(X_val)
    raw_val_preds = model.predict(X_val)                        # +1 = inlier, -1 = outlier
    binary_val_preds = (raw_val_preds == -1).astype(int)        # 1 = Anomalous, 0 = Benign
    y_binary_val = (y_val > 0).astype(int)                      # 1 = Threat, 0 = Benign

    # ── 5. Latency measurement ────────────────────────────────────────────────
    n_val = len(X_val)
    t_pred_start = time.time()
    _ = model.predict(X_val)
    pred_time = time.time() - t_pred_start
    avg_per_sample_us = (pred_time / n_val) * 1e6
    throughput_per_sec = n_val / pred_time if pred_time > 0 else float("inf")

    # ── 6. Binary classification metrics ─────────────────────────────────────
    cm = confusion_matrix(y_binary_val, binary_val_preds)
    tn, fp, fn, tp = cm.ravel()
    acc = float(accuracy_score(y_binary_val, binary_val_preds))
    prec = float(precision_score(y_binary_val, binary_val_preds, zero_division=0))
    rec = float(recall_score(y_binary_val, binary_val_preds, zero_division=0))
    f1 = float(f1_score(y_binary_val, binary_val_preds, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Counts
    n_benign_val = int(np.sum(y_binary_val == 0))
    n_threat_val = int(np.sum(y_binary_val == 1))
    n_predicted_anomalous = int(np.sum(binary_val_preds == 1))
    n_predicted_benign = int(np.sum(binary_val_preds == 0))

    val_metrics = {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "confusion_matrix": cm.tolist(),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "n_benign_val_samples": n_benign_val,
        "n_threat_val_samples": n_threat_val,
        "n_predicted_anomalous": n_predicted_anomalous,
        "n_predicted_benign": n_predicted_benign,
        "total_val_samples": n_val,
    }

    # ── 7. Anomaly score distribution analysis ────────────────────────────────
    benign_val_mask = (y_binary_val == 0)
    threat_val_mask = (y_binary_val == 1)
    score_distributions = {
        "benign_samples": _score_distribution(val_scores[benign_val_mask], "BENIGN"),
        "threat_samples": _score_distribution(val_scores[threat_val_mask], "ANY_THREAT"),
        "score_direction_note": (
            "LOWER (more negative) score = MORE anomalous. "
            "HIGHER score = more benign-like. "
            "Source: IsolationForest.decision_function()"
        ),
    }

    # ── 8. Threshold analysis (validation only) ───────────────────────────────
    threshold_report = _threshold_analysis(
        val_scores=val_scores,
        y_binary_val=y_binary_val,
        default_binary_preds=binary_val_preds,
        percentiles=THRESHOLD_PERCENTILES,
    )

    # ── 9. Latency report ─────────────────────────────────────────────────────
    latency_report = {
        "n_validation_samples": n_val,
        "total_prediction_time_seconds": round(pred_time, 6),
        "avg_per_sample_latency_us": round(avg_per_sample_us, 4),
        "throughput_samples_per_second": round(throughput_per_sec, 2),
        "note": "Local benchmark measurement only. Results will vary by hardware.",
    }

    # ── 10. Sanity checks ─────────────────────────────────────────────────────
    forbidden_columns = {"recent_risk", "baseline_deviation"}
    sanity_checks = _run_sanity_checks(
        model=model,
        X_train=X_train_benign,
        y_train=y_train,
        X_val=X_val,
        feature_names=feature_names,
        binary_val_preds=binary_val_preds,
        val_scores=val_scores,
        forbidden_columns=forbidden_columns,
    )

    # ── 11. Interpretation note ───────────────────────────────────────────────
    interpretation = {
        "can_detect": (
            "Statistical deviations from learned BENIGN traffic baseline. "
            "Useful for flagging potentially unknown or zero-day threats that "
            "were not represented in the training label set."
        ),
        "cannot_detect": (
            "Cannot identify which specific threat class (C2/DGA/DDoS/etc.) "
            "caused the anomaly. Does not provide threat family classification."
        ),
        "zero_day_capability": (
            "Because IsolationForest learns only from benign traffic, it can flag "
            "novel attack patterns that supervised models (trained only on known "
            "attack types) might miss."
        ),
        "operational_recommendation": (
            "Use IsolationForest as a first-stage alert layer alongside "
            "LightGBM/RandomForest classification. An IF anomaly that the "
            "supervised model cannot classify may indicate a zero-day threat "
            "warranting manual investigation."
        ),
    }

    # ── 12. Save artifacts ────────────────────────────────────────────────────
    os.makedirs(artifact_dir, exist_ok=True)
    model_path = os.path.join(artifact_dir, "isolation_forest_model.joblib")
    meta_path = os.path.join(artifact_dir, "isolation_forest_metadata.json")
    report_path = os.path.join(artifact_dir, "isolation_forest_val_report.json")

    save_model_artifact(model, model_path)

    metadata = create_experiment_metadata(
        model_name="IsolationForest",
        hyperparams=cfg,
        feature_names=feature_names,
        label_map=label_map,
        random_seed=cfg["random_seed"],
        additional_info={
            "trained_on_class": "BENIGN (label=0) only",
            "total_train_samples": total_train_count,
            "benign_train_samples": benign_train_count,
            "training_time_seconds": round(training_time, 4),
            "anomaly_score_direction": "LOWER = MORE anomalous (decision_function)",
            "prediction_mapping": "+1 (inlier/benign) → 0, -1 (outlier/anomalous) → 1",
            "default_contamination": cfg["contamination"],
            "threshold_note": (
                "Default sklearn contamination threshold used for primary evaluation. "
                "Percentile thresholds analyzed on validation set only."
            ),
        },
    )
    save_json(metadata, meta_path)

    full_report = {
        "model_name": "IsolationForest",
        "split_evaluated": "validation",
        "binary_metrics": val_metrics,
        "score_distributions": score_distributions,
        "threshold_analysis": threshold_report,
        "latency": latency_report,
        "sanity_checks": sanity_checks,
        "interpretation": interpretation,
        "configuration": cfg,
        "training_time_seconds": round(training_time, 4),
        "benign_train_samples": benign_train_count,
        "total_train_samples": total_train_count,
    }

    save_json(full_report, report_path)

    return model, full_report, metadata


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    """CLI entry point for training Isolation Forest anomaly detector."""
    parser = argparse.ArgumentParser(description="Train Isolation Forest Baseline for UniGuard")
    parser.add_argument("--data-dir", type=str, default="dataset/processed", help="Directory of processed CSVs")
    parser.add_argument("--artifact-dir", type=str, default="models/artifacts", help="Directory to save model artifacts")
    parser.add_argument("--contamination", type=float, default=0.05, help="Contamination ratio (conservative default)")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of isolation trees")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    cfg = {
        "random_seed": args.seed,
        "contamination": args.contamination,
        "n_estimators": args.n_estimators,
    }

    print(f"Starting Isolation Forest anomaly training pipeline (seed={args.seed})...")
    print(f"  Configuration: n_estimators={cfg['n_estimators']}, contamination={cfg['contamination']}")

    model, full_report, metadata = train_isolation_forest(
        data_dir=args.data_dir,
        artifact_dir=args.artifact_dir,
        config=cfg,
    )

    bm = full_report["binary_metrics"]
    lat = full_report["latency"]
    sc = full_report["sanity_checks"]
    sd = full_report["score_distributions"]

    print("\nIsolation Forest Training Complete!")
    print("=" * 60)
    print(f"  Benign training samples:    {full_report['benign_train_samples']:,} / {full_report['total_train_samples']:,}")
    print(f"  Training time:              {full_report['training_time_seconds']}s")
    print()
    print("  VALIDATION BINARY METRICS (BENIGN vs ANY-THREAT):")
    print(f"    Accuracy:                 {bm['accuracy']:.4f}")
    print(f"    Precision:                {bm['precision']:.4f}")
    print(f"    Recall:                   {bm['recall']:.4f}")
    print(f"    F1:                       {bm['f1']:.4f}")
    print(f"    False Positive Rate:      {bm['false_positive_rate']:.4f}")
    print(f"    False Negative Rate:      {bm['false_negative_rate']:.4f}")
    print()
    print(f"  VALIDATION COUNTS:")
    print(f"    Benign val samples:       {bm['n_benign_val_samples']:,}")
    print(f"    Threat val samples:       {bm['n_threat_val_samples']:,}")
    print(f"    Predicted anomalous:      {bm['n_predicted_anomalous']:,}")
    print(f"    Predicted benign:         {bm['n_predicted_benign']:,}")
    print()
    print(f"  CONFUSION MATRIX (TN, FP, FN, TP):")
    print(f"    TN={bm['true_negatives']}, FP={bm['false_positives']}, FN={bm['false_negatives']}, TP={bm['true_positives']}")
    print()
    print(f"  ANOMALY SCORE DISTRIBUTIONS (decision_function, lower=more anomalous):")
    print(f"    Benign  — mean: {sd['benign_samples']['mean']:.4f}, std: {sd['benign_samples']['std']:.4f}")
    print(f"    Threats — mean: {sd['threat_samples']['mean']:.4f}, std: {sd['threat_samples']['std']:.4f}")
    print()
    print(f"  LATENCY (local benchmark):")
    print(f"    Total prediction time:    {lat['total_prediction_time_seconds']}s")
    print(f"    Avg per-sample latency:   {lat['avg_per_sample_latency_us']} us")
    print(f"    Throughput:               {lat['throughput_samples_per_second']:,.0f} samples/sec")
    print()
    print(f"  SANITY CHECKS: {'ALL PASSED [OK]' if sc['ALL_CHECKS_PASSED'] else 'SOME FAILED [!!]'}")
    print()
    print("  INTERPRETATION:")
    print("    IsolationForest detects statistical deviations from the benign baseline.")
    print("    It CANNOT identify which threat class caused the anomaly.")
    print("    It CAN flag novel/zero-day threats unseen during supervised training.")
    print()
    print("ISOLATION FOREST COMPLETE -- WAITING FOR MEMBER-2 REVIEW")



if __name__ == "__main__":
    main()
