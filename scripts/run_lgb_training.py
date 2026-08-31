"""Standalone LightGBM training script for UniGuard.

This script is designed to be run DIRECTLY as a subprocess to avoid
LightGBM 4.7.0 C++ OpenMP initialization issues when imported as a module
on Windows.

Usage:
    python scripts/run_lgb_training.py
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import argparse
import numpy as np
import pandas as pd
import lightgbm as lgb
import joblib

# ─── Constants ────────────────────────────────────────────────────────────────

FORBIDDEN_COLUMNS = {"recent_risk", "baseline_deviation"}
EXPECTED_FEATURE_COUNT = 52
EXPECTED_LABEL_RANGE = set(range(7))

DEFAULT_LABEL_MAP = {
    "BENIGN": 0,
    "VOLUMETRIC_DDOS": 1,
    "BOTNET_C2_BEACONING": 2,
    "DGA_DNS_TUNNELLING": 3,
    "ENCRYPTED_MALWARE": 4,
    "RECON_PORT_SCAN": 5,
    "DATA_EXFILTRATION": 6,
}


# ─── Data loading ─────────────────────────────────────────────────────────────

def load_split(csv_path, split_name):
    """Load and validate a processed CSV split, returning fresh numpy arrays."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"Processed dataset file not found: '{csv_path}'. "
            "Run 'python -m dataset.prepare_dataset' first."
        )

    df = pd.read_csv(csv_path)

    if "label" not in df.columns:
        raise KeyError(f"Column 'label' missing from '{split_name}' split.")

    feature_cols = [c for c in df.columns if c != "label"]

    forbidden_found = set(feature_cols) & FORBIDDEN_COLUMNS
    if forbidden_found:
        raise ValueError(f"Forbidden leakage column(s) in '{split_name}': {forbidden_found}")

    if len(feature_cols) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            f"'{split_name}' has {len(feature_cols)} features, expected {EXPECTED_FEATURE_COUNT}."
        )

    labels = set(df["label"].unique())
    if not labels.issubset(EXPECTED_LABEL_RANGE):
        raise ValueError(f"Invalid label(s) in '{split_name}': {labels - EXPECTED_LABEL_RANGE}")

    X = np.array(df[feature_cols].values, dtype=np.float64, order="C")
    y = np.array(df["label"].values, dtype=np.float32, order="C")

    return X, y, feature_cols


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train LightGBM Model for UniGuard")
    parser.add_argument("--data-dir", default="dataset/processed")
    parser.add_argument("--artifact-dir", default="models/artifacts")
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--early-stopping-rounds", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"LightGBM version: {lgb.__version__}")
    print(f"Seed: {args.seed}")
    print(f"Data dir: {args.data_dir}")
    print(f"Artifact dir: {args.artifact_dir}")

    import random
    random.seed(args.seed)
    np.random.seed(args.seed)

    # ── Load data ─────────────────────────────────────────────────────────────
    train_path = os.path.join(args.data_dir, "train.csv")
    val_path = os.path.join(args.data_dir, "val.csv")
    test_path = os.path.join(args.data_dir, "test.csv")
    manifest_path = os.path.join(args.data_dir, "dataset_manifest.json")

    print("Loading train split...")
    X_train, y_train, feature_names = load_split(train_path, "train")
    print("Loading val split...")
    X_val, y_val, _ = load_split(val_path, "val")
    print("Validating test split (not used for training)...")
    load_split(test_path, "test")

    print(f"X_train: {X_train.shape}, y_train: {y_train.shape}")
    print(f"X_val:   {X_val.shape}, y_val: {y_val.shape}")

    label_map = DEFAULT_LABEL_MAP.copy()
    if os.path.exists(manifest_path):
        with open(manifest_path) as f:
            manifest = json.load(f)
            if "label_map" in manifest:
                label_map = manifest["label_map"]

    # ── Build datasets ────────────────────────────────────────────────────────
    print("Building lgb.Dataset objects...")
    dtrain = lgb.Dataset(X_train, label=y_train, feature_name=feature_names, free_raw_data=False)
    dval = lgb.Dataset(X_val, label=y_val, reference=dtrain, free_raw_data=False)

    # ── Train ─────────────────────────────────────────────────────────────────
    params = {
        "objective": "multiclass",
        "num_class": 7,
        "learning_rate": args.learning_rate,
        "num_leaves": 31,
        "seed": args.seed,
        "num_threads": 1,
        "verbose": -1,
    }

    callbacks = [lgb.early_stopping(stopping_rounds=args.early_stopping_rounds, verbose=False)]

    print(f"Training LightGBM (max {args.n_estimators} rounds)...")
    t0 = time.time()
    booster = lgb.train(
        params,
        dtrain,
        num_boost_round=args.n_estimators,
        valid_sets=[dval],
        callbacks=callbacks,
    )
    training_time = time.time() - t0
    best_iteration = booster.best_iteration

    print(f"Training complete in {training_time:.2f}s, best iteration: {best_iteration}")

    # ── Evaluate on validation ─────────────────────────────────────────────────
    print("Evaluating on validation set...")
    val_proba = booster.predict(X_val, num_iteration=best_iteration)
    y_val_pred = np.argmax(val_proba, axis=1).astype(np.int32)
    y_val_int = y_val.astype(np.int32)

    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    )

    accuracy = accuracy_score(y_val_int, y_val_pred)
    macro_p = precision_score(y_val_int, y_val_pred, average="macro", zero_division=0)
    macro_r = recall_score(y_val_int, y_val_pred, average="macro", zero_division=0)
    macro_f1 = f1_score(y_val_int, y_val_pred, average="macro", zero_division=0)
    weighted_p = precision_score(y_val_int, y_val_pred, average="weighted", zero_division=0)
    weighted_r = recall_score(y_val_int, y_val_pred, average="weighted", zero_division=0)
    weighted_f1 = f1_score(y_val_int, y_val_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_val_int, y_val_pred).tolist()

    label_names = list(label_map.keys())
    per_class_p = precision_score(y_val_int, y_val_pred, average=None, zero_division=0)
    per_class_r = recall_score(y_val_int, y_val_pred, average=None, zero_division=0)
    per_class_f1 = f1_score(y_val_int, y_val_pred, average=None, zero_division=0)
    per_class_metrics = {}
    for i, cls_name in enumerate(label_names):
        per_class_metrics[cls_name] = {
            "precision": float(per_class_p[i]),
            "recall": float(per_class_r[i]),
            "f1": float(per_class_f1[i]),
        }

    val_metrics = {
        "accuracy": float(accuracy),
        "macro_precision": float(macro_p),
        "macro_recall": float(macro_r),
        "macro_f1": float(macro_f1),
        "weighted_precision": float(weighted_p),
        "weighted_recall": float(weighted_r),
        "weighted_f1": float(weighted_f1),
        "confusion_matrix": cm,
        "per_class_metrics": per_class_metrics,
    }

    # ── Print results ─────────────────────────────────────────────────────────
    print(f"\n=== LIGHTGBM VALIDATION METRICS ===")
    print(f"Accuracy:          {accuracy:.4f}")
    print(f"Macro Precision:   {macro_p:.4f}")
    print(f"Macro Recall:      {macro_r:.4f}")
    print(f"Macro F1:          {macro_f1:.4f}")
    print(f"Weighted Precision:{weighted_p:.4f}")
    print(f"Weighted Recall:   {weighted_r:.4f}")
    print(f"Weighted F1:       {weighted_f1:.4f}")

    print("\n=== PER-CLASS METRICS ===")
    for cls_name, m in per_class_metrics.items():
        print(f"  {cls_name:<24} P:{m['precision']:.4f}  R:{m['recall']:.4f}  F1:{m['f1']:.4f}")

    print("\n=== CONFUSION MATRIX ===")
    for row in cm:
        print(" ", row)

    # ── Feature importance ────────────────────────────────────────────────────
    gain_imp = booster.feature_importance(importance_type="gain")
    split_imp = booster.feature_importance(importance_type="split")
    total_gain = gain_imp.sum()

    feat_imp = sorted(
        zip(feature_names, gain_imp, split_imp),
        key=lambda x: x[1], reverse=True
    )

    print("\n=== TOP 20 FEATURES BY GAIN ===")
    for fn, g, s in feat_imp[:20]:
        print(f"  {fn:<36} gain={g:.1f} ({100*g/total_gain:.2f}%)  split={s}")

    # Domain summary
    domains = {
        "Flow": {"duration", "total_packets", "total_bytes", "bytes_forward", "bytes_backward",
                 "packets_per_sec", "bytes_per_sec", "packet_size_mean"},
        "Temporal": {"iat_mean", "iat_std", "periodicity_score", "jitter", "burst_rate"},
        "DNS": {"dns_query_count", "unique_domain_count", "domain_length_mean",
                "domain_entropy", "ngram_score", "dns_query_rate"},
        "TLS": {"session_resumption", "tls_packet_size_mean"},
        "Recon": {"unique_dst_ips", "unique_dst_ports", "connection_attempt_rate",
                  "failed_connection_ratio", "fan_out"},
        "Exfiltration": {"outbound_bytes", "outbound_rate", "upload_download_ratio",
                         "destination_count", "large_transfer_score"},
        "Entity Context": {"entity_flow_count_1m", "entity_unique_destinations_1m",
                           "entity_new_destinations_5m", "entity_avg_connection_interval",
                           "entity_periodicity"},
    }

    print("\n=== DOMAIN IMPORTANCES (GAIN %) ===")
    for dom_name, dom_feats in domains.items():
        dom_gain = sum(g for fn, g, s in feat_imp if fn in dom_feats or
                       fn.startswith("ja3_") and dom_name == "TLS" or
                       fn.startswith("ja4_") and dom_name == "TLS" or
                       fn.startswith("tls_version_") and dom_name == "TLS")
        print(f"  {dom_name:<16}: {100*dom_gain/total_gain:.2f}%")

    # Synthetic shortcut audit
    print("\n=== SYNTHETIC SHORTCUT AUDIT ===")
    audit_feats = ["total_packets", "periodicity_score", "entity_periodicity",
                   "fan_out", "large_transfer_score"]
    for fn in audit_feats:
        row = next(((n, g, s) for n, g, s in feat_imp if n == fn), None)
        if row:
            print(f"  {row[0]:<28} Gain%: {100*row[1]/total_gain:.2f}")
    ja3_g = sum(g for fn, g, s in feat_imp if fn.startswith("ja3_"))
    ja4_g = sum(g for fn, g, s in feat_imp if fn.startswith("ja4_"))
    print(f"  {'JA3 one-hot total':<28} Gain%: {100*ja3_g/total_gain:.2f}")
    print(f"  {'JA4 one-hot total':<28} Gain%: {100*ja4_g/total_gain:.2f}")

    # Confusion pairs
    print("\n=== TOP CONFUSION PAIRS ===")
    pairs = []
    for i in range(7):
        for j in range(7):
            if i != j and cm[i][j] > 0:
                pairs.append((label_names[i], label_names[j], cm[i][j]))
    pairs.sort(key=lambda x: x[2], reverse=True)
    for true_l, pred_l, cnt in pairs[:5]:
        print(f"  {true_l} -> {pred_l} : {cnt} samples")

    # Latency
    print("\n=== LATENCY BENCHMARK ===")
    t_pred = time.time()
    _ = booster.predict(X_val, num_iteration=best_iteration)
    t_pred = time.time() - t_pred
    print(f"  Total validation prediction time: {t_pred:.4f}s")
    print(f"  Per-sample latency: {(t_pred/len(X_val))*1e6:.2f} us")
    print(f"  Throughput: {len(X_val)/t_pred:.1f} samples/sec")

    # Sanity checks
    print("\n=== SANITY CHECKS ===")
    print(f"  Predictions in 0..6: {set(y_val_pred).issubset(set(range(7)))}")
    print(f"  Proba shape == (18018, 7): {val_proba.shape == (18018, 7)}")
    print(f"  Proba in [0, 1]: {(val_proba >= 0).all() and (val_proba <= 1).all()}")
    print(f"  Proba rows sum ~1: {np.isclose(val_proba.sum(axis=1), 1.0).all()}")
    print(f"  recent_risk absent: {'recent_risk' not in feature_names}")
    print(f"  baseline_deviation absent: {'baseline_deviation' not in feature_names}")

    # ── Save artifacts ────────────────────────────────────────────────────────
    os.makedirs(args.artifact_dir, exist_ok=True)
    model_path = os.path.join(args.artifact_dir, "lgb_multiclass_model.joblib")
    meta_path = os.path.join(args.artifact_dir, "lgb_multiclass_metadata.json")
    report_path = os.path.join(args.artifact_dir, "lgb_multiclass_val_report.json")

    joblib.dump(booster, model_path)
    print(f"\n  Model saved: {model_path}")

    metadata = {
        "model_name": "LGBMBooster",
        "random_seed": args.seed,
        "num_features": len(feature_names),
        "feature_names": feature_names,
        "label_map": label_map,
        "hyperparameters": {
            "objective": "multiclass",
            "num_class": 7,
            "n_estimators": args.n_estimators,
            "learning_rate": args.learning_rate,
            "early_stopping_rounds": args.early_stopping_rounds,
            "num_leaves": 31,
        },
        "additional_info": {
            "best_iteration": best_iteration,
            "training_time_seconds": round(training_time, 4),
            "api": "lgb.train (low-level)",
            "lgb_version": lgb.__version__,
        },
    }
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata saved: {meta_path}")

    report = {
        "model_name": "LGBMBooster",
        "split_evaluated": "validation",
        "metrics": val_metrics,
        "config": metadata["hyperparameters"],
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report saved: {report_path}")

    print("\n=== TRAINING SUMMARY ===")
    print(f"  Best Iteration:       {best_iteration}")
    print(f"  Training Time:        {training_time:.4f}s")
    print(f"  Validation Accuracy:  {accuracy:.4f}")
    print(f"  Validation Macro F1:  {macro_f1:.4f}")
    print(f"  Artifact:             {model_path}")


if __name__ == "__main__":
    main()
