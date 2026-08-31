"""Random Forest Baseline Classifier Training Pipeline for UniGuard Threat Detection.

Trains a 7-class RandomForestClassifier on processed network flow and metadata features.
This module is fully reproducible, Colab-compatible, and importable without auto-execution.
"""

import os
import argparse
from typing import Dict, Any, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier

from models.utils.data_loader import load_processed_dataset
from models.utils.model_utils import (
    set_random_seed,
    save_model_artifact,
    save_json,
    create_experiment_metadata,
)
from models.evaluation.metrics import compute_classification_metrics
from models.evaluation.reports import generate_eval_report, save_eval_report

DEFAULT_CONFIG: Dict[str, Any] = {
    "random_seed": 42,
    "n_estimators": 100,
    "max_depth": 15,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "n_jobs": -1,
}


def build_random_forest_model(config: Optional[Dict[str, Any]] = None) -> RandomForestClassifier:
    """Instantiate a RandomForestClassifier with reproducible hyperparameters."""
    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)

    return RandomForestClassifier(
        n_estimators=cfg["n_estimators"],
        max_depth=cfg["max_depth"],
        min_samples_split=cfg["min_samples_split"],
        min_samples_leaf=cfg["min_samples_leaf"],
        random_state=cfg["random_seed"],
        n_jobs=cfg.get("n_jobs", -1),
    )


def train_random_forest(
    data_dir: str = "dataset/processed",
    artifact_dir: str = "models/artifacts",
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[RandomForestClassifier, Dict[str, Any], Dict[str, Any]]:
    """Execute the Random Forest training, validation, and artifact export pipeline.
    
    Returns:
        (trained_model, val_metrics, metadata_dict)
    """
    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)

    set_random_seed(cfg["random_seed"])

    # 1. Load validated dataset partitions
    X_train, y_train, X_val, y_val, X_test, y_test, feature_names, label_map = load_processed_dataset(data_dir)

    # 2. Build and fit model on TRAIN data only
    model = build_random_forest_model(cfg)
    model.fit(X_train, y_train)

    # 3. Evaluate on VALIDATION data (Test set reserved for final evaluation)
    y_val_pred = model.predict(X_val)
    label_names = list(label_map.keys())
    val_metrics = compute_classification_metrics(y_val, y_val_pred, label_names=label_names)

    # 4. Save artifacts
    model_path = os.path.join(artifact_dir, "rf_baseline_model.joblib")
    meta_path = os.path.join(artifact_dir, "rf_baseline_metadata.json")
    report_path = os.path.join(artifact_dir, "rf_baseline_val_report.json")

    save_model_artifact(model, model_path)

    metadata = create_experiment_metadata(
        model_name="RandomForestClassifier",
        hyperparams=cfg,
        feature_names=feature_names,
        label_map=label_map,
        random_seed=cfg["random_seed"],
    )
    save_json(metadata, meta_path)

    eval_report = generate_eval_report(
        model_name="RandomForestClassifier",
        metrics=val_metrics,
        config=cfg,
        split_evaluated="validation",
    )
    save_eval_report(eval_report, report_path)

    return model, val_metrics, metadata


def main():
    """CLI entry point for training Random Forest model."""
    parser = argparse.ArgumentParser(description="Train Random Forest Baseline for UniGuard")
    parser.add_argument("--data-dir", type=str, default="dataset/processed", help="Directory of processed CSVs")
    parser.add_argument("--artifact-dir", type=str, default="models/artifacts", help="Directory to save model artifacts")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of trees")
    parser.add_argument("--max-depth", type=int, default=15, help="Max depth of trees")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    cfg = {
        "random_seed": args.seed,
        "n_estimators": args.n_estimators,
        "max_depth": args.max_depth,
    }

    print(f"Starting Random Forest training pipeline (seed={args.seed})...")
    model, val_metrics, metadata = train_random_forest(
        data_dir=args.data_dir,
        artifact_dir=args.artifact_dir,
        config=cfg,
    )
    print(f"Random Forest Training Complete!")
    print(f"Validation Accuracy: {val_metrics['accuracy']:.4f}")
    print(f"Validation Macro F1: {val_metrics['macro_f1']:.4f}")


if __name__ == "__main__":
    main()
