"""Unit tests for Member-2 Milestone 12A: ML Training Infrastructure & Evaluation Utilities."""

import os
import json
import tempfile
import numpy as np
import pandas as pd
import pytest

from models.utils.data_loader import (
    load_processed_dataset,
    validate_feature_matrix,
    EXPECTED_FEATURE_COUNT,
    FORBIDDEN_COLUMNS,
)
from models.utils.model_utils import (
    set_random_seed,
    save_model_artifact,
    load_model_artifact,
    save_json,
    load_json,
    create_experiment_metadata,
)
from models.evaluation.metrics import compute_classification_metrics
from models.evaluation.reports import generate_eval_report, save_eval_report


def test_data_loader_processed_dataset():
    """Verify loading of valid processed dataset splits from dataset/processed/."""
    data_dir = "dataset/processed"
    if not os.path.exists(os.path.join(data_dir, "train.csv")):
        pytest.skip(f"Processed dataset directory '{data_dir}' not populated.")

    X_train, y_train, X_val, y_val, X_test, y_test, feature_names, label_map = load_processed_dataset(data_dir)

    assert len(X_train) == 83918
    assert len(X_val) == 18018
    assert len(X_test) == 18064

    assert X_train.shape[1] == EXPECTED_FEATURE_COUNT
    assert X_val.shape[1] == EXPECTED_FEATURE_COUNT
    assert X_test.shape[1] == EXPECTED_FEATURE_COUNT
    assert len(feature_names) == EXPECTED_FEATURE_COUNT

    assert len(y_train) == 83918
    assert len(y_val) == 18018
    assert len(y_test) == 18064

    # Verify no leakage columns in feature_names
    for col in FORBIDDEN_COLUMNS:
        assert col not in feature_names


def test_52_feature_validation_raises_error():
    """Verify data_loader raises ValueError when feature count is not 52."""
    df_invalid = pd.DataFrame({"feat_1": [1.0, 2.0], "feat_2": [3.0, 4.0], "label": [0, 1]})
    with pytest.raises(ValueError, match="expected exactly 52 features"):
        validate_feature_matrix(df_invalid, "test_split")


def test_forbidden_column_detection_raises_error():
    """Verify data_loader raises ValueError when a forbidden leakage column is present."""
    # Create 51 dummy features + 1 forbidden column
    data = {f"f_{i}": [1.0] * 5 for i in range(51)}
    data["recent_risk"] = [0.5] * 5  # Forbidden!
    data["label"] = [0] * 5
    df_forbidden = pd.DataFrame(data)

    with pytest.raises(ValueError, match="Forbidden leakage/metadata column"):
        validate_feature_matrix(df_forbidden, "test_split")


def test_label_validation_raises_error():
    """Verify data_loader raises ValueError when target label is outside 0..6."""
    data_dir = "dataset/processed"
    if not os.path.exists(os.path.join(data_dir, "train.csv")):
        pytest.skip("Processed dataset not available.")

    X_train, y_train, _, _, _, _, feature_names, _ = load_processed_dataset(data_dir)

    with tempfile.TemporaryDirectory() as temp_dir:
        df_export = X_train.head(10).copy()
        df_export["label"] = 99  # Invalid label!

        df_export.to_csv(os.path.join(temp_dir, "train.csv"), index=False)
        df_export.to_csv(os.path.join(temp_dir, "val.csv"), index=False)
        df_export.to_csv(os.path.join(temp_dir, "test.csv"), index=False)

        with pytest.raises(ValueError, match="Invalid label"):
            load_processed_dataset(temp_dir)


def test_nan_inf_validation_raises_error():
    """Verify data_loader raises ValueError when NaNs or Infs exist."""
    data = {f"f_{i}": [1.0, 2.0, 3.0] for i in range(52)}
    data["f_0"] = [1.0, np.nan, 3.0]  # NaN present!
    df_nan = pd.DataFrame(data)

    with pytest.raises(ValueError, match="contains 1 missing/NaN values"):
        validate_feature_matrix(df_nan, "test_split")

    data_inf = {f"f_{i}": [1.0, 2.0, 3.0] for i in range(52)}
    data_inf["f_0"] = [1.0, np.inf, 3.0]  # Inf present!
    df_inf = pd.DataFrame(data_inf)

    with pytest.raises(ValueError, match="contains 1 infinite"):
        validate_feature_matrix(df_inf, "test_split")


def test_evaluation_metrics_computation():
    """Verify multiclass classification metric calculations and report generation."""
    y_true = np.array([0, 1, 2, 3, 4, 5, 6, 0, 1, 2])
    y_pred = np.array([0, 1, 2, 3, 4, 5, 6, 0, 1, 0])  # 9/10 correct

    metrics = compute_classification_metrics(y_true, y_pred)

    assert metrics["accuracy"] == 0.9
    assert "macro_f1" in metrics
    assert "weighted_f1" in metrics
    assert "per_class_metrics" in metrics
    assert len(metrics["confusion_matrix"]) == 7

    # Check report serialization
    report = generate_eval_report("TestModel", metrics, {"seed": 42})
    assert report["model_name"] == "TestModel"
    assert report["metrics"]["accuracy"] == 0.9

    with tempfile.TemporaryDirectory() as temp_dir:
        rpt_path = os.path.join(temp_dir, "report.json")
        save_eval_report(report, rpt_path)
        assert os.path.exists(rpt_path)


def test_model_utils_serialization():
    """Test seed setting, metadata creation, and joblib/json saving and loading."""
    set_random_seed(123)

    metadata = create_experiment_metadata(
        model_name="TestModel",
        hyperparams={"n_estimators": 10},
        feature_names=["f1", "f2"],
        label_map={"BENIGN": 0},
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        json_path = os.path.join(temp_dir, "meta.json")
        save_json(metadata, json_path)
        loaded_meta = load_json(json_path)
        assert loaded_meta["model_name"] == "TestModel"

        # Mock model serialization using dummy object
        dummy_model = {"weights": [0.1, 0.2, 0.3]}
        model_path = os.path.join(temp_dir, "model.joblib")
        save_model_artifact(dummy_model, model_path)
        loaded_model = load_model_artifact(model_path)
        assert loaded_model["weights"] == [0.1, 0.2, 0.3]


def test_training_scripts_importable_without_running():
    """Verify that training modules can be imported without triggering model training."""
    import models.training.train_random_forest as trf
    import models.training.train_lightgbm as tlgb
    import models.training.train_isolation_forest as tif

    assert hasattr(trf, "train_random_forest")
    assert hasattr(trf, "build_random_forest_model")

    assert hasattr(tlgb, "train_lightgbm")
    assert hasattr(tlgb, "build_lightgbm_model")

    assert hasattr(tif, "train_isolation_forest")
    assert hasattr(tif, "build_isolation_forest_model")
