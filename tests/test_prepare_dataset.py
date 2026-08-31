"""Unit tests for Member-2 Milestone 11: Dataset Preparation Pipeline & ML Readiness."""

import os
import tempfile
import numpy as np
import pandas as pd
import pytest

from dataset.prepare_dataset import (
    UniGuardDatasetPipeline,
    LABEL_MAPPING,
    NUMERICAL_FEATURE_COLUMNS,
    CATEGORICAL_COLUMNS,
    EXCLUDED_LEAKAGE_FEATURES,
    EXCLUSION_REASON,
    generate_mock_df,
)


def test_missing_zip_raises_file_not_found():
    """Verify that a non-existent ZIP file raises FileNotFoundError without silent fallback."""
    pipeline = UniGuardDatasetPipeline(zip_path="non_existent_archive_12345.zip")
    with pytest.raises(FileNotFoundError, match="Required dataset archive not found"):
        pipeline.process()


def test_real_zip_processing_and_leakage_exclusion():
    """Test full processing pipeline and confirm leakage features are strictly excluded."""
    zip_path = "dataset/UniGuard_required_dataset_v1.zip"
    if not os.path.exists(zip_path):
        pytest.skip(f"Dataset zip archive '{zip_path}' not available for integration test.")

    pipeline = UniGuardDatasetPipeline(zip_path=zip_path)
    splits = pipeline.process()

    # Check shapes
    assert len(splits.X_train) == 83918
    assert len(splits.X_val) == 18018
    assert len(splits.X_test) == 18064

    # Verify leakage columns are strictly ABSENT from ML feature matrices
    for leakage_col in EXCLUDED_LEAKAGE_FEATURES:
        assert leakage_col not in splits.X_train.columns
        assert leakage_col not in splits.X_val.columns
        assert leakage_col not in splits.X_test.columns

    # Verify metadata and identifier columns are strictly ABSENT from X
    excluded_identifiers = [
        "entity_id", "src_ip", "dst_ip", "timestamp", "scenario_id",
        "dataset_source", "split", "attack_stage", "label"
    ]
    for col in excluded_identifiers:
        assert col not in splits.X_train.columns
        assert col not in splits.X_val.columns
        assert col not in splits.X_test.columns

    # Verify 7 unique label values (0 to 6)
    assert set(np.unique(splits.y_train)) == {0, 1, 2, 3, 4, 5, 6}
    assert set(np.unique(splits.y_val)) == {0, 1, 2, 3, 4, 5, 6}
    assert set(np.unique(splits.y_test)) == {0, 1, 2, 3, 4, 5, 6}


def test_no_entity_leakage():
    """Verify zero entity overlap across train, val, and test partitions."""
    zip_path = "dataset/UniGuard_required_dataset_v1.zip"
    if not os.path.exists(zip_path):
        pytest.skip(f"Dataset zip archive '{zip_path}' not available.")

    pipeline = UniGuardDatasetPipeline(zip_path=zip_path)
    train_df = pipeline.load_partition_from_zip("uniguard_train.csv")
    val_df = pipeline.load_partition_from_zip("uniguard_validation.csv")
    test_df = pipeline.load_partition_from_zip("uniguard_test.csv")

    train_entities = set(train_df["entity_id"].dropna().unique())
    val_entities = set(val_df["entity_id"].dropna().unique())
    test_entities = set(test_df["entity_id"].dropna().unique())

    assert len(train_entities.intersection(val_entities)) == 0
    assert len(train_entities.intersection(test_entities)) == 0
    assert len(val_entities.intersection(test_entities)) == 0


def test_onehot_categorical_encoding_and_train_only_fitting():
    """Verify One-Hot encoding strategy and safe handling of unseen eval categories."""
    pipeline = UniGuardDatasetPipeline()

    train_df = generate_mock_df(num_rows=50, seed=1)
    eval_df = generate_mock_df(num_rows=20, seed=2)

    # Introduce a new unseen categorical value in EVAL that was NOT in TRAIN
    eval_df["ja3"] = "UNSEEN_JA3_FINGERPRINT"

    X_train, state = pipeline.fit_transform_train(train_df)
    X_eval = pipeline.transform_eval(eval_df, state)

    # Verify One-Hot feature names are created (e.g. ja3_JA3_A)
    assert "ja3_JA3_A" in X_train.columns
    assert "ja4_JA4_A" in X_train.columns
    assert "tls_version_TLS1.3" in X_train.columns

    # Check that unseen ja3 value in EVAL maps safely to all 0.0s for known categories
    assert (X_eval["ja3_JA3_A"] == 0.0).all()


def test_synthetic_indicator_provenance_and_safety():
    """Verify that synthetic indicators exist in features and are non-leaking."""
    synthetic_cols = ["ngram_score", "dns_query_rate", "session_resumption", "large_transfer_score"]
    for col in synthetic_cols:
        assert col in NUMERICAL_FEATURE_COLUMNS


def test_unsupported_label_raises_value_error():
    """Verify that an unknown target label raises ValueError."""
    pipeline = UniGuardDatasetPipeline()
    invalid_labels = pd.Series(["BENIGN", "UNKNOWN_ATTACK_TYPE", "DDOS"])
    with pytest.raises(ValueError, match="Encountered unsupported dataset label"):
        pipeline.verify_label_mapping(invalid_labels)


def test_export_pipeline_and_manifest():
    """Test exporting dataset partitions and dataset_manifest.json with exclusion details."""
    zip_path = "dataset/UniGuard_required_dataset_v1.zip"
    if not os.path.exists(zip_path):
        pytest.skip(f"Dataset zip archive '{zip_path}' not available.")

    pipeline = UniGuardDatasetPipeline(zip_path=zip_path)
    splits = pipeline.process()

    with tempfile.TemporaryDirectory() as temp_dir:
        manifest = pipeline.export(splits, output_dir=temp_dir)

        assert os.path.exists(os.path.join(temp_dir, "train.csv"))
        assert os.path.exists(os.path.join(temp_dir, "val.csv"))
        assert os.path.exists(os.path.join(temp_dir, "test.csv"))
        assert os.path.exists(os.path.join(temp_dir, "dataset_manifest.json"))

        assert manifest["train_rows"] == 83918
        assert manifest["val_rows"] == 18018
        assert manifest["test_rows"] == 18064
        assert manifest["excluded_features"] == EXCLUDED_LEAKAGE_FEATURES
        assert manifest["exclusion_reason"] == EXCLUSION_REASON
