"""Unit tests for Production ML Inference Layer (Member 2 Milestone 16).

Tests model loading, feature contract validation, LightGBM/RF/IF inference,
BENIGN handling, anomaly coexistence, DetectionSignal conversion, and zero payload leakage.
"""

import os
import pytest
import numpy as np
import pandas as pd

from schemas import (
    DetectionSignal,
    ThreatClass,
    DetectorType,
    Severity,
    FeatureVector,
    FlowFeatures,
)
from models.inference.ml_inference import (
    MLInferenceEngine,
    ClassificationResult,
    AnomalyResult,
    UnifiedMLResult,
    EXPECTED_FEATURE_COUNT,
    EXPECTED_FEATURE_NAMES,
    LABEL_MAPPING,
)
from models.inference.signal_adapter import (
    SignalAdapter,
    FeatureVectorAdapter,
    calculate_severity,
)


@pytest.fixture
def engine():
    """Returns an instantiated MLInferenceEngine loaded from production artifacts."""
    return MLInferenceEngine(artifact_dir="models/artifacts")


@pytest.fixture
def sample_benign_features(engine):
    """Fixture providing a synthetic benign feature array matching 52-feature contract."""
    # Near zero / low flow values typical for benign traffic
    feats = np.zeros((1, EXPECTED_FEATURE_COUNT), dtype=np.float64)
    feats[0, 0] = 1.5   # duration
    feats[0, 1] = 10.0  # total_packets
    feats[0, 2] = 500.0 # total_bytes
    feats[0, 10] = 0.05 # periodicity_score
    return feats


@pytest.fixture
def sample_ddos_features():
    """Fixture providing a high-volume DDoS feature array."""
    feats = np.zeros((1, EXPECTED_FEATURE_COUNT), dtype=np.float64)
    feats[0, 0] = 10.0      # duration
    feats[0, 1] = 50000.0   # total_packets
    feats[0, 2] = 2000000.0 # total_bytes
    feats[0, 5] = 5000.0    # packets_per_sec
    feats[0, 6] = 200000.0  # bytes_per_sec
    return feats


# ──────────────────────────────────────────────────────────────────────────────
# 1. Model Loading Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_engine_initialization(engine):
    assert engine.lgb_model is not None
    assert engine.rf_model is not None
    assert engine.if_model is not None
    assert len(engine.feature_names) == EXPECTED_FEATURE_COUNT


def test_missing_artifact_raises_file_not_found():
    with pytest.raises(FileNotFoundError) as exc_info:
        MLInferenceEngine(artifact_dir="non_existent_directory_xyz")
    assert "Required production ML model artifact(s) missing" in str(exc_info.value)


# ──────────────────────────────────────────────────────────────────────────────
# 2. Feature Contract Validation Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_validate_features_valid_inputs(engine):
    # 1D array
    arr_1d = np.zeros(52)
    val_1d = engine.validate_features(arr_1d)
    assert val_1d.shape == (1, 52)

    # 2D array
    arr_2d = np.zeros((5, 52))
    val_2d = engine.validate_features(arr_2d)
    assert val_2d.shape == (5, 52)

    # List
    lst = [0.0] * 52
    val_lst = engine.validate_features(lst)
    assert val_lst.shape == (1, 52)

    # DataFrame
    df = pd.DataFrame(np.zeros((2, 52)), columns=EXPECTED_FEATURE_NAMES)
    val_df = engine.validate_features(df)
    assert val_df.shape == (2, 52)


def test_validate_features_invalid_shape_raises(engine):
    # Wrong 1D length
    with pytest.raises(ValueError) as exc:
        engine.validate_features(np.zeros(50))
    assert "Invalid 1D feature vector length" in str(exc.value)

    # Wrong 2D width
    with pytest.raises(ValueError) as exc:
        engine.validate_features(np.zeros((3, 53)))
    assert "Invalid 2D feature matrix width" in str(exc.value)


def test_validate_features_nan_inf_raises(engine):
    arr_nan = np.zeros((1, 52))
    arr_nan[0, 5] = np.nan
    with pytest.raises(ValueError) as exc:
        engine.validate_features(arr_nan)
    assert "NaN or Inf" in str(exc.value)

    arr_inf = np.zeros((1, 52))
    arr_inf[0, 10] = np.inf
    with pytest.raises(ValueError) as exc:
        engine.validate_features(arr_inf)
    assert "NaN or Inf" in str(exc.value)


def test_validate_features_dataframe_missing_extra_cols(engine):
    # Missing columns
    df_missing = pd.DataFrame(np.zeros((1, 51)), columns=EXPECTED_FEATURE_NAMES[:51])
    with pytest.raises(ValueError):
        engine.validate_features(df_missing)

    # Extra / wrong columns
    cols_bad = list(EXPECTED_FEATURE_NAMES[:51]) + ["unknown_column"]
    df_bad = pd.DataFrame(np.zeros((1, 52)), columns=cols_bad)
    with pytest.raises(ValueError) as exc:
        engine.validate_features(df_bad)
    assert "Feature column mismatch" in str(exc.value)


# ──────────────────────────────────────────────────────────────────────────────
# 3. LightGBM & RF Classification Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_predict_classification_lightgbm(engine, sample_benign_features):
    res = engine.predict_classification(sample_benign_features, use_fallback_rf=False)

    assert isinstance(res, ClassificationResult)
    assert 0 <= res.predicted_class_index <= 6
    assert res.predicted_class_name in LABEL_MAPPING[res.predicted_class_index][0]
    assert 0.0 <= res.confidence <= 1.0
    assert len(res.probabilities) == 7
    assert abs(sum(res.probabilities.values()) - 1.0) < 1e-4
    assert res.model_name == "LGBMClassifier"
    assert res.inference_latency_ms >= 0.0


def test_predict_classification_random_forest_fallback(engine, sample_benign_features):
    res = engine.predict_classification(sample_benign_features, use_fallback_rf=True)

    assert isinstance(res, ClassificationResult)
    assert res.model_name == "RandomForestClassifier"
    assert 0 <= res.predicted_class_index <= 6
    assert 0.0 <= res.confidence <= 1.0


def test_predict_classification_batch_input(engine):
    batch_x = np.zeros((3, 52))
    results = engine.predict_classification(batch_x)

    assert isinstance(results, list)
    assert len(results) == 3
    for r in results:
        assert isinstance(r, ClassificationResult)


# ──────────────────────────────────────────────────────────────────────────────
# 4. Isolation Forest Anomaly Detection Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_predict_anomaly_isolation_forest(engine, sample_benign_features):
    res = engine.predict_anomaly(sample_benign_features)

    assert isinstance(res, AnomalyResult)
    assert isinstance(res.is_anomaly, bool)
    assert isinstance(res.anomaly_score, float)
    assert 0.0 <= res.normalized_confidence <= 1.0
    assert res.model_name == "IsolationForest"
    assert "deviations" in res.note


def test_predict_anomaly_batch_input(engine):
    batch_x = np.zeros((4, 52))
    results = engine.predict_anomaly(batch_x)

    assert isinstance(results, list)
    assert len(results) == 4
    for r in results:
        assert isinstance(r, AnomalyResult)


# ──────────────────────────────────────────────────────────────────────────────
# 5. Unified ML Prediction & Anomaly Coexistence
# ──────────────────────────────────────────────────────────────────────────────
def test_predict_unified(engine, sample_benign_features):
    res = engine.predict_unified(
        sample_benign_features,
        source_entity="192.168.1.50",
        target_entity="10.0.0.1",
    )

    assert isinstance(res, UnifiedMLResult)
    assert isinstance(res.classification, ClassificationResult)
    assert isinstance(res.anomaly, AnomalyResult)
    assert res.source_entity == "192.168.1.50"
    assert res.target_entity == "10.0.0.1"


# ──────────────────────────────────────────────────────────────────────────────
# 6. Severity Calculation Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_calculate_severity():
    assert calculate_severity(0.95) == Severity.HIGH
    assert calculate_severity(0.70) == Severity.HIGH
    assert calculate_severity(0.69) == Severity.MEDIUM
    assert calculate_severity(0.40) == Severity.MEDIUM
    assert calculate_severity(0.39) == Severity.LOW
    assert calculate_severity(0.10) == Severity.LOW
    assert calculate_severity(0.05) == Severity.INFO


# ──────────────────────────────────────────────────────────────────────────────
# 7. DetectionSignal Adapter & BENIGN Handling Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_signal_adapter_benign_classification_returns_none():
    benign_res = ClassificationResult(
        predicted_class_index=0,
        predicted_class_name="BENIGN",
        threat_class=None,
        probabilities={"BENIGN": 0.99, "VOLUMETRIC_DDOS": 0.01},
        confidence=0.99,
        is_threat=False,
        model_name="LGBMClassifier",
        inference_latency_ms=0.5,
    )

    sig = SignalAdapter.to_detection_signal(benign_res, source_entity="192.168.1.100")
    # Must return None for BENIGN traffic
    assert sig is None


def test_signal_adapter_threat_classification_returns_signal():
    threat_res = ClassificationResult(
        predicted_class_index=1,
        predicted_class_name="VOLUMETRIC_DDOS",
        threat_class=ThreatClass.VOLUMETRIC_DDOS,
        probabilities={"BENIGN": 0.01, "VOLUMETRIC_DDOS": 0.99},
        confidence=0.99,
        is_threat=True,
        model_name="LGBMClassifier",
        inference_latency_ms=0.5,
    )

    sig = SignalAdapter.to_detection_signal(threat_res, source_entity="192.168.1.100")
    assert isinstance(sig, DetectionSignal)
    assert sig.threat_class == ThreatClass.VOLUMETRIC_DDOS
    assert sig.detector_type == DetectorType.LIGHTWEIGHT_ML
    assert sig.confidence == 0.99
    assert sig.severity == Severity.HIGH
    assert sig.source_entity == "192.168.1.100"

    # Verify indicators payload
    ind = sig.indicators
    assert ind["predicted_class"] == "VOLUMETRIC_DDOS"
    assert ind["confidence"] == 0.99
    assert ind["model_name"] == "LGBMClassifier"
    # Ensure zero payload leakage
    assert "raw_payload" not in ind
    assert "decrypted_payload" not in ind


def test_signal_adapter_anomaly_coexistence_when_benign_classifier():
    # LightGBM says BENIGN, but Isolation Forest flags ANOMALY
    clf_benign = ClassificationResult(
        predicted_class_index=0,
        predicted_class_name="BENIGN",
        threat_class=None,
        probabilities={"BENIGN": 0.95},
        confidence=0.95,
        is_threat=False,
        model_name="LGBMClassifier",
        inference_latency_ms=0.5,
    )
    anom_detected = AnomalyResult(
        is_anomaly=True,
        anomaly_score=-0.15,
        normalized_confidence=0.85,
        model_name="IsolationForest",
        inference_latency_ms=0.2,
    )

    unified = UnifiedMLResult(
        classification=clf_benign,
        anomaly=anom_detected,
        source_entity="10.0.0.50",
    )

    sig = SignalAdapter.to_detection_signal(unified)
    assert isinstance(sig, DetectionSignal)
    assert sig.threat_class == ThreatClass.UNKNOWN_ANOMALY
    assert sig.detector_type == DetectorType.UNSUPERVISED_ANOMALY
    assert sig.confidence == 0.85
    assert sig.severity == Severity.HIGH
    assert sig.source_entity == "10.0.0.50"
    assert sig.indicators["classifier_predicted_benign"] is True
    assert sig.indicators["is_anomaly"] is True


def test_signal_adapter_pure_benign_unified_returns_none():
    clf_benign = ClassificationResult(
        predicted_class_index=0,
        predicted_class_name="BENIGN",
        threat_class=None,
        probabilities={"BENIGN": 0.99},
        confidence=0.99,
        is_threat=False,
        model_name="LGBMClassifier",
        inference_latency_ms=0.5,
    )
    anom_inlier = AnomalyResult(
        is_anomaly=False,
        anomaly_score=0.08,
        normalized_confidence=0.10,
        model_name="IsolationForest",
        inference_latency_ms=0.2,
    )

    unified = UnifiedMLResult(
        classification=clf_benign,
        anomaly=anom_inlier,
        source_entity="10.0.0.50",
    )

    sig = SignalAdapter.to_detection_signal(unified)
    assert sig is None


# ──────────────────────────────────────────────────────────────────────────────
# 8. FeatureVector Adapter Tests
# ──────────────────────────────────────────────────────────────────────────────
def test_feature_vector_adapter_dict():
    d = {"duration": 10.0, "total_packets": 100, "ja3_JA3_A": 1.0}
    feats = FeatureVectorAdapter.dict_to_features(d)

    assert feats.shape == (1, 52)
    assert feats[0, 0] == 10.0  # duration
    assert feats[0, 1] == 100.0 # total_packets
    assert feats[0, 36] == 1.0 # ja3_JA3_A


def test_feature_vector_adapter_pydantic_schema():
    fv = FeatureVector(
        feature_id="feat_123",
        entity_ip="192.168.1.10",
        timestamp_iso="2026-08-31T12:00:00Z",
        flow_features=FlowFeatures(
            packets_per_sec=10.0,
            bytes_per_sec=500.0,
        ),
    )

    feats = FeatureVectorAdapter.feature_vector_to_features(fv)
    assert feats.shape == (1, 52)
    assert feats[0, 5] == 10.0  # packets_per_sec
    assert feats[0, 6] == 500.0 # bytes_per_sec



# ──────────────────────────────────────────────────────────────────────────────
# 9. Latency Benchmarking Helper Test
# ──────────────────────────────────────────────────────────────────────────────
def test_benchmark_inference_latency(engine, sample_benign_features):
    bench = engine.benchmark_inference_latency(sample_benign_features, num_runs=10)

    assert "lightgbm" in bench
    assert "random_forest" in bench
    assert "isolation_forest" in bench

    assert bench["lightgbm"]["per_sample_us"] > 0.0
    assert bench["lightgbm"]["throughput_samples_per_sec"] > 0.0
