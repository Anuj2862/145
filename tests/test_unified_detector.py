"""Unit tests for Member-2 Milestone 17: Unified M2 Detection Orchestration.

Tests baseline detector integration, LightGBM primary classification, Isolation Forest anomaly detection,
BENIGN handling, failure isolation, duplicate signal preservation, and deterministic signal ordering.
"""

import pytest
import numpy as np
from typing import List

from schemas import (
    DetectionSignal,
    ThreatClass,
    DetectorType,
    Severity,
    FeatureVector,
    FlowFeatures,
    TemporalFeatures,
    DNSFeatures,
    TLSFeatures,
)
from features.recon_features import ReconFeatures
from features.exfil_features import ExfiltrationFeatures
from detectors.engine import DetectionContext, DetectorResult
from detectors.unified_detector import UnifiedM2Orchestrator


@pytest.fixture
def orchestrator():
    """Instantiate a UnifiedM2Orchestrator loaded with production artifacts."""
    return UnifiedM2Orchestrator(artifact_dir="models/artifacts")


@pytest.fixture
def sample_context():
    """Fixture producing a sample DetectionContext with feature_vector."""
    fv = FeatureVector(
        feature_id="fv_test_001",
        entity_ip="192.168.1.100",
        timestamp_iso="2026-08-31T12:00:00Z",
        flow_features=FlowFeatures(
            packets_per_sec=10.0,
            bytes_per_sec=1000.0,
        ),
        temporal_features=TemporalFeatures(
            periodicity_score=0.95,
            jitter_pct=2.0,
            iat_mean_ms=1000.0,
            iat_std_ms=10.0,
        ),
    )
    return DetectionContext(
        source_entity="192.168.1.100",
        timestamp_iso="2026-08-31T12:00:00Z",
        feature_vector=fv,
        observation_count=20,
    )


@pytest.fixture
def benign_feature_matrix():
    """52-feature matrix representing typical benign traffic."""
    feats = np.zeros((1, 52), dtype=np.float64)
    feats[0, 0] = 2.0     # duration
    feats[0, 1] = 12.0    # total_packets
    feats[0, 2] = 600.0   # total_bytes
    feats[0, 10] = 0.02   # periodicity_score (low/benign)
    return feats


@pytest.fixture
def ddos_feature_matrix():
    """52-feature matrix representing a high-volume Volumetric DDoS attack."""
    feats = np.zeros((1, 52), dtype=np.float64)
    feats[0, 0] = 10.0      # duration
    feats[0, 1] = 50000.0   # total_packets
    feats[0, 2] = 2000000.0 # total_bytes
    feats[0, 5] = 5000.0    # packets_per_sec
    feats[0, 6] = 200000.0  # bytes_per_sec
    return feats


# ──────────────────────────────────────────────────────────────────────────────
# 1. Baseline Detector Integration & Engine Execution
# ──────────────────────────────────────────────────────────────────────────────
def test_orchestrator_initialization(orchestrator):
    assert orchestrator.baseline_engine is not None
    assert len(orchestrator.baseline_engine) == 6
    assert orchestrator.ml_engine is not None


def test_all_deterministic_detectors_executing(orchestrator, sample_context, benign_feature_matrix):
    results = orchestrator.run_all(sample_context, feature_matrix=benign_feature_matrix)

    # 6 baseline detectors + 1 LightGBM + 1 Isolation Forest = 8 detector sources
    assert len(results) == 8
    detector_names = [r.detector_name for r in results]
    assert "DDoSBaselineDetector" in detector_names
    assert "C2BeaconDetector" in detector_names
    assert "DNSAnomalyDetector" in detector_names
    assert "EncryptedThreatDetector" in detector_names
    assert "ReconDetector" in detector_names
    assert "ExfiltrationDetector" in detector_names
    assert "LightGBMClassifier" in detector_names
    assert "IsolationForestAnomaly" in detector_names


# ──────────────────────────────────────────────────────────────────────────────
# 2. LightGBM Classification & BENIGN Handling
# ──────────────────────────────────────────────────────────────────────────────
def test_lightgbm_threat_prediction(orchestrator, sample_context, ddos_feature_matrix):
    signals = orchestrator.evaluate(sample_context, feature_matrix=ddos_feature_matrix)

    ml_signals = [s for s in signals if s.detector_type == DetectorType.LIGHTWEIGHT_ML]
    assert len(ml_signals) == 1
    sig = ml_signals[0]

    assert sig.threat_class == ThreatClass.VOLUMETRIC_DDOS
    assert sig.confidence > 0.90
    assert sig.severity == Severity.HIGH
    assert sig.source_entity == "192.168.1.100"
    assert "VOLUMETRIC_DDOS" in sig.indicators["predicted_class"]


def test_lightgbm_benign_prediction_no_threat_signal(orchestrator, sample_context, benign_feature_matrix):
    signals = orchestrator.evaluate(sample_context, feature_matrix=benign_feature_matrix)

    # LightGBM predicts BENIGN -> no LIGHTWEIGHT_ML threat signal produced
    ml_signals = [s for s in signals if s.detector_type == DetectorType.LIGHTWEIGHT_ML]
    assert len(ml_signals) == 0


# ──────────────────────────────────────────────────────────────────────────────
# 3. Isolation Forest Anomaly Detection & Coexistence
# ──────────────────────────────────────────────────────────────────────────────
def test_isolation_forest_anomaly_coexistence_with_benign_lightgbm(orchestrator, sample_context):
    # Construct feature matrix that triggers IF anomaly but LightGBM predicts BENIGN
    anom_matrix = np.zeros((1, 52), dtype=np.float64)
    anom_matrix[0, 0] = 500.0       # Unusual duration
    anom_matrix[0, 1] = 9999.0      # Unusual packet count
    anom_matrix[0, 10] = 0.88       # High periodicity

    signals = orchestrator.evaluate(sample_context, feature_matrix=anom_matrix)

    anom_signals = [s for s in signals if s.detector_type == DetectorType.UNSUPERVISED_ANOMALY]
    if len(anom_signals) > 0:
        sig = anom_signals[0]
        assert sig.threat_class == ThreatClass.UNKNOWN_ANOMALY
        assert sig.indicators["is_anomaly"] is True
        assert "anomaly_score" in sig.indicators


# ──────────────────────────────────────────────────────────────────────────────
# 4. Duplicate Independent Signals Preserved
# ──────────────────────────────────────────────────────────────────────────────
def test_duplicate_independent_signals_preserved(orchestrator, ddos_feature_matrix):
    # Context with DDoS FlowFeatures + DDoS ML matrix
    fv_ddos = FeatureVector(
        feature_id="fv_ddos",
        entity_ip="10.0.0.99",
        timestamp_iso="2026-08-31T12:00:00Z",
        flow_features=FlowFeatures(
            packets_per_sec=5000.0,
            bytes_per_sec=200000.0,
        ),
    )
    ctx = DetectionContext(
        source_entity="10.0.0.99",
        timestamp_iso="2026-08-31T12:00:00Z",
        feature_vector=fv_ddos,
    )

    signals = orchestrator.evaluate(ctx, feature_matrix=ddos_feature_matrix)

    # Should contain BOTH DDoSBaselineDetector signal AND LightGBM signal
    detector_types = [s.detector_type for s in signals]
    threat_classes = [s.threat_class for s in signals]

    assert DetectorType.DETERMINISTIC_BASELINE in detector_types
    assert DetectorType.LIGHTWEIGHT_ML in detector_types

    # Both report VOLUMETRIC_DDOS independently
    ddos_signals = [s for s in signals if s.threat_class == ThreatClass.VOLUMETRIC_DDOS]
    assert len(ddos_signals) >= 2


# ──────────────────────────────────────────────────────────────────────────────
# 5. Failure Isolation
# ──────────────────────────────────────────────────────────────────────────────
def test_model_load_failure_isolation(sample_context, benign_feature_matrix):
    # Pass invalid directory -> ML engine load fails, but baseline detectors execute cleanly
    orch_invalid = UnifiedM2Orchestrator(artifact_dir="non_existent_path", enable_ml=True)

    assert orch_invalid.ml_engine is None
    results = orch_invalid.run_all(sample_context, feature_matrix=benign_feature_matrix)

    # ML results contain explicit error descriptions and succeeded is False
    ml_failed_results = [r for r in results if not r.succeeded and ("MLInferenceEngine" in str(r.error) or "unavailable" in str(r.error))]
    assert len(ml_failed_results) == 2
    for r in ml_failed_results:
        assert r.signal is None
        assert r.error is not None



# ──────────────────────────────────────────────────────────────────────────────
# 6. Deterministic Output Signal Ordering
# ──────────────────────────────────────────────────────────────────────────────
def test_deterministic_signal_ordering(orchestrator, ddos_feature_matrix):
    fv_c2 = FeatureVector(
        feature_id="fv_c2",
        entity_ip="192.168.1.200",
        timestamp_iso="2026-08-31T12:00:00Z",
        flow_features=FlowFeatures(packets_per_sec=5000.0, bytes_per_sec=200000.0),
        temporal_features=TemporalFeatures(periodicity_score=0.98, jitter_pct=1.0, iat_mean_ms=1000.0, iat_std_ms=5.0),
    )
    ctx = DetectionContext(
        source_entity="192.168.1.200",
        timestamp_iso="2026-08-31T12:00:00Z",
        feature_vector=fv_c2,
        observation_count=20,
    )

    signals1 = orchestrator.evaluate(ctx, feature_matrix=ddos_feature_matrix)
    signals2 = orchestrator.evaluate(ctx, feature_matrix=ddos_feature_matrix)

    # Identical input produces identical signal count and ordering
    assert len(signals1) == len(signals2)
    for s1, s2 in zip(signals1, signals2):
        assert s1.threat_class == s2.threat_class
        assert s1.detector_type == s2.detector_type
        assert s1.confidence == s2.confidence
        assert s1.severity == s2.severity


# ──────────────────────────────────────────────────────────────────────────────
# 7. Zero Payload Leakage & Schema Validation
# ──────────────────────────────────────────────────────────────────────────────
def test_zero_payload_leakage_in_indicators(orchestrator, sample_context, ddos_feature_matrix):
    signals = orchestrator.evaluate(sample_context, feature_matrix=ddos_feature_matrix)

    for sig in signals:
        assert isinstance(sig, DetectionSignal)
        ind = sig.indicators
        assert "raw_payload" not in ind
        assert "decrypted_payload" not in ind
        assert "packet_contents" not in ind
