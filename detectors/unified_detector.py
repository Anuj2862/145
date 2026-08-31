"""Unified Member-2 Detection Orchestration Layer (PS 26145).

Orchestrates all Member-2 detection sources:
  1. Six Deterministic Baseline Detectors (DDoS, C2, DNS, Encrypted, Recon, Exfiltration)
  2. LightGBM Primary Multiclass ML Classifier
  3. Isolation Forest Unsupervised Anomaly Detector

DESIGN & BOUNDARY PRINCIPLES:
  - NO PREMATURE FUSION: Does NOT combine or collapse signals. Emits independent,
    explainable DetectionSignal objects. Member-3 owns multi-signal fusion.
  - BENIGN HANDLING: Benign traffic from LightGBM generates NO false threat signals.
  - ANOMALY COEXISTENCE: Isolation Forest anomalies on benign classifier traffic produce
    independent UNKNOWN_ANOMALY signals with DetectorType.UNSUPERVISED_ANOMALY.
  - FAILURE ISOLATION: A failure in ML models or a specific baseline detector will
    NEVER block other detectors from executing.
  - DETERMINISTIC ORDERING: Signals are returned in strict, predictable sequence:
    [baseline_signals..., lightgbm_signal, isolation_forest_signal].
"""

import traceback
from typing import List, Optional, Any, Dict, Union
import numpy as np

from schemas import (
    DetectionSignal,
    ThreatClass,
    DetectorType,
    FeatureVector,
)
from detectors.engine import DetectionEngine, DetectionContext, DetectorResult
from detectors.ddos_detector import DDoSBaselineDetector
from detectors.c2_detector import C2BeaconDetector
from detectors.dns_detector import DNSAnomalyDetector
from detectors.encrypted_detector import EncryptedThreatDetector
from detectors.recon_detector import ReconDetector
from detectors.exfil_detector import ExfiltrationDetector

from models.inference import (
    MLInferenceEngine,
    SignalAdapter,
    FeatureVectorAdapter,
    ClassificationResult,
    AnomalyResult,
    UnifiedMLResult,
)


class UnifiedM2Orchestrator:
    """Unified Member-2 Detection Orchestrator for UniGuard AI.
    
    Coordinates deterministic rule-based baseline detectors and ML inference models,
    returning an ordered, un-fused collection of independent DetectionSignal objects.
    """

    def __init__(
        self,
        artifact_dir: str = "models/artifacts",
        enable_ml: bool = True,
        enable_baseline: bool = True,
    ):
        self.artifact_dir = artifact_dir
        self.enable_ml = enable_ml
        self.enable_baseline = enable_baseline

        # 1. Initialize Baseline Detection Engine
        self.baseline_engine = DetectionEngine()
        if self.enable_baseline:
            self._register_baseline_detectors()

        # 2. Safely initialize ML Inference Engine
        self.ml_engine: Optional[MLInferenceEngine] = None
        self.ml_error: Optional[str] = None
        if self.enable_ml:
            self._initialize_ml_engine()

    def _register_baseline_detectors(self) -> None:
        """Register all six deterministic baseline detectors."""
        self.baseline_engine.register(DDoSBaselineDetector())
        self.baseline_engine.register(C2BeaconDetector())
        self.baseline_engine.register(DNSAnomalyDetector())
        self.baseline_engine.register(EncryptedThreatDetector())
        self.baseline_engine.register(ReconDetector())
        self.baseline_engine.register(ExfiltrationDetector())

    def _initialize_ml_engine(self) -> None:
        """Safely load ML models; failures set ml_engine=None without blocking baseline detectors."""
        try:
            self.ml_engine = MLInferenceEngine(artifact_dir=self.artifact_dir)
            self.ml_error = None
        except Exception as exc:
            self.ml_engine = None
            self.ml_error = f"MLInferenceEngine load failed: {exc}"

    def run_all(
        self,
        ctx: DetectionContext,
        feature_matrix: Optional[Union[np.ndarray, List[float]]] = None,
    ) -> List[DetectorResult]:
        """Execute all baseline detectors and ML models, returning structured DetectorResult objects.
        
        Preserves failure isolation and detailed diagnostic messages for every detection source.
        """
        results: List[DetectorResult] = []

        # 1. Run deterministic baseline detectors
        if self.enable_baseline:
            baseline_results = self.baseline_engine.run(ctx)
            results.extend(baseline_results)

        # 2. Run ML models if enabled
        if self.enable_ml:
            # Extract or validate 52-feature vector for ML
            ml_feats: Optional[np.ndarray] = None
            feat_error: Optional[str] = None

            if feature_matrix is not None:
                try:
                    ml_feats = self.ml_engine.validate_features(feature_matrix) if self.ml_engine else np.array(feature_matrix, dtype=np.float64).reshape(1, -1)
                except Exception as exc:
                    feat_error = f"Feature matrix validation failed: {exc}"
            elif ctx.feature_vector is not None:
                try:
                    ml_feats = FeatureVectorAdapter.feature_vector_to_features(ctx.feature_vector)
                except Exception as exc:
                    feat_error = f"FeatureVector conversion failed: {exc}"

            # 2a. LightGBM Primary Classifier
            if self.ml_engine is None:
                results.append(
                    DetectorResult(
                        detector_name="LightGBMClassifier",
                        error=self.ml_error or "MLInferenceEngine unavailable",
                    )
                )
            elif feat_error:
                results.append(
                    DetectorResult(
                        detector_name="LightGBMClassifier",
                        error=feat_error,
                    )
                )
            else:
                try:
                    lgb_res = self.ml_engine.predict_classification(ml_feats, use_fallback_rf=False)
                    if isinstance(lgb_res, list):
                        lgb_res = lgb_res[0]

                    lgb_signal = SignalAdapter.to_detection_signal(
                        lgb_res,
                        source_entity=ctx.source_entity,
                        timestamp_iso=ctx.timestamp_iso,
                    )
                    results.append(
                        DetectorResult(detector_name="LightGBMClassifier", signal=lgb_signal)
                    )
                except Exception as exc:
                    results.append(
                        DetectorResult(
                            detector_name="LightGBMClassifier",
                            error=f"LightGBM inference error: {exc}\n{traceback.format_exc()}",
                        )
                    )

            # 2b. Isolation Forest Anomaly Detector
            if self.ml_engine is None:
                results.append(
                    DetectorResult(
                        detector_name="IsolationForestAnomaly",
                        error=self.ml_error or "MLInferenceEngine unavailable",
                    )
                )
            elif feat_error:
                results.append(
                    DetectorResult(
                        detector_name="IsolationForestAnomaly",
                        error=feat_error,
                    )
                )
            else:
                try:
                    lgb_res = self.ml_engine.predict_classification(ml_feats, use_fallback_rf=False)
                    if isinstance(lgb_res, list):
                        lgb_res = lgb_res[0]

                    if_res = self.ml_engine.predict_anomaly(ml_feats)
                    if isinstance(if_res, list):
                        if_res = if_res[0]

                    unified = UnifiedMLResult(
                        classification=lgb_res,
                        anomaly=if_res,
                        source_entity=ctx.source_entity,
                        timestamp_iso=ctx.timestamp_iso,
                    )

                    # SignalAdapter produces UNKNOWN_ANOMALY if IF flags anomaly on Benign LightGBM traffic,
                    # or None if both agree it's benign. If LightGBM already flagged a known threat,
                    # IF anomaly evidence is attached to the LightGBM signal or produced independently.
                    if not lgb_res.is_threat and if_res.is_anomaly:
                        if_signal = SignalAdapter.to_detection_signal(
                            unified,
                            source_entity=ctx.source_entity,
                            timestamp_iso=ctx.timestamp_iso,
                        )
                    else:
                        if_signal = None

                    results.append(
                        DetectorResult(detector_name="IsolationForestAnomaly", signal=if_signal)
                    )
                except Exception as exc:
                    results.append(
                        DetectorResult(
                            detector_name="IsolationForestAnomaly",
                            error=f"Isolation Forest inference error: {exc}\n{traceback.format_exc()}",
                        )
                    )

        return results

    def evaluate(
        self,
        ctx: DetectionContext,
        feature_matrix: Optional[Union[np.ndarray, List[float]]] = None,
    ) -> List[DetectionSignal]:
        """Evaluate all detection sources and return an ordered list of valid DetectionSignals.
        
        OUTPUT ORDER GUARANTEE (Deterministic):
          1. Deterministic baseline signals (in registration order)
          2. LightGBM primary classifier signal (if threat detected)
          3. Isolation Forest anomaly signal (if unlabelled anomaly detected)
        """
        results = self.run_all(ctx, feature_matrix=feature_matrix)
        return [r.signal for r in results if r.succeeded and r.signal is not None]

    def signals(
        self,
        ctx: DetectionContext,
        feature_matrix: Optional[Union[np.ndarray, List[float]]] = None,
    ) -> List[DetectionSignal]:
        """Convenience alias matching DetectionEngine.signals interface."""
        return self.evaluate(ctx, feature_matrix=feature_matrix)
