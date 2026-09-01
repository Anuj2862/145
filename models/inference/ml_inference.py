"""Production ML Inference Engine for UniGuard Threat Detection System (Member 2).

Provides high-performance, validated inference across LightGBM (primary classifier),
Random Forest (baseline/fallback), and Isolation Forest (unsupervised anomaly detector).
"""

# lightgbm MUST be imported first to avoid Windows C++ DLL initialization conflicts with sklearn
import lightgbm as lgb

import os
import json
import time
import uuid
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
import numpy as np
import pandas as pd
import joblib

from schemas import ThreatClass
from features.feature_contract import (
    LEGACY_MODEL_FEATURE_NAMES,
    MODEL_FEATURE_SCHEMA_VERSION,
    ModelVector,
    check_model_feature_compatibility,
    legacy_model_schema,
    validate_feature_schema,
)
from features.model_features_v2 import (
    MODEL_V2_FEATURE_NAMES,
    MODEL_V2_FEATURE_SCHEMA_VERSION,
    V2FeaturePreprocessor,
    V2PreprocessingState,
)
from models.training.calibration import ValidationProbabilityCalibrator

EXPECTED_FEATURE_NAMES = list(LEGACY_MODEL_FEATURE_NAMES)
EXPECTED_FEATURE_COUNT = len(EXPECTED_FEATURE_NAMES)

LABEL_MAPPING: Dict[int, Tuple[str, Optional[ThreatClass]]] = {
    0: ("BENIGN", None),
    1: ("VOLUMETRIC_DDOS", ThreatClass.VOLUMETRIC_DDOS),
    2: ("BOTNET_C2_BEACONING", ThreatClass.BOTNET_C2_BEACONING),
    3: ("DGA_DNS_TUNNELLING", ThreatClass.DGA_DNS_TUNNELLING),
    4: ("ENCRYPTED_MALWARE", ThreatClass.ENCRYPTED_MALWARE),
    5: ("RECON_PORT_SCAN", ThreatClass.RECON_PORT_SCAN),
    6: ("DATA_EXFILTRATION", ThreatClass.DATA_EXFILTRATION),
}


@dataclass
class ClassificationResult:
    """Encapsulates supervised multiclass threat classification output."""
    predicted_class_index: int
    predicted_class_name: str
    threat_class: Optional[ThreatClass]
    probabilities: Dict[str, float]
    confidence: float
    is_threat: bool
    model_name: str
    inference_latency_ms: float


@dataclass
class AnomalyResult:
    """Encapsulates unsupervised Isolation Forest anomaly detection output.
    
    NOTE: Isolation Forest does NOT identify the specific threat family.
    It indicates whether traffic deviates statistically from learned benign baseline.
    """
    is_anomaly: bool
    anomaly_score: float  # decision_function score (lower/negative = more anomalous)
    normalized_confidence: float  # bounded score confidence [0.0, 1.0]
    model_name: str = "IsolationForest"
    inference_latency_ms: float = 0.0
    note: str = "IsolationForest detects benign baseline deviations; does NOT classify threat family"


@dataclass
class UnifiedMLResult:
    """Coexistence container holding both classification & anomaly evidence.
    
    Exposes both LightGBM known-threat classification and Isolation Forest
    unsupervised anomaly detection for Member 3 fusion reasoning.
    """
    classification: ClassificationResult
    anomaly: AnomalyResult
    source_entity: str = "unknown"
    target_entity: Optional[str] = None
    timestamp_iso: str = ""


class MLInferenceEngine:
    """Production ML Inference Engine for UniGuard Threat Detection.
    
    Loads trained LightGBM, Random Forest, and Isolation Forest model artifacts,
    validates 52-feature input contracts, and executes low-latency predictions.
    """

    def __init__(self, artifact_dir: str = "models/artifacts"):
        self.artifact_dir = os.path.abspath(artifact_dir)
        self.lgb_model = None
        self.rf_model = None
        self.if_model = None
        self.metadata = None
        self.model_feature_schema_version = MODEL_FEATURE_SCHEMA_VERSION
        self.feature_names = EXPECTED_FEATURE_NAMES

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Safely load trained model artifacts from artifacts directory.
        
        Raises FileNotFoundError if any expected artifact is missing.
        Does NOT automatically trigger retraining during inference.
        """
        lgb_path = os.path.join(self.artifact_dir, "lgb_multiclass_model.joblib")
        rf_path = os.path.join(self.artifact_dir, "rf_baseline_model.joblib")
        if_path = os.path.join(self.artifact_dir, "isolation_forest_model.joblib")
        meta_path = os.path.join(self.artifact_dir, "lgb_multiclass_metadata.json")
        rf_meta_path = os.path.join(self.artifact_dir, "rf_baseline_metadata.json")
        if_meta_path = os.path.join(self.artifact_dir, "isolation_forest_metadata.json")

        missing_files = []
        if not os.path.exists(lgb_path):
            missing_files.append(lgb_path)
        if not os.path.exists(rf_path):
            missing_files.append(rf_path)
        if not os.path.exists(if_path):
            missing_files.append(if_path)

        if missing_files:
            raise FileNotFoundError(
                f"Required production ML model artifact(s) missing: {missing_files}. "
                f"Please ensure models are trained before invoking inference."
            )

        self.lgb_model = joblib.load(lgb_path)
        self.rf_model = joblib.load(rf_path)
        self.if_model = joblib.load(if_path)
        if hasattr(self.rf_model, "n_jobs"):
            self.rf_model.n_jobs = 1
        if hasattr(self.if_model, "n_jobs"):
            self.if_model.n_jobs = 1

        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                self.metadata = json.load(f)
                if "feature_names" in self.metadata:
                    self.feature_names = self.metadata["feature_names"]
                check_model_feature_compatibility(
                    self.metadata,
                    legacy_model_schema(),
                    allow_legacy_adapter=True,
                )

        for path in (rf_meta_path, if_meta_path):
            if os.path.exists(path):
                with open(path, "r") as f:
                    check_model_feature_compatibility(
                        json.load(f),
                        legacy_model_schema(),
                        allow_legacy_adapter=True,
                    )

    def validate_features(self, X: Union[np.ndarray, pd.DataFrame, pd.Series, List[float], ModelVector]) -> np.ndarray:
        """Validate input features against strict 52-feature contract.
        
        Enforces:
          - Feature count == 52
          - Feature column names and ordering (for DataFrame inputs)
          - Absence of NaN/Inf values
          
        Returns clean C-contiguous np.ndarray of shape (N, 52) or (1, 52).
        """
        if isinstance(X, ModelVector):
            self.validate_model_vector(X)
            X_arr = X.as_2d_array()
        elif isinstance(X, list):
            X_arr = np.array(X, dtype=np.float64)
        elif isinstance(X, pd.Series):
            if len(X) != EXPECTED_FEATURE_COUNT:
                raise ValueError(
                    f"Invalid feature count in Series: expected {EXPECTED_FEATURE_COUNT}, got {len(X)}"
                )
            X_arr = X.values.astype(np.float64)
        elif isinstance(X, pd.DataFrame):
            if X.shape[1] != EXPECTED_FEATURE_COUNT:
                raise ValueError(
                    f"Invalid feature count in DataFrame: expected {EXPECTED_FEATURE_COUNT}, got {X.shape[1]}"
                )
            # Verify feature names and ordering if present
            df_cols = list(X.columns)
            if df_cols != self.feature_names:
                missing = set(self.feature_names) - set(df_cols)
                extra = set(df_cols) - set(self.feature_names)
                if missing or extra:
                    raise ValueError(
                        f"Feature column mismatch! Missing: {sorted(missing)}, Extra: {sorted(extra)}"
                    )
                # Reorder columns to match expected training ordering
                X = X[self.feature_names]
            X_arr = X.values.astype(np.float64)
        elif isinstance(X, np.ndarray):
            X_arr = X.astype(np.float64)
        else:
            raise TypeError(f"Unsupported feature input type: {type(X)}")

        # Format shape to 2D matrix
        if X_arr.ndim == 1:
            if len(X_arr) != EXPECTED_FEATURE_COUNT:
                raise ValueError(
                    f"Invalid 1D feature vector length: expected {EXPECTED_FEATURE_COUNT}, got {len(X_arr)}"
                )
            X_arr = X_arr.reshape(1, -1)
        elif X_arr.ndim == 2:
            if X_arr.shape[1] != EXPECTED_FEATURE_COUNT:
                raise ValueError(
                    f"Invalid 2D feature matrix width: expected {EXPECTED_FEATURE_COUNT}, got {X_arr.shape[1]}"
                )
        else:
            raise ValueError(f"Invalid feature array dimensions: expected 1D or 2D, got {X_arr.ndim}D")

        if np.any(np.isnan(X_arr)) or np.any(np.isinf(X_arr)):
            raise ValueError("Input feature matrix contains NaN or Inf values")

        return np.ascontiguousarray(X_arr, dtype=np.float64)

    def validate_model_vector(self, vector: ModelVector) -> None:
        """Fail loudly when a versioned model vector drifts from the loaded model contract."""
        if vector.schema_version != self.model_feature_schema_version:
            raise ValueError(
                "Model vector schema version mismatch: "
                f"expected {self.model_feature_schema_version}, got {vector.schema_version}"
            )
        validate_feature_schema(
            actual_feature_names=vector.feature_names,
            expected_feature_names=self.feature_names,
            actual_schema_version=vector.schema_version,
            expected_schema_version=self.model_feature_schema_version,
        ).raise_for_error()

    def predict_classification(
        self,
        X: Union[np.ndarray, pd.DataFrame, pd.Series, List[float]],
        use_fallback_rf: bool = False,
    ) -> Union[ClassificationResult, List[ClassificationResult]]:
        """Execute supervised multiclass threat classification.
        
        Default model: LightGBM (primary classifier).
        Set use_fallback_rf=True to use Random Forest (secondary/fallback classifier).
        """
        X_mat = self.validate_features(X)
        model = self.rf_model if use_fallback_rf else self.lgb_model
        model_name = "RandomForestClassifier" if use_fallback_rf else "LGBMClassifier"

        t0 = time.perf_counter()
        if hasattr(model, "predict_proba"):
            probas = model.predict_proba(X_mat)
        else:
            # Booster object
            probas = model.predict(X_mat)
        pred_time_ms = max(time.perf_counter() - t0, 1e-12) * 1000.0 / len(X_mat)

        results = []
        for i in range(len(X_mat)):
            sample_proba = probas[i]
            pred_idx = int(np.argmax(sample_proba))
            conf = float(sample_proba[pred_idx])

            class_name, threat_cls = LABEL_MAPPING.get(pred_idx, ("UNKNOWN", None))
            prob_dict = {LABEL_MAPPING[k][0]: float(sample_proba[k]) for k in range(7)}

            res = ClassificationResult(
                predicted_class_index=pred_idx,
                predicted_class_name=class_name,
                threat_class=threat_cls,
                probabilities=prob_dict,
                confidence=conf,
                is_threat=(pred_idx > 0),
                model_name=model_name,
                inference_latency_ms=round(pred_time_ms, 4),
            )
            results.append(res)

        return results[0] if len(results) == 1 else results

    def predict_anomaly(
        self,
        X: Union[np.ndarray, pd.DataFrame, pd.Series, List[float]],
    ) -> Union[AnomalyResult, List[AnomalyResult]]:
        """Execute unsupervised Isolation Forest anomaly detection.
        
        Isolation Forest predicts outliers relative to benign training baseline.
        Does NOT classify specific threat family.
        """
        X_mat = self.validate_features(X)

        t0 = time.perf_counter()
        scores = self.if_model.decision_function(X_mat)
        preds = self.if_model.predict(X_mat)
        pred_time_ms = max(time.perf_counter() - t0, 1e-12) * 1000.0 / len(X_mat)

        results = []
        for i in range(len(X_mat)):
            score = float(scores[i])
            is_anomaly = bool(preds[i] == -1)

            # Map decision_function score (approx range [-0.2, +0.1]) to normalized confidence [0.0, 1.0]
            # Lower score = higher anomaly confidence
            norm_conf = float(np.clip(1.0 / (1.0 + np.exp(score * 20.0)), 0.0, 1.0)) if is_anomaly else float(np.clip(1.0 / (1.0 + np.exp(-score * 20.0)), 0.0, 1.0))

            res = AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=round(score, 6),
                normalized_confidence=round(norm_conf, 4),
                model_name="IsolationForest",
                inference_latency_ms=round(pred_time_ms, 4),
            )
            results.append(res)

        return results[0] if len(results) == 1 else results

    def predict_unified(
        self,
        X: Union[np.ndarray, pd.DataFrame, pd.Series, List[float]],
        source_entity: str = "unknown",
        target_entity: Optional[str] = None,
        timestamp_iso: Optional[str] = None,
    ) -> UnifiedMLResult:
        """Execute combined classification and anomaly detection for a single sample.
        
        Exposes both LightGBM known threat classification and Isolation Forest
        unsupervised anomaly detection for Member 3 fusion reasoning.
        """
        clf_res = self.predict_classification(X)
        if isinstance(clf_res, list):
            clf_res = clf_res[0]

        anom_res = self.predict_anomaly(X)
        if isinstance(anom_res, list):
            anom_res = anom_res[0]

        if not timestamp_iso:
            timestamp_iso = pd.Timestamp.now(tz="UTC").isoformat()

        return UnifiedMLResult(
            classification=clf_res,
            anomaly=anom_res,
            source_entity=source_entity,
            target_entity=target_entity,
            timestamp_iso=timestamp_iso,
        )

    def benchmark_inference_latency(self, X_sample: np.ndarray, num_runs: int = 100) -> Dict[str, Dict[str, float]]:
        """Benchmark inference latency on sample data for all three models."""
        X_mat = self.validate_features(X_sample)

        # Warmup
        _ = self.predict_classification(X_mat, use_fallback_rf=False)
        _ = self.predict_classification(X_mat, use_fallback_rf=True)
        _ = self.predict_anomaly(X_mat)

        # LightGBM
        t0 = time.perf_counter()
        for _ in range(num_runs):
            _ = self.predict_classification(X_mat, use_fallback_rf=False)
        lgb_time = max((time.perf_counter() - t0) / num_runs, 1e-12)

        # Random Forest
        t0 = time.perf_counter()
        for _ in range(num_runs):
            _ = self.predict_classification(X_mat, use_fallback_rf=True)
        rf_time = max((time.perf_counter() - t0) / num_runs, 1e-12)

        # Isolation Forest
        t0 = time.perf_counter()
        for _ in range(num_runs):
            _ = self.predict_anomaly(X_mat)
        if_time = max((time.perf_counter() - t0) / num_runs, 1e-12)

        n_samples = len(X_mat)
        return {
            "lightgbm": {
                "per_sample_us": round((lgb_time / n_samples) * 1e6, 4),
                "throughput_samples_per_sec": round(n_samples / lgb_time, 2),
            },
            "random_forest": {
                "per_sample_us": round((rf_time / n_samples) * 1e6, 4),
                "throughput_samples_per_sec": round(n_samples / rf_time, 2),
            },
            "isolation_forest": {
                "per_sample_us": round((if_time / n_samples) * 1e6, 4),
                "throughput_samples_per_sec": round(n_samples / if_time, 2),
            },
        }


class V2MLInferenceEngine:
    """Production ML Inference Engine for Native FeatureSchema-v2 Models (M16).

    Loads native v2 artifacts:
      - lgb_multiclass_v2.joblib
      - lgb_calibrator_v2.joblib
      - rf_baseline_v2.joblib
      - isolation_forest_v2.joblib
      - v2_preprocessor.joblib
    """

    def __init__(self, artifact_dir: str = "models/artifacts"):
        self.artifact_dir = os.path.abspath(artifact_dir)
        self.lgb_model = None
        self.calibrator = None
        self.rf_model = None
        self.if_model = None
        self.preprocessor = None
        self.metadata = None
        self.feature_names = list(MODEL_V2_FEATURE_NAMES)
        self.feature_schema_version = MODEL_V2_FEATURE_SCHEMA_VERSION
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        lgb_path = os.path.join(self.artifact_dir, "lgb_multiclass_v2.joblib")
        cal_path = os.path.join(self.artifact_dir, "lgb_calibrator_v2.joblib")
        rf_path = os.path.join(self.artifact_dir, "rf_baseline_v2.joblib")
        if_path = os.path.join(self.artifact_dir, "isolation_forest_v2.joblib")
        prep_path = os.path.join(self.artifact_dir, "v2_preprocessor.joblib")
        meta_path = os.path.join(self.artifact_dir, "lgb_multiclass_v2_metadata.json")

        self.lgb_model = joblib.load(lgb_path)
        self.calibrator = joblib.load(cal_path)
        self.rf_model = joblib.load(rf_path)
        self.if_model = joblib.load(if_path)
        self.preprocessor = joblib.load(prep_path)

        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                self.metadata = json.load(f)

    def predict(
        self,
        features: Union[Dict[str, Any], np.ndarray, pd.DataFrame],
        source_entity: str = "unknown",
        target_entity: Optional[str] = None,
        timestamp_iso: Optional[str] = None,
    ) -> UnifiedMLResult:
        """Execute calibrated v2 classification and anomaly inference."""
        if isinstance(features, dict):
            X_mat = self.preprocessor.transform_dict(features)
        elif isinstance(features, pd.DataFrame):
            X_mat = self.preprocessor.transform_df(features)
        elif isinstance(features, np.ndarray):
            X_mat = features if features.ndim == 2 else features.reshape(1, -1)
        else:
            raise TypeError(f"Unsupported features type: {type(features)}")

        # Classification with Calibrated Probabilities
        t0 = time.perf_counter()
        raw_probs = self.lgb_model.predict_proba(X_mat)
        cal_probs = self.calibrator.calibrate(raw_probs)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        pred_idx = int(np.argmax(cal_probs, axis=1)[0])
        prob_dict = {
            cname: float(cal_probs[0, idx])
            for idx, (cname, _) in LABEL_MAPPING.items()
            if idx < cal_probs.shape[1]
        }
        pred_name, threat_cls = LABEL_MAPPING[pred_idx]
        conf = float(cal_probs[0, pred_idx])
        is_threat = (pred_idx != 0)

        clf_res = ClassificationResult(
            predicted_class_index=pred_idx,
            predicted_class_name=pred_name,
            threat_class=threat_cls,
            probabilities=prob_dict,
            confidence=conf,
            is_threat=is_threat,
            model_name="LGBMClassifier-V2-Calibrated",
            inference_latency_ms=latency_ms,
        )

        # Anomaly Detection
        t0 = time.perf_counter()
        raw_score = float(self.if_model.decision_function(X_mat)[0])
        is_anom = bool(self.if_model.predict(X_mat)[0] == -1)
        anom_latency_ms = (time.perf_counter() - t0) * 1000.0

        norm_conf = float(1.0 / (1.0 + np.exp(raw_score * 10.0)))
        anom_res = AnomalyResult(
            is_anomaly=is_anom,
            anomaly_score=raw_score,
            normalized_confidence=norm_conf,
            model_name="IsolationForest-V2",
            inference_latency_ms=anom_latency_ms,
        )

        if not timestamp_iso:
            timestamp_iso = pd.Timestamp.now(tz="UTC").isoformat()

        return UnifiedMLResult(
            classification=clf_res,
            anomaly=anom_res,
            source_entity=source_entity,
            target_entity=target_entity,
            timestamp_iso=timestamp_iso,
        )
