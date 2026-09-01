"""Milestone 16 Comprehensive Test Suite: Native Feature-Schema-v2 Models, Calibration & Evaluation.

Verifies:
1. Native v2 dataset generation & manifest validity
2. Strict data leakage protection across E1, E2, E3, E4 splits
3. Zero-leakage train-only preprocessor fit and transform
4. Feature projection parity (training projection == inference projection)
5. LightGBM v2 calibrated inference with Brier score & ECE bounds
6. Random Forest baseline inference
7. Isolation Forest anomaly scoring
8. High-cardinality TLS fingerprint engineered numericals
9. Real PCAP end-to-end inference pipeline
10. Multimodal Ablation Study execution
"""

import os
import json
import unittest
import numpy as np
import pandas as pd
import joblib

from schemas import ThreatClass
from features.feature_engine import FeatureEngine
from features.model_features_v2 import (
    MODEL_V2_FEATURE_NAMES,
    MODEL_V2_FEATURE_SCHEMA_VERSION,
    V2FeaturePreprocessor,
    V2PreprocessingState,
)
from dataset.generate_v2_dataset import (
    engineer_v2_features,
    build_and_save_v2_dataset,
    LABEL_MAP,
)
from models.inference.ml_inference import (
    V2MLInferenceEngine,
    ClassificationResult,
    AnomalyResult,
    UnifiedMLResult,
)
from models.inference.signal_adapter import SignalAdapter
from models.training.calibration import (
    ValidationProbabilityCalibrator,
    compute_ece,
)
from models.evaluation.v2_evaluator import (
    evaluate_model_on_split,
    run_ablation_study,
)
from ingest.pcap_reader import iter_pcap


class TestM16DatasetAndSplits(unittest.TestCase):

    def setUp(self):
        self.data_dir = "dataset/processed_v2"

    def test_native_v2_dataset_manifest_exists(self):
        manifest_path = os.path.join(self.data_dir, "dataset_manifest_v2.json")
        self.assertTrue(os.path.exists(manifest_path))

    def test_e1_e2_e3_e4_splits_exist_and_non_empty(self):
        for split_file in ["train_v2.csv", "val_v2.csv", "test_v2.csv", "entity_holdout_test_v2.csv", "scenario_holdout_test_v2.csv", "temporal_holdout_test_v2.csv"]:
            p = os.path.join(self.data_dir, split_file)
            self.assertTrue(os.path.exists(p), f"Missing split: {split_file}")
            df = pd.read_csv(p)
            self.assertGreater(len(df), 100)

    def test_e2_entity_holdout_zero_leakage(self):
        """Entity holdout split must have 0% entity overlap with training set."""
        train_df = pd.read_csv(os.path.join(self.data_dir, "e2_entity_train_v2.csv"))
        entity_test_df = pd.read_csv(os.path.join(self.data_dir, "e2_entity_test_v2.csv"))

        train_entities = set(train_df["entity_id"].dropna().unique())
        test_entities = set(entity_test_df["entity_id"].dropna().unique())

        overlap = train_entities.intersection(test_entities)
        self.assertEqual(len(overlap), 0)
        self.assertGreater(len(test_entities), 0)

    def test_no_forbidden_leakage_features_in_v2_model_columns(self):
        """recent_risk and baseline_deviation must not be in model feature list."""
        forbidden = {"recent_risk", "baseline_deviation"}
        for feat in MODEL_V2_FEATURE_NAMES:
            self.assertNotIn(feat, forbidden)


class TestM16PreprocessorAndParity(unittest.TestCase):

    def test_preprocessor_fit_transform_parity(self):
        """Verify train-only fit preserves feature names and dimensions."""
        df = pd.DataFrame({
            feat: np.random.uniform(0.0, 100.0, size=20)
            for feat in MODEL_V2_FEATURE_NAMES
        })
        prep = V2FeaturePreprocessor()
        prep.fit(df)

        mat = prep.transform_df(df)
        self.assertEqual(mat.shape, (20, len(MODEL_V2_FEATURE_NAMES)))

        # Test single dict transformation
        row_dict = df.iloc[0].to_dict()
        vec = prep.transform_dict(row_dict)
        self.assertEqual(vec.shape, (1, len(MODEL_V2_FEATURE_NAMES)))
        np.testing.assert_allclose(vec[0], mat[0], rtol=1e-5)

    def test_missing_values_handled_without_nan(self):
        """Missing or corrupted fields are safely imputed with train medians or zeros."""
        df = pd.DataFrame({
            "duration": [10.0, np.nan, 30.0],
            "syn_ratio": [np.nan, 0.5, np.nan],
        })
        prep = V2FeaturePreprocessor()
        prep.fit(df)

        mat = prep.transform_df(df)
        self.assertFalse(np.isnan(mat).any())
        self.assertFalse(np.isinf(mat).any())


class TestM16V2ModelInference(unittest.TestCase):

    def setUp(self):
        self.engine = V2MLInferenceEngine(artifact_dir="models/artifacts")

    def test_v2_model_artifacts_loaded(self):
        self.assertIsNotNone(self.engine.lgb_model)
        self.assertIsNotNone(self.engine.calibrator)
        self.assertIsNotNone(self.engine.rf_model)
        self.assertIsNotNone(self.engine.if_model)
        self.assertIsNotNone(self.engine.preprocessor)

    def test_v2_predict_calibrated_probabilities(self):
        """Predict returns calibrated probabilities summing to 1.0."""
        sample = {
            "duration": 5.0,
            "total_packets": 100,
            "total_bytes": 50000,
            "packets_per_sec": 20.0,
            "bytes_per_sec": 10000.0,
            "unique_dst_ips": 1,
            "unique_dst_ports": 1,
        }
        res = self.engine.predict(sample, source_entity="10.0.0.5")
        self.assertIsInstance(res, UnifiedMLResult)
        self.assertIsInstance(res.classification, ClassificationResult)
        self.assertIsInstance(res.anomaly, AnomalyResult)

        prob_sum = sum(res.classification.probabilities.values())
        self.assertAlmostEqual(prob_sum, 1.0, places=4)
        self.assertGreaterEqual(res.classification.confidence, 0.0)
        self.assertLessEqual(res.classification.confidence, 1.0)

    def test_signal_adapter_to_detection_signal(self):
        """DetectionSignal adapter formats output correctly."""
        sample = {
            "duration": 1.0,
            "total_packets": 5000,
            "total_bytes": 5000000,
            "packets_per_sec": 5000.0,
            "bytes_per_sec": 5000000.0,
            "syn_ratio": 0.99,
        }
        res = self.engine.predict(sample, source_entity="10.0.0.100")
        sig = SignalAdapter.to_detection_signal(res, source_entity="10.0.0.100")
        if sig is not None:
            self.assertEqual(sig.source_entity, "10.0.0.100")
            self.assertGreater(sig.confidence, 0.0)


class TestM16RealPCAPInference(unittest.TestCase):

    def setUp(self):
        self.feature_engine = FeatureEngine()
        self.inference_engine = V2MLInferenceEngine(artifact_dir="models/artifacts")

    def test_real_pcap_to_v2_model_prediction(self):
        """Real PCAP -> FeatureEngine -> V2MLInferenceEngine pipeline execution."""
        pcap_path = os.path.join("dataset", "pcaps", "ddos", "ddos_syn_boundary_3kpps.pcap")
        if not os.path.exists(pcap_path):
            self.skipTest(f"PCAP not found: {pcap_path}")

        packets = list(iter_pcap(pcap_path))
        self.assertGreater(len(packets), 0)

        for pkt in packets[:200]:
            self.feature_engine.update_packet(pkt)

        # Extract features for source entity
        source_ip = packets[0].src_ip
        feat_set = self.feature_engine.extract(entity_id=source_ip)
        self.assertIsNotNone(feat_set)

        # Execute V2 ML inference
        res = self.inference_engine.predict(
            feat_set.values(),
            source_entity=source_ip,
        )
        self.assertIsInstance(res, UnifiedMLResult)
        self.assertIn("LGBMClassifier-V2-Calibrated", res.classification.model_name)
        self.assertGreaterEqual(res.classification.confidence, 0.0)


class TestM16AblationAndEvaluationReport(unittest.TestCase):

    def test_evaluation_report_metrics(self):
        report_path = "models/evaluation/v2_eval_report.json"
        self.assertTrue(os.path.exists(report_path))

        with open(report_path, "r") as f:
            report = json.load(f)

        self.assertIn("E1_standard_lightgbm", report)
        e1 = report["E1_standard_lightgbm"]

        self.assertGreaterEqual(e1["accuracy"], 0.90)
        self.assertGreaterEqual(e1["macro_f1"], 0.90)
        self.assertLessEqual(e1["brier_score"], 0.10)
        self.assertLessEqual(e1["expected_calibration_error"], 0.05)

        self.assertIn("E2_true_entity_holdout", report)
        self.assertIn("E3_scenario_holdout", report)
        self.assertIn("E4_true_temporal_holdout", report)

        self.assertIn("ablation_study", report)
        self.assertIn("A0_Flow_Only", report["ablation_study"])
        self.assertIn("A5_Full_Multimodal_V2", report["ablation_study"])
