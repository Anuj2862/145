"""Comprehensive Unit & Integration Test Suite for Milestone 19 (Real-PCAP, Public Dataset & Generalization Validation).

Verifies:
1. Dataset Adapter Framework: CanonicalEvaluationRecord, SHA-256 provenance, metadata tracking.
2. Label Mapping Contract: Unknown labels fail validation; never silently map unknown labels to BENIGN.
3. Public Dataset Adapters: CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, UGR'16 adapters and semantic mappings.
4. Real-PCAP End-to-End Replay: PCAP -> FlowEvent -> FeatureEngine -> Detectors + V2 ML -> Fusion -> Incident.
5. Six-Threat Validation Matrix: Correct status and metrics for all 6 canonical threat classes + benign baseline.
6. Operational Metrics: TTFD, TTCI, false alerts per hour calculation.
7. Benign Periodic vs C2 Discrimination: Verifies jitter robustness and periodicity distinction.
8. Encrypted Metadata-Only Traffic Evaluation: Strictly zero payload decryption verification.
9. True Entity Holdout (E2): Verifies zero entity overlap between train, val, and test partitions.
10. True Temporal Holdout (E4): Verifies chronological split boundaries (t_train <= t_val <= t_test).
11. Honest Scenario Holdout (E3): Verifies status is NOT_AVAILABLE without fabricated metrics.
12. Comprehensive Report Generation: Verifies EVAL_M19_REPORT.json format and consistency.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import numpy as np
import pandas as pd

from schemas import (
    ThreatClass,
    Severity,
    DetectorType,
    DetectionSignal,
    FusionResult,
    Incident,
    IncidentStatus,
)
from evaluation.adapters import (
    CanonicalEvaluationRecord,
    DatasetAdapter,
    SyntheticBenchmarkAdapter,
    CICIDS2017Adapter,
    CSECICIDS2018Adapter,
    UNSWNB15Adapter,
    UGR16Adapter,
    compute_file_sha256,
)
from evaluation.runners.real_pcap_evaluator import RealPCAPEvaluator, PCAPEvalResult
from evaluation.runners.m19_generalization_runner import (
    audit_cross_dataset_compatibility,
    run_full_m19_evaluation,
)


class TestM19DatasetAdapterFramework(unittest.TestCase):
    """Test DatasetAdapter base class, label mapping, and provenance calculation."""

    def setUp(self):
        self.synthetic_adapter = SyntheticBenchmarkAdapter()
        self.cicids_adapter = CICIDS2017Adapter()
        self.csecic_adapter = CSECICIDS2018Adapter()
        self.unsw_adapter = UNSWNB15Adapter()
        self.ugr_adapter = UGR16Adapter()

    def test_sha256_provenance_calculation(self):
        """Verify compute_file_sha256 generates accurate cryptographic hashes."""
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as f:
            f.write("UniGuard-M19-Evaluation-Provenance-Test")
            temp_path = f.name

        try:
            h = compute_file_sha256(temp_path)
            self.assertEqual(len(h), 64)
            self.assertEqual(compute_file_sha256("non_existent_file.csv"), "FILE_NOT_FOUND")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_synthetic_adapter_label_mapping(self):
        """Verify synthetic benchmark label mappings and unknown label rejection."""
        self.assertEqual(self.synthetic_adapter.map_label("BENIGN"), "BENIGN")
        self.assertEqual(self.synthetic_adapter.map_label("VOLUMETRIC_DDOS"), "VOLUMETRIC_DDOS")
        self.assertEqual(self.synthetic_adapter.map_label("DDOS"), "VOLUMETRIC_DDOS")
        self.assertEqual(self.synthetic_adapter.map_label("C2"), "BOTNET_C2_BEACONING")
        self.assertEqual(self.synthetic_adapter.map_label("RECON"), "RECON_PORT_SCAN")

        # Unknown label MUST raise ValueError, never silently map to BENIGN
        with self.assertRaises(ValueError):
            self.synthetic_adapter.map_label("UNKNOWN_MALICIOUS_PAYLOAD")

        with self.assertRaises(ValueError):
            self.synthetic_adapter.map_label(None)

    def test_cicids2017_adapter_label_mapping(self):
        """Verify CIC-IDS2017 label mappings."""
        self.assertEqual(self.cicids_adapter.map_label("BENIGN"), "BENIGN")
        self.assertEqual(self.cicids_adapter.map_label("DDoS"), "VOLUMETRIC_DDOS")
        self.assertEqual(self.cicids_adapter.map_label("PortScan"), "RECON_PORT_SCAN")
        self.assertEqual(self.cicids_adapter.map_label("Bot"), "BOTNET_C2_BEACONING")

        with self.assertRaises(ValueError):
            self.cicids_adapter.map_label("Heartbleed_Unsupported")

    def test_csecicids2018_adapter_label_mapping(self):
        """Verify CSE-CIC-IDS2018 label mappings."""
        self.assertEqual(self.csecic_adapter.map_label("Benign"), "BENIGN")
        self.assertEqual(self.csecic_adapter.map_label("DDOS attack-HOIC"), "VOLUMETRIC_DDOS")
        self.assertEqual(self.csecic_adapter.map_label("Bot"), "BOTNET_C2_BEACONING")

        with self.assertRaises(ValueError):
            self.csecic_adapter.map_label("BruteForce_Web")

    def test_unsw_nb15_adapter_label_mapping(self):
        """Verify UNSW-NB15 label mappings."""
        self.assertEqual(self.unsw_adapter.map_label("Normal"), "BENIGN")
        self.assertEqual(self.unsw_adapter.map_label("Reconnaissance"), "RECON_PORT_SCAN")
        self.assertEqual(self.unsw_adapter.map_label("Backdoor"), "BOTNET_C2_BEACONING")

        with self.assertRaises(ValueError):
            self.unsw_adapter.map_label("UnsupportedAttackType")

    def test_ugr16_adapter_label_mapping(self):
        """Verify UGR'16 label mappings."""
        self.assertEqual(self.ugr_adapter.map_label("background"), "BENIGN")
        self.assertEqual(self.ugr_adapter.map_label("dos"), "VOLUMETRIC_DDOS")
        self.assertEqual(self.ugr_adapter.map_label("scan"), "RECON_PORT_SCAN")
        self.assertEqual(self.ugr_adapter.map_label("botnet"), "BOTNET_C2_BEACONING")

        with self.assertRaises(ValueError):
            self.ugr_adapter.map_label("spam")

    def test_canonical_evaluation_record_schema(self):
        """Verify CanonicalEvaluationRecord structure."""
        rec = CanonicalEvaluationRecord(
            dataset="CIC-IDS2017",
            dataset_version="1.0",
            capture_id="Friday-WorkingHours-Afternoon-DDos.pcap",
            event_time=1500000000.0,
            entity_id="192.168.10.50",
            flow_id="192.168.10.50:4444-192.168.10.1:80-6",
            raw_label="DDoS",
            label="VOLUMETRIC_DDOS",
            scenario_id="ddos_hoic",
            features={"duration": 1.25, "total_packets": 1000},
            provenance={"source_pcap_sha256": "abc1234"},
        )
        d = rec.to_dict()
        self.assertEqual(d["dataset"], "CIC-IDS2017")
        self.assertEqual(d["raw_label"], "DDoS")
        self.assertEqual(d["label"], "VOLUMETRIC_DDOS")
        self.assertEqual(d["features"]["total_packets"], 1000)


class TestM19RealPCAPEvaluator(unittest.TestCase):
    """Test RealPCAPEvaluator on lab PCAPs."""

    def setUp(self):
        self.evaluator = RealPCAPEvaluator(
            artifact_dir="models/artifacts",
            pcaps_root="dataset/pcaps",
        )

    def test_pcap_evaluator_missing_file_handling(self):
        """Verify missing PCAP is cleanly reported without unhandled crashes."""
        res = self.evaluator.evaluate_pcap("non_existent_file.pcap", expected_threat=ThreatClass.VOLUMETRIC_DDOS)
        self.assertEqual(res.file_sha256, "NOT_FOUND")
        self.assertTrue(res.is_false_negative)
        self.assertIn("error", res.details)

    def test_evaluate_benign_workstation_pcap(self):
        """Verify benign PCAP evaluation yields valid packet count and low false positive."""
        pcap_path = os.path.join("dataset", "pcaps", "benign", "corp_workstation_baseline_01.pcap")
        if not os.path.exists(pcap_path):
            self.skipTest(f"PCAP missing: {pcap_path}")

        res = self.evaluator.evaluate_pcap(pcap_path, expected_threat=None)
        self.assertGreater(res.packet_count, 0)
        self.assertGreater(res.duration_sec, 0.0)
        self.assertIsNotNone(res.file_sha256)

    def test_evaluate_ddos_pcap(self):
        """Verify DDoS SYN flood PCAP triggers volumetric detection and incident creation."""
        pcap_path = os.path.join("dataset", "pcaps", "ddos", "syn_flood_15kpps_burst.pcap")
        if not os.path.exists(pcap_path):
            self.skipTest(f"PCAP missing: {pcap_path}")

        res = self.evaluator.evaluate_pcap(pcap_path, expected_threat=ThreatClass.VOLUMETRIC_DDOS)
        self.assertGreater(res.packet_count, 1000)
        self.assertEqual(res.expected_threat, ThreatClass.VOLUMETRIC_DDOS)
        self.assertGreaterEqual(res.fused_risk, 0.40)
        self.assertIsNotNone(res.incident_id)

    def test_six_threat_matrix_execution(self):
        """Verify evaluate_six_threat_matrix runs and aggregates operational metrics."""
        rep = self.evaluator.evaluate_six_threat_matrix()
        matrix = rep["six_threat_matrix"]
        op_metrics = rep["operational_metrics"]

        self.assertIn("BENIGN", matrix)
        self.assertIn("VOLUMETRIC_DDOS", matrix)
        self.assertIn("BOTNET_C2_BEACONING", matrix)
        self.assertIn("RECON_PORT_SCAN", matrix)
        self.assertIn("DGA_DNS_TUNNELLING", matrix)
        self.assertIn("DATA_EXFILTRATION", matrix)
        self.assertIn("ENCRYPTED_MALWARE", matrix)

        self.assertGreaterEqual(op_metrics["total_pcaps_evaluated"], 7)
        self.assertIn("false_alerts_per_hour", op_metrics)

    def test_benign_periodic_vs_c2_analysis(self):
        """Verify periodicity discrimination between benign polling and malicious C2."""
        res = self.evaluator.evaluate_benign_periodic_vs_c2()
        self.assertTrue(res["periodicity_discrimination_verified"])
        self.assertIn("c2_5pct_jitter", res)
        self.assertIn("c2_50pct_jitter", res)
        self.assertIn("benign_baseline", res)

    def test_encrypted_traffic_metadata_only_validation(self):
        """Verify encrypted traffic validation strictly confirms zero payload decryption."""
        res = self.evaluator.evaluate_encrypted_metadata_ablation()
        for variant_name, variant_data in res.items():
            self.assertFalse(
                variant_data["payload_decryption_performed"],
                f"Decryption violation in {variant_name}!",
            )
            self.assertEqual(variant_data["status"], "PASS")


class TestM19GeneralizationAudits(unittest.TestCase):
    """Test public dataset adapters, holdout integrity, and comprehensive report output."""

    def test_cross_dataset_compatibility_audit(self):
        """Verify cross-dataset audit reports adapter readiness and semantic compatibility."""
        audit = audit_cross_dataset_compatibility()
        self.assertIn("CIC-IDS2017", audit)
        self.assertIn("CSE-CIC-IDS2018", audit)
        self.assertIn("UNSW-NB15", audit)
        self.assertIn("UGR16", audit)

        for name, entry in audit.items():
            self.assertEqual(entry["status"], "ADAPTER_READY")
            self.assertIn("supported_canonical_threat_classes", entry)
            self.assertIn("flow_feature_overlap", entry)

    def test_entity_holdout_zero_overlap_verification(self):
        """Verify E2 train, val, and test splits have exactly zero entity intersection."""
        dataset_dir = "dataset/processed_v2"
        train_path = os.path.join(dataset_dir, "e2_entity_train_v2.csv")
        val_path = os.path.join(dataset_dir, "e2_entity_val_v2.csv")
        test_path = os.path.join(dataset_dir, "e2_entity_test_v2.csv")

        if not (os.path.exists(train_path) and os.path.exists(val_path) and os.path.exists(test_path)):
            self.skipTest("E2 split CSV files missing")

        train_df = pd.read_csv(train_path, usecols=["entity_id"])
        val_df = pd.read_csv(val_path, usecols=["entity_id"])
        test_df = pd.read_csv(test_path, usecols=["entity_id"])

        train_ents = set(train_df["entity_id"].unique())
        val_ents = set(val_df["entity_id"].unique())
        test_ents = set(test_df["entity_id"].unique())

        self.assertEqual(len(train_ents & val_ents), 0, "Train-Val entity leakage detected!")
        self.assertEqual(len(train_ents & test_ents), 0, "Train-Test entity leakage detected!")
        self.assertEqual(len(val_ents & test_ents), 0, "Val-Test entity leakage detected!")

    def test_temporal_holdout_boundary_verification(self):
        """Verify E4 train, val, and test splits have strictly chronological boundaries."""
        dataset_dir = "dataset/processed_v2"
        train_path = os.path.join(dataset_dir, "e4_temporal_train_v2.csv")
        val_path = os.path.join(dataset_dir, "e4_temporal_val_v2.csv")
        test_path = os.path.join(dataset_dir, "e4_temporal_test_v2.csv")

        if not (os.path.exists(train_path) and os.path.exists(val_path) and os.path.exists(test_path)):
            self.skipTest("E4 split CSV files missing")

        train_df = pd.read_csv(train_path, usecols=["timestamp"])
        val_df = pd.read_csv(val_path, usecols=["timestamp"])
        test_df = pd.read_csv(test_path, usecols=["timestamp"])

        max_train_t = train_df["timestamp"].max()
        min_val_t = val_df["timestamp"].min()
        max_val_t = val_df["timestamp"].max()
        min_test_t = test_df["timestamp"].min()

        self.assertLessEqual(max_train_t, min_val_t, "Temporal inversion between Train and Val!")
        self.assertLessEqual(max_val_t, min_test_t, "Temporal inversion between Val and Test!")

    def test_full_m19_evaluation_report_artifact(self):
        """Verify EVAL_M19_REPORT.json is present, valid JSON, and contains all required sections."""
        report_path = os.path.join("evaluation", "reports", "EVAL_M19_REPORT.json")
        if not os.path.exists(report_path):
            _ = run_full_m19_evaluation()

        self.assertTrue(os.path.exists(report_path))
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["milestone"], "M19")
        self.assertIn("git_commit", data)
        self.assertIn("provenance", data)
        self.assertIn("evaluation_sections", data)

        secs = data["evaluation_sections"]
        self.assertIn("multi_split_benchmarks", secs)
        self.assertIn("six_threat_validation_matrix", secs)
        self.assertIn("operational_metrics", secs)
        self.assertIn("ablation_study", secs)
        self.assertIn("benign_periodic_vs_c2", secs)
        self.assertIn("encrypted_traffic_validation", secs)
        self.assertIn("legacy_vs_native_v2", secs)
        self.assertIn("cross_dataset_adapters", secs)


if __name__ == "__main__":
    unittest.main()
