"""Milestone 17.5 Integrity & Research Methodology Test Suite.

Verifies:
1. P0-1: True unseen-entity holdout (E2) with 0% entity overlap between train, val, and test.
2. P0-2: True chronological temporal holdout (E4) with strict timestamp monotonicity.
3. P0-3: Honest scenario holdout (E3) status reporting (NOT_AVAILABLE when single scenario).
4. P0-4: Canonical FeatureEngine v2 row generation matching inference semantics.
5. P1-1: Missingness preservation (NaNs) until train-only model preprocessing.
6. P1-2: Real entity-history TLS fingerprint novelty (first-seen vs previously observed).
7. P1-3: Global bounded entity state in MultiSignalFusionEngine with LRU eviction.
8. P1-4: Event-time consistency without wall-clock dependency.
9. P1-5: Threat-specific persistence tracking (entity_id + threat_class).
10. P1-6: Unknown raw label rejection (never silently mapped to BENIGN).
11. P1-8: Single canonical risk path through FusionResult in IncidentBuilder.
"""

from datetime import datetime, timezone
import os
import json
import unittest
import numpy as np
import pandas as pd

from schemas import (
    DetectionSignal,
    ThreatClass,
    Severity,
    DetectorType,
    FusionResult,
    FusionEvidenceItem,
    SignalFamily,
)
from entity.memory import EntityMemory, EntityProfile
from fusion.engine import (
    MultiSignalFusionEngine,
    FusionConfig,
    EntityCorrelationState,
    ActiveCorrelationGroup,
)
from incidents.incident_builder import IncidentBuilder
from features.feature_engine import FeatureEngine
from features.model_features_v2 import (
    MODEL_V2_FEATURE_NAMES,
    V2FeaturePreprocessor,
)
from dataset.generate_v2_dataset import (
    engineer_v2_features,
    map_raw_label,
    generate_v2_row_from_feature_engine,
)


class TestM17_5Integrity(unittest.TestCase):

    def setUp(self):
        self.data_dir = "dataset/processed_v2"

    def test_p0_1_true_entity_holdout_zero_overlap(self):
        """P0-1: E2 split partitions unique entities into mutually disjoint sets."""
        e2_tr = pd.read_csv(os.path.join(self.data_dir, "e2_entity_train_v2.csv"))
        e2_va = pd.read_csv(os.path.join(self.data_dir, "e2_entity_val_v2.csv"))
        e2_te = pd.read_csv(os.path.join(self.data_dir, "e2_entity_test_v2.csv"))

        train_ent = set(e2_tr["entity_id"].dropna().unique())
        val_ent = set(e2_va["entity_id"].dropna().unique())
        test_ent = set(e2_te["entity_id"].dropna().unique())

        self.assertEqual(len(train_ent.intersection(val_ent)), 0)
        self.assertEqual(len(train_ent.intersection(test_ent)), 0)
        self.assertEqual(len(val_ent.intersection(test_ent)), 0)

    def test_p0_2_true_temporal_holdout_monotonicity(self):
        """P0-2: E4 split enforces strict past -> present -> future ordering."""
        manifest_path = os.path.join(self.data_dir, "dataset_manifest_v2.json")
        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        tb = manifest["splits"]["E4_true_temporal_holdout"]["timestamp_boundaries"]
        self.assertTrue(tb["is_strictly_chronological"])
        self.assertLessEqual(tb["t_train_max"], tb["t_val_min"])
        self.assertLessEqual(tb["t_val_max"], tb["t_test_min"])

    def test_p0_3_scenario_holdout_honest_status(self):
        """P0-3: E3 is marked NOT_AVAILABLE when only 1 scenario ID exists."""
        eval_report_path = "models/evaluation/v2_eval_report.json"
        with open(eval_report_path, "r") as f:
            report = json.load(f)

        e3 = report.get("E3_scenario_holdout", {})
        self.assertEqual(e3.get("status"), "NOT_AVAILABLE")
        self.assertIsNone(e3.get("accuracy"))
        self.assertIsNone(e3.get("macro_f1"))

    def test_p0_4_canonical_feature_engine_row_generation(self):
        """P0-4: Direct row generation from FeatureEngine produces valid v2 feature dictionary."""
        from schemas.flow_event import FlowEvent
        engine = FeatureEngine()
        event = FlowEvent(
            timestamp=1001.0,
            event_time=1001.0,
            flow_id="10.0.0.99:1234-10.0.0.1:80-6",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1",
            src_port=1234,
            dst_port=80,
            protocol=6,
            packet_count=10,
            byte_count=1000,
            duration=1.0,
            packet_rate=10.0,
            byte_rate=1000.0,
            syn_count=1,
            ack_count=9,
            fin_count=0,
            rst_count=0,
            psh_count=0,
            urg_count=0,
            syn_ratio=0.1,
            ack_ratio=0.9,
            fin_ratio=0.0,
            rst_ratio=0.0,
            packet_length_min=100.0,
            packet_length_max=140.0,
            packet_length_mean=120.0,
            packet_length_std=10.0,
            iat_min_ms=10.0,
            iat_max_ms=20.0,
            iat_mean_ms=15.0,
            iat_std_ms=5.0,
            packet_lengths=(100, 120, 140),
            inter_arrival_times_ms=(10.0, 20.0),
        )
        row = generate_v2_row_from_feature_engine(engine, entity_id="10.0.0.99", events=[event], as_of_event_time=1001.0)

        self.assertEqual(row["entity_id"], "10.0.0.99")
        self.assertEqual(row["feature_schema_version"], "feature-schema-v2.1.0")
        for feat in MODEL_V2_FEATURE_NAMES:
            self.assertIn(feat, row)

    def test_p1_1_missingness_preservation_in_raw_dataset(self):
        """P1-1: Unobserved features remain NaN until train-fitted model preprocessing."""
        raw_df = pd.DataFrame({
            "duration": [1.0],
            "total_packets": [10],
            "label": ["BENIGN"],
            # ja3 missing
        })
        v2_df = engineer_v2_features(raw_df)
        # tls_fingerprint_novelty should be NaN, not blindly filled 0
        self.assertTrue(pd.isna(v2_df["tls_fingerprint_novelty"].iloc[0]))

    def test_p1_2_tls_novelty_differentiates_first_seen_from_known(self):
        """P1-2: First seen fingerprint = 1.0 (novel), repeated observation = 0.0 (known)."""
        raw_df = pd.DataFrame({
            "entity_id": ["host-A", "host-A"],
            "ja3": ["abc123hash", "abc123hash"],
            "label": ["BENIGN", "BENIGN"],
        })
        v2_df = engineer_v2_features(raw_df)
        self.assertEqual(v2_df["tls_fingerprint_novelty"].iloc[0], 1.0)
        self.assertEqual(v2_df["tls_fingerprint_novelty"].iloc[1], 0.0)

    def test_p1_3_fusion_bounded_memory_lru_eviction(self):
        """P1-3: MultiSignalFusionEngine evicts oldest entity state when exceeding max_entities."""
        config = FusionConfig(max_entities=3)
        fusion = MultiSignalFusionEngine(config=config)

        for i in range(5):
            sig = DetectionSignal(
                signal_id=f"sig-{i}",
                threat_class=ThreatClass.VOLUMETRIC_DDOS,
                source_entity=f"10.0.0.{i}",
                confidence=0.80,
                timestamp_iso="2026-08-31T12:00:00Z",
            )
            fusion.fuse(signals=[sig])

        # Cache size must never exceed max_entities (3)
        self.assertLessEqual(len(fusion._entity_states), 3)
        # Oldest entities (10.0.0.0, 10.0.0.1) should have been evicted
        self.assertNotIn("10.0.0.0", fusion._entity_states)
        self.assertNotIn("10.0.0.1", fusion._entity_states)
        self.assertIn("10.0.0.4", fusion._entity_states)

    def test_p1_4_event_time_expiration_consistency(self):
        """P1-4: ActiveCorrelationGroup expires based on event-time elapsed seconds."""
        group = ActiveCorrelationGroup(primary_entity="10.0.0.50", window_duration_sec=300)
        sig = DetectionSignal(
            signal_id="sig-t1",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            source_entity="10.0.0.50",
            confidence=0.75,
            event_time=1000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        group.add_signal(sig)

        # Within window (1000 -> 1200, dt=200s < 300s)
        self.assertFalse(group.is_expired(current_time=1200.0))
        # Expired (1000 -> 1400, dt=400s > 300s)
        self.assertTrue(group.is_expired(current_time=1400.0))

    def test_p1_5_threat_specific_persistence_isolation(self):
        """P1-5: Recon signals do not inflate persistence for an unrelated C2 signal."""
        state = EntityCorrelationState(entity_id="10.0.0.60", config=FusionConfig())
        
        # Ingest 2 Recon signals separated by 200s
        sig_recon1 = DetectionSignal(
            signal_id="sig-r1",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            source_entity="10.0.0.60",
            confidence=0.70,
            event_time=1000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        sig_recon2 = DetectionSignal(
            signal_id="sig-r2",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            source_entity="10.0.0.60",
            confidence=0.70,
            event_time=1200.0,
            timestamp_iso="2026-08-31T12:03:20Z",
        )
        state.add_signal(sig_recon1)
        state.add_signal(sig_recon2)

        # Ingest 1 fresh C2 signal at t=1200.0
        sig_c2 = DetectionSignal(
            signal_id="sig-c2",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            source_entity="10.0.0.60",
            confidence=0.85,
            event_time=1200.0,
            timestamp_iso="2026-08-31T12:03:20Z",
        )
        state.add_signal(sig_c2)

        recon_persistence = state.get_persistence_duration(threat_class=ThreatClass.RECON_PORT_SCAN)
        c2_persistence = state.get_persistence_duration(threat_class=ThreatClass.BOTNET_C2_BEACONING)

        self.assertAlmostEqual(recon_persistence, 200.0)
        self.assertAlmostEqual(c2_persistence, 0.0)  # C2 only observed once, 0 persistence!

    def test_p1_6_unknown_label_rejection(self):
        """P1-6: Unknown raw labels must raise ValueError rather than mapping to BENIGN."""
        with self.assertRaises(ValueError):
            map_raw_label("TOTALLY_UNKNOWN_ATTACK_XYZ")

    def test_p1_8_canonical_incident_risk_path(self):
        """P1-8: IncidentBuilder accepts FusionResult as the single canonical risk score."""
        builder = IncidentBuilder()
        group = ActiveCorrelationGroup(primary_entity="10.0.0.70")
        sig = DetectionSignal(
            signal_id="sig-inc-01",
            threat_class=ThreatClass.DATA_EXFILTRATION,
            source_entity="10.0.0.70",
            confidence=0.80,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        group.add_signal(sig)

        fusion_res = FusionResult(
            fusion_id="FUS-12345",
            entity_id="10.0.0.70",
            threat_class=ThreatClass.DATA_EXFILTRATION,
            fused_risk=0.825,
            confidence=0.90,
            severity=Severity.HIGH,
            timestamp_iso="2026-08-31T12:00:00Z",
        )

        inc = builder.build_incident_from_group(group=group, fusion_result=fusion_res)
        self.assertAlmostEqual(inc.risk_score, 0.825)
        self.assertEqual(inc.overall_severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
