"""Milestone 18 Comprehensive Test Suite: Incident Lifecycle, Correlation & Evidence-Backed Attack Chain.

Verifies:
1. Incident creation, incremental update, and state machine transitions (NEW -> UPDATED/OPEN -> ESCALATED -> RESOLVED).
2. Strict entity isolation (unrelated entities never merge).
3. Threat compatibility matrix (incompatible attack categories remain separate).
4. Signal and evidence deduplication without duplicate counting.
5. Inactivity timeout resolution on event time.
6. Reopen policy (reopening within window vs new incident after window).
7. Out-of-order event insertion with strict timeline sorting.
8. Evidence-backed attack chains (missing stages are never hallucinated).
9. Bounded memory limits and LRU eviction.
10. Deterministic incident dossier JSON export and SHA-256 fingerprinting.
11. Invariant property checks (first_seen <= last_seen, non-decreasing stage timestamps).
12. Real PCAP end-to-end integration through FeatureEngine and MultiSignalFusionEngine.
"""

from datetime import datetime, timezone
import os
import json
import unittest

from schemas import (
    DetectionSignal,
    ThreatClass,
    Severity,
    DetectorType,
    FusionResult,
    FusionEvidenceItem,
    Incident,
    IncidentStatus,
    AttackStageType,
    EvidenceItem,
)
from incidents.lifecycle_engine import (
    IncidentLifecycleEngine,
    LifecycleConfig,
)
from features.feature_engine import FeatureEngine
from models.inference.ml_inference import V2MLInferenceEngine
from fusion.engine import MultiSignalFusionEngine
from ingest.pcap_reader import iter_pcap


class TestM18IncidentLifecycleSynthetic(unittest.TestCase):

    def setUp(self):
        self.config = LifecycleConfig(
            inactivity_timeout_sec=600.0,
            reopen_window_sec=300.0,
            escalation_risk_delta=0.15,
            max_active_incidents=5,
        )
        self.engine = IncidentLifecycleEngine(config=self.config)

    def test_first_fusion_result_creates_new_incident(self):
        """First qualifying FusionResult creates an incident in NEW state."""
        fusion_res = FusionResult(
            fusion_id="fus-recon-01",
            entity_id="10.0.0.50",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.55,
            confidence=0.85,
            severity=Severity.MEDIUM,
            signal_ids=["sig-r1"],
            event_time=1000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
            evidence=[
                FusionEvidenceItem(
                    component_name="detector_signal",
                    raw_value=0.75,
                    weight=0.30,
                    weighted_contribution=0.225,
                    description="Recon horizontal port sweep",
                )
            ],
        )

        inc = self.engine.process_fusion_result(fusion_res, current_event_time=1000.0)

        self.assertIsInstance(inc, Incident)
        self.assertEqual(inc.entity_id, "10.0.0.50")
        self.assertEqual(inc.primary_threat_class, ThreatClass.RECON_PORT_SCAN)
        self.assertEqual(inc.status, IncidentStatus.NEW)
        self.assertAlmostEqual(inc.current_fused_risk, 0.55)
        self.assertAlmostEqual(inc.max_fused_risk, 0.55)
        self.assertEqual(len(inc.attack_chain), 1)
        self.assertEqual(inc.attack_chain[0].stage_type, AttackStageType.RECONNAISSANCE)
        self.assertEqual(len(inc.evidence), 1)

    def test_related_signal_updates_existing_incident(self):
        """Additional related evidence on the same entity updates the existing active incident."""
        fus1 = FusionResult(
            fusion_id="fus-recon-01",
            entity_id="10.0.0.50",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.50,
            confidence=0.80,
            severity=Severity.MEDIUM,
            signal_ids=["sig-r1"],
            event_time=1000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        fus2 = FusionResult(
            fusion_id="fus-recon-02",
            entity_id="10.0.0.50",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.58,  # Minor increase (< 0.15 delta)
            confidence=0.85,
            severity=Severity.MEDIUM,
            signal_ids=["sig-r2"],
            event_time=1050.0,
            timestamp_iso="2026-08-31T12:00:50Z",
        )

        inc1 = self.engine.process_fusion_result(fus1, current_event_time=1000.0)
        inc2 = self.engine.process_fusion_result(fus2, current_event_time=1050.0)

        # Same incident ID updated
        self.assertEqual(inc1.incident_id, inc2.incident_id)
        self.assertEqual(inc2.status, IncidentStatus.UPDATED)
        self.assertAlmostEqual(inc2.current_fused_risk, 0.58)
        self.assertAlmostEqual(inc2.max_fused_risk, 0.58)
        self.assertIn("fus-recon-01", inc2.fusion_ids)
        self.assertIn("fus-recon-02", inc2.fusion_ids)
        self.assertIn("sig-r1", inc2.signal_ids)
        self.assertIn("sig-r2", inc2.signal_ids)
        self.assertEqual(inc2.first_seen_event_time, 1000.0)
        self.assertEqual(inc2.last_seen_event_time, 1050.0)

    def test_material_risk_jump_triggers_escalation(self):
        """A material jump in fused risk (>= 0.15) escalates incident state to ESCALATED."""
        fus1 = FusionResult(
            fusion_id="fus-c2-01",
            entity_id="10.0.0.60",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            fused_risk=0.45,
            confidence=0.70,
            severity=Severity.MEDIUM,
            signal_ids=["sig-c2-1"],
            event_time=2000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        fus2 = FusionResult(
            fusion_id="fus-c2-02",
            entity_id="10.0.0.60",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            fused_risk=0.78,  # +0.33 jump
            confidence=0.92,
            severity=Severity.HIGH,
            signal_ids=["sig-c2-2"],
            event_time=2100.0,
            timestamp_iso="2026-08-31T12:01:40Z",
        )

        self.engine.process_fusion_result(fus1, current_event_time=2000.0)
        inc = self.engine.process_fusion_result(fus2, current_event_time=2100.0)

        self.assertEqual(inc.status, IncidentStatus.ESCALATED)
        self.assertEqual(inc.severity, Severity.HIGH)
        # Verify escalation event in timeline
        escalation_evts = [t for t in inc.timeline if t.event_type == "RISK_ESCALATED"]
        self.assertGreaterEqual(len(escalation_evts), 1)

    def test_strict_entity_isolation(self):
        """Signals from entity A and entity B must never merge into the same incident."""
        fus_a = FusionResult(
            fusion_id="fus-a",
            entity_id="192.168.1.10",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.60,
            confidence=0.80,
            event_time=3000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        fus_b = FusionResult(
            fusion_id="fus-b",
            entity_id="192.168.1.20",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.60,
            confidence=0.80,
            event_time=3000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )

        inc_a = self.engine.process_fusion_result(fus_a, current_event_time=3000.0)
        inc_b = self.engine.process_fusion_result(fus_b, current_event_time=3000.0)

        self.assertNotEqual(inc_a.incident_id, inc_b.incident_id)
        self.assertEqual(inc_a.entity_id, "192.168.1.10")
        self.assertEqual(inc_b.entity_id, "192.168.1.20")

    def test_inactivity_timeout_resolution(self):
        """Inactivity exceeding inactivity_timeout_sec resolves active incident to RESOLVED."""
        fus = FusionResult(
            fusion_id="fus-01",
            entity_id="10.0.0.80",
            threat_class=ThreatClass.DGA_DNS_TUNNELLING,
            fused_risk=0.70,
            confidence=0.85,
            event_time=4000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )

        inc = self.engine.process_fusion_result(fus, current_event_time=4000.0)
        self.assertEqual(inc.status, IncidentStatus.NEW)

        # Audit at t=4700 (dt=700s > 600s timeout)
        resolved_list = self.engine.check_inactivity_resolutions(current_event_time=4700.0)

        self.assertEqual(len(resolved_list), 1)
        self.assertEqual(resolved_list[0].incident_id, inc.incident_id)
        self.assertEqual(resolved_list[0].status, IncidentStatus.RESOLVED)
        self.assertNotIn(inc.incident_id, self.engine._active_incidents)
        self.assertIn(inc.incident_id, self.engine._resolved_incidents)

    def test_reopen_policy_within_window(self):
        """Activity arriving within reopen_window_sec of resolution reopens the original incident."""
        fus1 = FusionResult(
            fusion_id="fus-01",
            entity_id="10.0.0.90",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            fused_risk=0.70,
            confidence=0.85,
            event_time=5000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        inc1 = self.engine.process_fusion_result(fus1, current_event_time=5000.0)

        # Auto-resolve at t=5650 (dt=650s > 600s)
        self.engine.check_inactivity_resolutions(current_event_time=5650.0)
        self.assertEqual(inc1.status, IncidentStatus.RESOLVED)

        # New activity arrives at t=5800 (dt_resolved = 800s - 5000s = 800s > timeout, but dt from resolve = 150s <= 300s window)
        fus2 = FusionResult(
            fusion_id="fus-02",
            entity_id="10.0.0.90",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            fused_risk=0.75,
            confidence=0.90,
            event_time=5800.0,
            timestamp_iso="2026-08-31T12:13:20Z",
        )
        inc2 = self.engine.process_fusion_result(fus2, current_event_time=5800.0)

        self.assertEqual(inc1.incident_id, inc2.incident_id)
        self.assertIn(inc2.status, [IncidentStatus.UPDATED, IncidentStatus.ESCALATED, IncidentStatus.OPEN])
        self.assertIn(inc2.incident_id, self.engine._active_incidents)

    def test_out_of_order_events_sorted_strictly(self):
        """Out-of-order events are inserted into strict chronological timeline order."""
        fus_late = FusionResult(
            fusion_id="fus-t20",
            entity_id="10.0.0.95",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.50,
            confidence=0.80,
            event_time=6020.0,
            timestamp_iso="2026-08-31T12:00:20Z",
        )
        fus_early = FusionResult(
            fusion_id="fus-t10",
            entity_id="10.0.0.95",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.45,
            confidence=0.80,
            event_time=6010.0,  # Arrived second, but earlier in event time
            timestamp_iso="2026-08-31T12:00:10Z",
        )

        self.engine.process_fusion_result(fus_late, current_event_time=6020.0)
        inc = self.engine.process_fusion_result(fus_early, current_event_time=6020.0)

        # Timeline must have t=6010 first, then t=6020
        event_times = [t.event_time for t in inc.timeline]
        self.assertEqual(event_times, sorted(event_times))
        self.assertEqual(inc.first_seen_event_time, 6010.0)
        self.assertEqual(inc.last_seen_event_time, 6020.0)

    def test_evidence_backed_attack_chain_never_invents_stages(self):
        """Attack chain stages must only reflect actual observed threats."""
        # 1. Recon stage
        fus_recon = FusionResult(
            fusion_id="fus-recon",
            entity_id="10.0.0.100",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            fused_risk=0.60,
            confidence=0.85,
            event_time=7000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        # 2. C2 stage
        fus_c2 = FusionResult(
            fusion_id="fus-c2",
            entity_id="10.0.0.100",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            fused_risk=0.80,
            confidence=0.90,
            event_time=7100.0,
            timestamp_iso="2026-08-31T12:01:40Z",
        )

        self.engine.process_fusion_result(fus_recon, current_event_time=7000.0)
        inc = self.engine.process_fusion_result(fus_c2, current_event_time=7100.0)

        # Exactly 2 stages: RECONNAISSANCE and C2_ESTABLISHMENT
        self.assertEqual(len(inc.attack_chain), 2)
        stage_types = [s.stage_type for s in inc.attack_chain]
        self.assertEqual(stage_types, [AttackStageType.RECONNAISSANCE, AttackStageType.C2_ESTABLISHMENT])
        # Unobserved stages like DATA_EXFILTRATION must NOT be present
        self.assertNotIn(AttackStageType.DATA_EXFILTRATION, stage_types)

    def test_bounded_memory_lru_eviction(self):
        """Active incident cache stays strictly bounded under high entity volume."""
        for i in range(10):
            fus = FusionResult(
                fusion_id=f"fus-ent-{i}",
                entity_id=f"10.0.1.{i}",
                threat_class=ThreatClass.VOLUMETRIC_DDOS,
                fused_risk=0.80,
                confidence=0.90,
                event_time=8000.0 + i * 10,
                timestamp_iso="2026-08-31T12:00:00Z",
            )
            self.engine.process_fusion_result(fus)

        # Max active incidents configured is 5
        self.assertLessEqual(len(self.engine._active_incidents), 5)

    def test_deterministic_dossier_serialization_and_hashing(self):
        """Incident dossier JSON export produces idempotent output and SHA-256 hash."""
        fus = FusionResult(
            fusion_id="fus-dossier-01",
            entity_id="10.0.0.222",
            threat_class=ThreatClass.DATA_EXFILTRATION,
            fused_risk=0.92,
            confidence=0.95,
            severity=Severity.CRITICAL,
            signal_ids=["sig-exfil-1"],
            event_time=9000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
            evidence=[
                FusionEvidenceItem(
                    component_name="exfil_detector",
                    raw_value=5000000.0,
                    weight=0.30,
                    weighted_contribution=0.276,
                    description="Upload download byte ratio 120.5",
                )
            ],
        )

        inc = self.engine.process_fusion_result(fus, current_event_time=9000.0)

        dossier1 = inc.to_dossier_json()
        dossier2 = inc.to_dossier_json()
        hash1 = inc.compute_dossier_hash()
        hash2 = inc.compute_dossier_hash()

        self.assertEqual(dossier1, dossier2)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # Valid SHA-256 hex string

    def test_incompatible_threat_does_not_merge(self):
        """Incompatible threat classes (e.g. Volumetric DDoS and Encrypted Malware) create separate incidents."""
        fus_ddos = FusionResult(
            fusion_id="fus-ddos-1",
            entity_id="10.0.0.120",
            threat_class=ThreatClass.VOLUMETRIC_DDOS,
            fused_risk=0.85,
            confidence=0.90,
            event_time=9100.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        fus_malware = FusionResult(
            fusion_id="fus-mal-1",
            entity_id="10.0.0.120",
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
            fused_risk=0.75,
            confidence=0.85,
            event_time=9150.0,
            timestamp_iso="2026-08-31T12:00:50Z",
        )

        inc_ddos = self.engine.process_fusion_result(fus_ddos, current_event_time=9100.0)
        inc_malware = self.engine.process_fusion_result(fus_malware, current_event_time=9150.0)

        # Incompatible threats must not merge into the same incident
        self.assertNotEqual(inc_ddos.incident_id, inc_malware.incident_id)
        self.assertEqual(inc_ddos.primary_threat_class, ThreatClass.VOLUMETRIC_DDOS)
        self.assertEqual(inc_malware.primary_threat_class, ThreatClass.ENCRYPTED_MALWARE)

    def test_duplicate_signal_does_not_duplicate_incident_membership(self):
        """Re-ingesting the exact same signal ID does not duplicate entry in signal_ids."""
        sig = DetectionSignal(
            signal_id="sig-dup-01",
            detector_id="BotnetDetector",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.80,
            source_entity="10.0.0.130",
            event_time=9200.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        fus = FusionResult(
            fusion_id="fus-dup-01",
            entity_id="10.0.0.130",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            fused_risk=0.70,
            confidence=0.80,
            signal_ids=["sig-dup-01"],
            event_time=9200.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )

        inc1 = self.engine.process_fusion_result(fus, raw_signals=[sig], current_event_time=9200.0)
        inc2 = self.engine.process_fusion_result(fus, raw_signals=[sig], current_event_time=9210.0)

        self.assertEqual(inc1.incident_id, inc2.incident_id)
        self.assertEqual(inc2.signal_ids.count("sig-dup-01"), 1)

    def test_evidence_deduplication_increments_occurrence_count(self):
        """Repeated evidence items increment occurrence_count rather than appending duplicate rows."""
        ev_item = FusionEvidenceItem(
            component_name="dns_entropy",
            raw_value=4.52,
            weight=0.25,
            weighted_contribution=0.18,
            description="High entropy DNS query",
        )
        fus1 = FusionResult(
            fusion_id="fus-ev-1",
            entity_id="10.0.0.140",
            threat_class=ThreatClass.DGA_DNS_TUNNELLING,
            fused_risk=0.65,
            confidence=0.80,
            evidence=[ev_item],
            event_time=9300.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        fus2 = FusionResult(
            fusion_id="fus-ev-2",
            entity_id="10.0.0.140",
            threat_class=ThreatClass.DGA_DNS_TUNNELLING,
            fused_risk=0.68,
            confidence=0.82,
            evidence=[ev_item],
            event_time=9350.0,
            timestamp_iso="2026-08-31T12:00:50Z",
        )

        self.engine.process_fusion_result(fus1, current_event_time=9300.0)
        inc = self.engine.process_fusion_result(fus2, current_event_time=9350.0)

        self.assertEqual(len(inc.evidence), 1)
        self.assertEqual(inc.evidence[0].occurrence_count, 2)
        self.assertEqual(inc.evidence[0].first_seen_event_time, 9300.0)
        self.assertEqual(inc.evidence[0].last_seen_event_time, 9350.0)

    def test_invariant_first_seen_lte_last_seen(self):
        """Invariant: first_seen_event_time <= last_seen_event_time always holds."""
        fus1 = FusionResult(
            fusion_id="fus-inv-1",
            entity_id="10.0.0.250",
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
            fused_risk=0.60,
            confidence=0.80,
            event_time=10000.0,
            timestamp_iso="2026-08-31T12:00:00Z",
        )
        fus2 = FusionResult(
            fusion_id="fus-inv-2",
            entity_id="10.0.0.250",
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
            fused_risk=0.70,
            confidence=0.85,
            event_time=10200.0,
            timestamp_iso="2026-08-31T12:03:20Z",
        )

        self.engine.process_fusion_result(fus1, current_event_time=10000.0)
        inc = self.engine.process_fusion_result(fus2, current_event_time=10200.0)

        self.assertLessEqual(inc.first_seen_event_time, inc.last_seen_event_time)
        for stage in inc.attack_chain:
            self.assertLessEqual(stage.first_seen_event_time, stage.last_seen_event_time)


class TestM18RealPCAPIncidentIntegration(unittest.TestCase):

    def setUp(self):
        self.feature_engine = FeatureEngine()
        self.ml_engine = V2MLInferenceEngine(artifact_dir="models/artifacts")
        self.fusion = MultiSignalFusionEngine()
        self.lifecycle = IncidentLifecycleEngine()

    def test_real_pcap_recon_to_incident_dossier(self):
        """Real PCAP -> FeatureEngine -> ML/Detector -> MultiSignalFusionEngine -> IncidentLifecycleEngine."""
        pcap_path = os.path.join("dataset", "pcaps", "recon", "horizontal_vertical_port_scan.pcap")
        if not os.path.exists(pcap_path):
            self.skipTest(f"PCAP not found: {pcap_path}")

        packets = list(iter_pcap(pcap_path))
        self.assertGreater(len(packets), 0)

        for pkt in packets[:300]:
            self.feature_engine.update_packet(pkt)

        src_ip = packets[0].src_ip
        feat_set = self.feature_engine.extract(entity_id=src_ip)
        entity_prof = self.feature_engine.entity_memory.get_profile(src_ip)

        # 1. ML & Detector Signal
        ml_res = self.ml_engine.predict(feat_set.values(), source_entity=src_ip)
        det_sig = DetectionSignal(
            signal_id="pcap-recon-sig-01",
            detector_id="ReconDetector",
            threat_class=ThreatClass.RECON_PORT_SCAN,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.85,
            score=0.85,
            severity=Severity.HIGH,
            source_entity=src_ip,
            event_time=packets[-1].timestamp,
            timestamp_iso="2026-08-31T12:00:00Z",
        )

        # 2. Multi-Signal Fusion
        fusion_res = self.fusion.fuse(
            signals=[det_sig],
            ml_result=ml_res,
            entity_profile=entity_prof,
            event_time=packets[-1].timestamp,
        )

        # 3. Incident Lifecycle Ingestion
        inc = self.lifecycle.process_fusion_result(
            fusion_result=fusion_res,
            raw_signals=[det_sig],
            current_event_time=packets[-1].timestamp,
        )

        self.assertIsInstance(inc, Incident)
        self.assertEqual(inc.entity_id, src_ip)
        self.assertEqual(inc.primary_threat_class, ThreatClass.RECON_PORT_SCAN)
        self.assertEqual(inc.status, IncidentStatus.NEW)
        self.assertGreater(inc.current_fused_risk, 0.0)
        self.assertEqual(len(inc.attack_chain), 1)
        self.assertEqual(inc.attack_chain[0].stage_type, AttackStageType.RECONNAISSANCE)

        # 4. Dossier Export
        dossier = inc.to_dossier_dict()
        self.assertEqual(dossier["entity_id"], src_ip)
        self.assertIn("timeline", dossier)
        self.assertIn("attack_chain", dossier)
        self.assertIn("evidence", dossier)


if __name__ == "__main__":
    unittest.main()
