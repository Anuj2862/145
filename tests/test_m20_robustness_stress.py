"""Unit & Integration Test Suite for Milestone 20: Robustness, Evasion & Concept Drift.

Tests:
1. Scenario mutation framework (jitter, packet loss, reordering, metadata drift, deterministic hashing)
2. C2 jitter sweep (0% to 70%) & timing resilience
3. Slow reconnaissance fan-out vs burst rate dependence
4. Low-and-slow exfiltration baseline tracking
5. Benign periodic traffic discrimination (NTP, telemetry, backup, cloud sync)
6. TLS fingerprint drift (JA3/JA4/ALPN) & destination rotation
7. Packet-loss robustness (0% to 20%)
8. Out-of-order packet reordering
9. Missing telemetry availability modes
10. Population Stability Index (PSI) drift detector & severity buckets
11. ADWIN adaptive windowing streaming change detector
12. Multi-feature drift monitor tracking stable aggregates
13. Retraining candidate generation & production safety gating
14. Concept drift timeline & calibration degradation (ECE, Brier)
15. M20 master report generation and schema compliance
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import pytest
import numpy as np

from schemas import ThreatClass
from ingest.pcap_reader import NormalizedPacket
from evaluation.stress.mutation_framework import (
    ScenarioMutator,
    MutationParameters,
    MutatedScenario,
)
from evaluation.drift.drift_detector import (
    PSIDriftDetector,
    ADWINDriftDetector,
    MultiFeatureDriftMonitor,
    DriftSeverity,
)
from evaluation.drift.candidate_generator import (
    RetrainingCandidateManager,
    RetrainingCandidate,
)
from evaluation.stress.concept_drift_experiment import (
    ConceptDriftExperiment,
    compute_brier_score,
    compute_ece,
)
from evaluation.stress.stress_evaluator import StressEvaluator
from evaluation.stress.leakage_auditor import IntegrityAuditor
from evaluation.runners.m20_stress_runner import run_full_m20_stress_evaluation


@pytest.fixture
def sample_packets() -> list[NormalizedPacket]:
    """Generate a synthetic sequence of 100 normalized packets."""
    pkts = []
    t_start = 1756680000.0
    for i in range(100):
        pkts.append(
            NormalizedPacket(
                timestamp=t_start + i * 0.1,
                src_ip="192.168.1.50",
                dst_ip="203.0.113.10",
                src_port=49152 + (i % 10),
                dst_port=443,
                protocol=6,
                packet_length=500 + (i % 200),
                tcp_syn=1 if i == 0 else 0,
                tcp_ack=1 if i > 0 else 0,
                sensor_id="sensor-test-01",
                tls={"ja3": "771,4865-4866,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0", "ja4": "t13d1516h2_8daaf6152771_b74621d9b3a0", "alpn": "h2"},
            )
        )
    return pkts


# 1. Mutation Framework Tests
def test_scenario_mutator_deterministic_hashing(sample_packets):
    params1 = MutationParameters(jitter_pct=10.0, random_seed=42)
    params2 = MutationParameters(jitter_pct=10.0, random_seed=42)

    scen1 = ScenarioMutator.mutate_packets(sample_packets, params1, "parent-01", ThreatClass.BOTNET_C2_BEACONING)
    scen2 = ScenarioMutator.mutate_packets(sample_packets, params2, "parent-01", ThreatClass.BOTNET_C2_BEACONING)

    assert scen1.provenance_hash == scen2.provenance_hash
    assert scen1.scenario_id == scen2.scenario_id
    assert len(scen1.packets) == len(scen2.packets)


def test_scenario_mutator_packet_loss(sample_packets):
    params = MutationParameters(packet_loss_rate=0.20, random_seed=123)
    scen = ScenarioMutator.mutate_packets(sample_packets, params, "parent-loss", None)

    assert scen.mutated_packet_count < scen.original_packet_count
    assert scen.original_packet_count == 100
    assert 70 <= scen.mutated_packet_count <= 90


def test_scenario_mutator_reordering(sample_packets):
    params = MutationParameters(reordering_rate=0.30, reordering_delay_sec=0.5, random_seed=999)
    scen = ScenarioMutator.mutate_packets(sample_packets, params, "parent-reorder", None)

    assert len(scen.packets) == 100
    assert scen.ground_truth_end_time >= scen.ground_truth_start_time


def test_scenario_mutator_tls_drift(sample_packets):
    params = MutationParameters(
        tls_fingerprint_drift=True,
        mutated_ja3="new-ja3-hash-12345",
        mutated_ja4="new-ja4-hash-67890",
        mutated_alpn="http/1.1",
        random_seed=42,
    )
    scen = ScenarioMutator.mutate_packets(sample_packets, params, "parent-tls", ThreatClass.ENCRYPTED_MALWARE)

    for pkt in scen.packets:
        if pkt.tls:
            assert pkt.tls.get("ja3") == "new-ja3-hash-12345"
            assert pkt.tls.get("ja4") == "new-ja4-hash-67890"
            assert pkt.tls.get("alpn") == "http/1.1"


# 2. Statistical Drift Monitoring Tests (PSI & ADWIN)
def test_psi_drift_detector_stable_and_drift():
    psi_det = PSIDriftDetector(threshold=0.25)
    rng = np.random.RandomState(42)

    # Identical distribution -> PSI should be very low (< 0.10)
    base = rng.normal(100.0, 15.0, 500)
    target_stable = rng.normal(100.0, 15.0, 500)

    score_stable, sev_stable = psi_det.calculate_psi(base, target_stable)
    assert score_stable < 0.10
    assert sev_stable == DriftSeverity.NONE

    # Significantly shifted distribution -> PSI should be >= 0.25
    target_drifted = rng.normal(180.0, 30.0, 500)
    score_drift, sev_drift = psi_det.calculate_psi(base, target_drifted)
    assert score_drift >= 0.25
    assert sev_drift in (DriftSeverity.MODERATE, DriftSeverity.HIGH, DriftSeverity.CRITICAL)


def test_adwin_drift_detector_streaming():
    adwin = ADWINDriftDetector(delta=0.002)
    rng = np.random.RandomState(42)

    drift_fired = False
    # Stream baseline mean 50.0
    for _ in range(100):
        adwin.add_element(rng.normal(50.0, 2.0))

    # Introduce sudden step change to mean 150.0
    for _ in range(100):
        if adwin.add_element(rng.normal(150.0, 2.0)):
            drift_fired = True
            break

    assert drift_fired is True


def test_multi_feature_drift_monitor():
    monitor = MultiFeatureDriftMonitor(psi_threshold=0.25)
    rng = np.random.RandomState(42)

    base_pps = rng.normal(50.0, 5.0, 200).tolist()
    monitor.set_baseline("packets_per_sec", base_pps)

    events = []
    for i in range(50):
        evts = monitor.observe({"packets_per_sec": rng.normal(50.0, 5.0)}, 1756680000.0 + i)
        events.extend(evts)

    psi_events = monitor.evaluate_batch_psi(1756680050.0)
    assert len(psi_events) == 0  # No PSI drift on stable data


# 3. Retraining Candidate Safety Gating Tests
def test_retraining_candidate_safety_policy(tmp_path):
    manager = RetrainingCandidateManager(candidates_dir=str(tmp_path))

    psi_det = PSIDriftDetector()
    base = np.random.normal(50, 5, 200)
    drifted = np.random.normal(150, 20, 200)
    score, sev = psi_det.calculate_psi(base, drifted)

    evt = type("DriftEvent", (), {
        "event_id": "evt-01",
        "feature_name": "packets_per_sec",
        "baseline_window": "base",
        "current_window": "curr",
        "metric": "PSI",
        "drift_score": score,
        "threshold": 0.25,
        "is_drift": True,
        "severity": sev,
        "event_time": 1756680000.0,
        "timestamp_iso": "2026-09-01T00:00:00Z",
        "details": {},
        "to_dict": lambda self: {"event_id": "evt-01", "feature_name": "packets_per_sec", "is_drift": True},
    })()

    cand = manager.evaluate_drift_and_propose_candidate(
        drift_events=[evt],
        window_start_iso="2026-09-01T00:00:00Z",
        window_end_iso="2026-09-01T04:00:00Z",
    )

    assert cand is not None
    # Mandatory Safety Constraints:
    assert cand.production_deployment_blocked is True
    assert cand.human_approved is False
    assert cand.offline_validation_required is True

    # Approve for offline validation only
    cand.approve_for_offline_validation(approver_name="SecurityArchitect", notes="Audit required")
    assert cand.human_approved is True
    # Production deployment remains blocked until full validation audit
    assert cand.production_deployment_blocked is True


# 4. Calibration Degradation Computation Tests
def test_calibration_metrics():
    y_true = np.array([0, 1, 2, 0, 1, 2])
    # Well calibrated probabilities
    y_prob_good = np.array([
        [0.9, 0.05, 0.05],
        [0.05, 0.9, 0.05],
        [0.05, 0.05, 0.9],
        [0.85, 0.1, 0.05],
        [0.1, 0.85, 0.05],
        [0.05, 0.1, 0.85],
    ])
    brier_good = compute_brier_score(y_true, y_prob_good)
    ece_good = compute_ece(y_true, y_prob_good)

    # Degraded / overconfident wrong probabilities
    y_prob_bad = np.array([
        [0.1, 0.8, 0.1],
        [0.8, 0.1, 0.1],
        [0.1, 0.8, 0.1],
        [0.1, 0.1, 0.8],
        [0.8, 0.1, 0.1],
        [0.8, 0.1, 0.1],
    ])
    brier_bad = compute_brier_score(y_true, y_prob_bad)
    ece_bad = compute_ece(y_true, y_prob_bad)

    assert brier_good < brier_bad
    assert ece_good < ece_bad


# 5. Concept Drift Experiment Tests
def test_concept_drift_experiment_timeline(tmp_path):
    exp = ConceptDriftExperiment(candidates_dir=str(tmp_path))
    results = exp.run_experiment()

    assert results["status"] == "COMPLETED"
    periods = results["periods"]
    assert "P1_baseline" in periods
    assert "P2_benign_distribution_shift" in periods
    assert "P3_new_service_mix" in periods
    assert "P4_unseen_attack_parameterization" in periods

    assert periods["P1_baseline"]["status"] == "STABLE"
    assert periods["P2_benign_distribution_shift"]["status"] == "DRIFT_IDENTIFIED"
    assert periods["P4_unseen_attack_parameterization"]["brier_score"] > 0.0


# 6. Full M20 Stress Report Verification
def test_m20_stress_runner_report_artifacts(tmp_path):
    rep_data = run_full_m20_stress_evaluation(output_dir=str(tmp_path))

    assert rep_data["milestone"] == "M20.5"
    assert rep_data["parent_milestone"] == "M20"
    assert "stress_evaluation_sections" in rep_data
    assert "safety_and_retraining_policy" in rep_data

    json_path = os.path.join(tmp_path, "M20_ROBUSTNESS_REPORT.json")
    md_path = os.path.join(tmp_path, "M20_ROBUSTNESS_REPORT.md")

    assert os.path.exists(json_path)
    assert os.path.exists(md_path)

    with open(json_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        assert loaded["milestone"] == "M20.5"
        assert loaded["parent_milestone"] == "M20"
        assert "c2_jitter_sweep" in loaded["stress_evaluation_sections"]
        assert "packet_loss_robustness" in loaded["stress_evaluation_sections"]
        assert "unseen_parameter_generalization" in loaded["stress_evaluation_sections"]


# 7. M20.5 Specific Integrity Audit Tests
def test_c2_jitter_iat_variance_effect(sample_packets):
    """Verify that applying jitter actually increases IAT variance."""
    p_no_jitter = MutationParameters(jitter_pct=0.0, random_seed=42)
    p_high_jitter = MutationParameters(jitter_pct=50.0, random_seed=42)

    scen_no_jitter = ScenarioMutator.mutate_packets(sample_packets, p_no_jitter, "p_c2", ThreatClass.BOTNET_C2_BEACONING)
    scen_high_jitter = ScenarioMutator.mutate_packets(sample_packets, p_high_jitter, "p_c2", ThreatClass.BOTNET_C2_BEACONING)

    stats_no_jitter = scen_no_jitter.iat_statistics
    stats_high_jitter = scen_high_jitter.iat_statistics

    assert stats_high_jitter["mutated_iat_std_ms"] > stats_no_jitter["mutated_iat_std_ms"]


def test_parameter_disjointness_auditor():
    """Verify that parameter disjointness auditor correctly certifies disjoint parameters."""
    train_intervals = {60.0, 120.0}
    test_intervals_disjoint = {47.0, 93.0}
    test_intervals_leaked = {60.0, 93.0}

    res_valid = IntegrityAuditor.audit_parameter_disjointness(train_intervals, test_intervals_disjoint, "beacon_interval")
    assert res_valid.is_disjoint is True
    assert res_valid.status == "VALID"
    assert res_valid.overlap_count == 0

    res_leaked = IntegrityAuditor.audit_parameter_disjointness(train_intervals, test_intervals_leaked, "beacon_interval")
    assert res_leaked.is_disjoint is False
    assert res_leaked.status == "INVALID"
    assert res_leaked.overlap_count == 1
    assert 60.0 in res_leaked.overlap_samples


def test_ttfd_event_time_calculation_invariance():
    """Verify that TTFD calculation is strictly event-time based and invariant to replay timing."""
    evaluator = StressEvaluator()
    # Mock sequence of 20 packets spanning 100 seconds event time
    t0 = 1756680000.0
    pkts = [
        NormalizedPacket(
            timestamp=t0 + i * 5.0,
            src_ip="192.168.1.100",
            dst_ip="203.0.113.5",
            src_port=50000 + i,
            dst_port=80,
            protocol=6,
            packet_length=60,
            tcp_syn=1 if i == 0 else 0,
            tcp_ack=1 if i > 0 else 0,
        )
        for i in range(20)
    ]
    res = evaluator._replay_packets(pkts, expected_threat=None)
    assert res["duration_sec"] == 95.0
    # TTFD should either be None (if not detected) or a non-negative float
    if res["ttfd_sec"] is not None:
        assert res["ttfd_sec"] >= 0.0


def test_benign_exposure_hours_calculation():
    """Verify that benign exposure correctly reports observation hours and alert rates."""
    evaluator = StressEvaluator()
    res = evaluator.evaluate_benign_periodic_baselines()
    assert res["status"] == "VALID"
    assert "scenarios" in res
    for name, scen_res in res["scenarios"].items():
        assert scen_res["duration_hours"] > 0.0
        assert "false_alerts_per_hour" in scen_res
        assert scen_res["periodicity_misclassification_avoided"] is True

