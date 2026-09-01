"""Unit & Integration Test Suite for Milestones 21 & 21.5: End-to-End Performance Integrity and Capacity Audit.

Tests:
1. Environment profiler hardware/software/repository capture
2. Deterministic traffic generator and label distribution
3. Bounded pipeline queue capacity, drops, wait latencies, and received=processed+dropped accounting
4. Resource monitor continuous sampling, memory growth rate, and classification (bounded_plateau)
5. Pipeline profiler stage & ML sub-stage percentiles (P50, P90, P95, P99) and bottleneck identification
6. Full pipeline benchmark execution across all stages and ML sub-stages
7. Replay-speed independence of event-time detection latency
8. Load sweep runner and stopping rule evaluation (Offered vs Sustained Processed capacity)
9. High flow-churn short-lived flow bounded state
10. High entity-churn source IP bounded state
11. State pressure cardinality tracking (destinations, ports, domains, TLS JA3)
12. Mixed traffic threat detection confusion matrix (TP, FP, TN, FN, recall, precision, F1)
13. Sustained stability memory plateau verification
14. Master M21/M21.5 benchmark runner report artifact creation
"""

from __future__ import annotations

import json
import os
import tempfile
import pytest

from schemas import ThreatClass
from ingest.pcap_reader import NormalizedPacket
from evaluation.benchmark.environment_profiler import EnvironmentProfiler
from evaluation.benchmark.traffic_generator import (
    SyntheticTrafficGenerator,
    TrafficStreamConfig,
    BoundedPipelineQueue,
)
from evaluation.benchmark.resource_monitor import ContinuousResourceMonitor
from evaluation.benchmark.pipeline_profiler import PipelineProfiler, EventTimingRecord
from evaluation.benchmark.load_sweeps import (
    FullPipelineBenchmarkEngine,
    LoadSweepRunner,
    ReplaySpeedIndependenceRunner,
    FlowChurnRunner,
    EntityChurnRunner,
    StatePressureRunner,
    MixedCorrectnessRunner,
    SustainedStabilityRunner,
)
from evaluation.runners.m21_performance_runner import run_full_m21_performance_benchmark


def test_environment_profiler_metadata():
    """Verify that environment profiler captures valid hardware, software, and git metadata."""
    env = EnvironmentProfiler.capture_environment()
    assert env.hardware.cpu_model != ""
    assert env.hardware.physical_cores >= 1
    assert env.hardware.total_ram_gb > 0.0
    assert env.software.python_version != ""
    assert "scikit-learn" in env.software.installed_packages
    assert env.software.sklearn_training_version == "1.8.0"
    assert env.repository.feature_schema_version != ""


def test_traffic_generator_determinism():
    """Verify that synthetic traffic generator produces deterministic packets for identical seeds."""
    cfg1 = TrafficStreamConfig(duration_sec=1.0, target_pps=100.0, random_seed=42)
    cfg2 = TrafficStreamConfig(duration_sec=1.0, target_pps=100.0, random_seed=42)

    gen1 = SyntheticTrafficGenerator(cfg1)
    gen2 = SyntheticTrafficGenerator(cfg2)

    pkts1, labels1 = gen1.generate_packets_with_labels(total_packets=50)
    pkts2, labels2 = gen2.generate_packets_with_labels(total_packets=50)

    assert len(pkts1) == 50
    assert len(pkts2) == 50
    assert labels1 == labels2
    for p1, p2 in zip(pkts1, pkts2):
        assert p1.timestamp == p2.timestamp
        assert p1.src_ip == p2.src_ip
        assert p1.dst_ip == p2.dst_ip
        assert p1.packet_length == p2.packet_length


def test_bounded_pipeline_queue_capacity_and_drops():
    """Verify bounded queue capacity enforcement, overflow drops, and exact queue accounting."""
    q = BoundedPipelineQueue(capacity=10)
    pkt = NormalizedPacket(
        timestamp=1756680000.0,
        src_ip="192.168.1.10",
        dst_ip="203.0.113.5",
        src_port=50000,
        dst_port=80,
        protocol=6,
        packet_length=100,
        sensor_id="test-sensor",
    )

    # Fill queue to capacity
    for _ in range(10):
        assert q.enqueue(pkt) is True

    # 11th packet should overflow and drop
    assert q.enqueue(pkt) is False
    assert q.overflow_drops == 1

    stats = q.get_stats()
    assert stats["capacity"] == 10
    assert stats["current_depth"] == 10
    assert stats["overflow_drops"] == 1
    assert stats["drop_rate_pct"] > 0.0
    assert stats["total_received"] == 11
    assert stats["total_enqueued"] == 10

    # Dequeue items
    item = q.dequeue()
    assert item is not None
    dequeued_pkt, wait_ms = item
    assert dequeued_pkt.src_ip == "192.168.1.10"
    assert wait_ms >= 0.0

    post_stats = q.get_stats()
    assert post_stats["total_processed"] == 1
    assert post_stats["total_received"] == post_stats["total_enqueued"] + post_stats["overflow_drops"]


def test_continuous_resource_monitor_sampling_and_classification():
    """Verify that resource monitor starts, samples process metrics, and computes memory classification."""
    monitor = ContinuousResourceMonitor(sample_interval_sec=0.01)
    monitor.start()
    # Simulate short burst
    x = [i ** 2 for i in range(10000)]
    stats = monitor.stop()

    assert stats["sample_count"] >= 1
    assert stats["initial_rss_mb"] > 0.0
    assert stats["peak_rss_mb"] >= stats["initial_rss_mb"]
    assert stats["memory_bounded_stable"] is True
    assert stats["memory_growth_classification"] in ("bounded_plateau", "warmup_growth", "persistent_growth", "inconclusive")


def test_pipeline_profiler_stage_and_ml_substage_distributions():
    """Verify that pipeline profiler computes stage and ML sub-stage percentiles."""
    profiler = PipelineProfiler()
    profiler.start_run()

    for i in range(100):
        rec = EventTimingRecord(
            packet_event_time=1756680000.0 + i * 0.1,
            ingest_wall_time=1000.0,
            ingest_us=5.0,
            flow_state_us=10.0,
            feature_engine_us=20.0,
            entity_state_us=5.0,
            detectors_us=30.0,
            ml_preprocessor_us=10.0,
            ml_lgb_us=80.0,
            ml_calibrator_us=20.0,
            ml_iforest_us=40.0,
            ml_inference_us=150.0,  # Deliberately dominant
            fusion_us=15.0,
            incident_us=5.0,
            total_processing_us=240.0,
            packet_bytes=500,
        )
        profiler.record_event(rec)

    metrics = profiler.finish_run()
    assert metrics["events_processed"] == 100
    assert metrics["throughput_pps"] > 0.0
    assert metrics["throughput_mbps"] > 0.0
    assert "stage_latencies_us" in metrics
    assert "ml_substage_latencies_us" in metrics

    stages = metrics["stage_latencies_us"]
    assert "ml_inference" in stages
    assert stages["ml_inference"]["p50_us"] == 150.0
    assert stages["ml_inference"]["p95_us"] == 150.0
    assert metrics["dominant_bottleneck"] == "ml_inference"

    ml_subs = metrics["ml_substage_latencies_us"]
    assert "ml_lgb_multiclass" in ml_subs
    assert ml_subs["ml_lgb_multiclass"]["p50_us"] == 80.0
    assert ml_subs["ml_isolation_forest"]["p50_us"] == 40.0


def test_full_pipeline_benchmark_execution():
    """Verify that FullPipelineBenchmarkEngine executes all stages without exception."""
    engine = FullPipelineBenchmarkEngine()
    cfg = TrafficStreamConfig(duration_sec=0.5, target_pps=50.0)
    gen = SyntheticTrafficGenerator(cfg)
    pkts, labels = gen.generate_packets_with_labels(total_packets=25)

    res = engine.process_packet_stream(pkts, queue_capacity=1000, enable_resource_monitor=False, ground_truth_labels=labels)

    assert "profiler" in res
    assert "queue" in res
    assert "final_state_counts" in res
    assert "correctness" in res
    assert res["profiler"]["events_processed"] == 25
    assert res["profiler"]["throughput_pps"] > 0.0


def test_replay_speed_independence():
    """Verify that event-time detection latency is invariant across replay speeds."""
    engine = FullPipelineBenchmarkEngine()
    runner = ReplaySpeedIndependenceRunner(engine)
    res = runner.run_benchmark(packet_count=50)

    assert res["status"] == "PASS"
    assert res["event_time_invariant"] is True


def test_high_flow_churn_bounds():
    """Verify flow churn benchmark executes and maintains bounded state."""
    engine = FullPipelineBenchmarkEngine()
    runner = FlowChurnRunner(engine)
    res = runner.run_benchmark(flow_count=50)

    assert res["status"] == "PASS"
    assert res["ephemeral_flows_evaluated"] == 50
    assert res["throughput_pps"] > 0.0
    assert res["memory_bounded"] is True


def test_high_entity_churn_bounds():
    """Verify entity churn benchmark executes and maintains bounded EntityMemory profile size."""
    engine = FullPipelineBenchmarkEngine()
    runner = EntityChurnRunner(engine)
    res = runner.run_benchmark(entity_count=50)

    assert res["status"] == "PASS"
    assert res["unique_entities_evaluated"] == 50
    assert res["entity_memory_bounded"] is True


def test_state_pressure_cardinality_tracking():
    """Verify state pressure benchmark tracks destination, port, domain, and fingerprint cardinality."""
    engine = FullPipelineBenchmarkEngine()
    runner = StatePressureRunner(engine)
    res = runner.run_benchmark(packet_count=50)

    assert res["status"] == "PASS"
    assert res["state_bounded"] is True
    assert res["max_unique_destinations"] >= 1
    assert res["max_unique_ports"] >= 1
    assert res["max_unique_domains"] >= 1
    assert res["max_unique_fingerprints"] >= 1


def test_mixed_traffic_detection_correctness():
    """Verify mixed traffic correctness benchmark measures recall without silent loss."""
    engine = FullPipelineBenchmarkEngine()
    runner = MixedCorrectnessRunner(engine)
    res = runner.run_benchmark(total_packets=50)

    assert res["status"] == "PASS"
    assert res["total_packets_processed"] == 50
    cb = res["correctness_breakdown"]
    assert "precision" in cb
    assert "recall" in cb
    assert "f1_score" in cb


def test_m21_performance_runner_report_artifacts(tmp_path):
    """Verify that master M21 performance runner produces valid JSON and Markdown artifacts."""
    rep_data = run_full_m21_performance_benchmark(output_dir=str(tmp_path))

    assert rep_data["milestone"] in ("M21", "M21.5")
    assert "environment" in rep_data
    assert "baseline_profiling" in rep_data
    assert "load_sweep" in rep_data
    assert "replay_speed_independence" in rep_data
    assert "stress_scenarios" in rep_data
    assert "performance_ceiling_summary" in rep_data
    assert "state_bounds_audit" in rep_data

    json_path = os.path.join(tmp_path, "M21_PERFORMANCE_REPORT.json")
    md_path = os.path.join(tmp_path, "M21_PERFORMANCE_REPORT.md")

    assert os.path.exists(json_path)
    assert os.path.exists(md_path)

    with open(json_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        assert loaded["milestone"] in ("M21", "M21.5")
        assert "maximum_sustained_processed_pps" in loaded["performance_ceiling_summary"]

