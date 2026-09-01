"""End-to-End Pipeline & Fine-Grained Stage Latency Profiler (Milestones 21 & 21.5).

Measures latency across every constituent pipeline stage and ML sub-stages:
1. Ingest (Packet normalization & queueing)
2. Flow State (Flow key hashing & window aggregation)
3. FeatureEngine (Canonical FeatureEngine extraction)
4. EntityState (Profile retrieval & novelty/baseline deviation)
5. Threat Detectors (6 behavioral detectors execution)
6. ML Inference:
   - Feature Preprocessing / Vectorization
   - LightGBM Multiclass Prediction
   - Probability Calibration (Isotonic Regression)
   - Isolation Forest Anomaly Scoring
7. MultiSignal Fusion (M17 evidence fusion & risk scoring)
8. Incident Lifecycle (M18 incident correlation & transitions)

Separates:
- Processing Latency (Wall-clock execution duration in microseconds/milliseconds)
- Event-Time Detection Latency (Timestamp delta between packet event_time and alert event_time)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import numpy as np
import time
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class EventTimingRecord:
    """Microsecond-level latency breakdown and event-time tracking for a single processed event."""
    packet_event_time: float
    ingest_wall_time: float
    ingest_us: float = 0.0
    flow_state_us: float = 0.0
    feature_engine_us: float = 0.0
    entity_state_us: float = 0.0
    detectors_us: float = 0.0
    
    # ML Sub-stage timings
    ml_preprocessor_us: float = 0.0
    ml_lgb_us: float = 0.0
    ml_calibrator_us: float = 0.0
    ml_iforest_us: float = 0.0
    ml_inference_us: float = 0.0
    
    fusion_us: float = 0.0
    incident_us: float = 0.0
    total_processing_us: float = 0.0
    
    # Event-time milestone latencies
    first_signal_event_time: Optional[float] = None
    fusion_event_time: Optional[float] = None
    incident_event_time: Optional[float] = None
    alert_event_time: Optional[float] = None
    alert_wall_time: Optional[float] = None
    
    packet_bytes: int = 0
    threat_detected: bool = False
    threat_class_name: Optional[str] = None


class PipelineProfiler:
    """High-resolution profiler for stage latency distributions and bottleneck analysis."""

    def __init__(self):
        self.records: List[EventTimingRecord] = []
        self._t_start_wall: Optional[float] = None
        self._t_end_wall: Optional[float] = None
        self.total_bytes_processed: int = 0
        self.total_flows_observed: int = 0
        self.dropped_events_count: int = 0

    def start_run(self) -> None:
        """Mark start of benchmark run."""
        self.records.clear()
        self.total_bytes_processed = 0
        self.total_flows_observed = 0
        self.dropped_events_count = 0
        self._t_start_wall = time.perf_counter()

    def record_event(self, rec: EventTimingRecord) -> None:
        """Append timing record for a processed event."""
        if len(self.records) < 200000:
            self.records.append(rec)
        self.total_bytes_processed += rec.packet_bytes

    def record_drop(self, count: int = 1) -> None:
        """Increment count of dropped events."""
        self.dropped_events_count += count

    def finish_run(self) -> Dict[str, Any]:
        """Compile comprehensive latency distribution and stage profiling metrics."""
        self._t_end_wall = time.perf_counter()
        duration_sec = max(1e-6, (self._t_end_wall - (self._t_start_wall or self._t_end_wall)))

        n_events = len(self.records)
        if n_events == 0:
            return {
                "events_processed": 0,
                "duration_sec": round(duration_sec, 4),
                "throughput_pps": 0.0,
                "throughput_mbps": 0.0,
                "stage_latencies_us": {},
                "ml_substage_latencies_us": {},
                "detection_latency_sec": {},
                "dominant_bottleneck": "NONE",
            }

        # Stage latency arrays in microseconds
        stages = {
            "ingest": [r.ingest_us for r in self.records],
            "flow_state": [r.flow_state_us for r in self.records],
            "feature_engine": [r.feature_engine_us for r in self.records],
            "entity_state": [r.entity_state_us for r in self.records],
            "detectors": [r.detectors_us for r in self.records],
            "ml_inference": [r.ml_inference_us for r in self.records],
            "fusion": [r.fusion_us for r in self.records],
            "incident": [r.incident_us for r in self.records],
            "end_to_end": [r.total_processing_us for r in self.records],
        }

        # ML Sub-stages
        ml_substages = {
            "ml_preprocessor": [r.ml_preprocessor_us for r in self.records],
            "ml_lgb_multiclass": [r.ml_lgb_us for r in self.records],
            "ml_probability_calibration": [r.ml_calibrator_us for r in self.records],
            "ml_isolation_forest": [r.ml_iforest_us for r in self.records],
        }

        stage_profiles: Dict[str, Any] = {}
        stage_means: Dict[str, float] = {}

        def _calc_stats(arr_list: List[float]) -> Dict[str, float]:
            arr = np.array(arr_list, dtype=np.float64)
            return {
                "p50_us": round(float(np.percentile(arr, 50)), 2),
                "p90_us": round(float(np.percentile(arr, 90)), 2),
                "p95_us": round(float(np.percentile(arr, 95)), 2),
                "p99_us": round(float(np.percentile(arr, 99)), 2),
                "max_us": round(float(np.max(arr)), 2),
                "mean_us": round(float(np.mean(arr)), 2),
                "std_us": round(float(np.std(arr)), 2),
            }

        for name, lat_list in stages.items():
            stats = _calc_stats(lat_list)
            stage_profiles[name] = stats
            if name != "end_to_end":
                stage_means[name] = stats["mean_us"]

        ml_substage_profiles: Dict[str, Any] = {}
        for name, lat_list in ml_substages.items():
            ml_substage_profiles[name] = _calc_stats(lat_list)

        # Compute percentage contribution of each stage
        total_mean_sum = sum(stage_means.values()) or 1.0
        for name in stage_means:
            contrib = (stage_means[name] / total_mean_sum) * 100.0
            stage_profiles[name]["cpu_latency_contribution_pct"] = round(contrib, 2)

        # Event-time detection latency metrics (alert_event_time - packet_event_time)
        detection_delays = [
            (r.alert_event_time - r.packet_event_time)
            for r in self.records
            if r.threat_detected and r.alert_event_time is not None
        ]
        det_lat_stats: Dict[str, float] = {}
        if detection_delays:
            arr_det = np.array(detection_delays, dtype=np.float64)
            det_lat_stats = {
                "count": len(detection_delays),
                "p50_sec": round(float(np.percentile(arr_det, 50)), 4),
                "p90_sec": round(float(np.percentile(arr_det, 90)), 4),
                "p95_sec": round(float(np.percentile(arr_det, 95)), 4),
                "p99_sec": round(float(np.percentile(arr_det, 99)), 4),
                "max_sec": round(float(np.max(arr_det)), 4),
                "mean_sec": round(float(np.mean(arr_det)), 4),
            }

        # Identify dominant bottleneck
        dominant_stage = max(stage_means.items(), key=lambda x: x[1])[0]

        # Throughput metrics
        pps = n_events / duration_sec
        mbps = (self.total_bytes_processed * 8.0) / (duration_sec * 1e6)
        total_received = n_events + self.dropped_events_count
        drop_rate_pct = (self.dropped_events_count / max(1, total_received)) * 100.0

        return {
            "events_processed": n_events,
            "duration_sec": round(duration_sec, 4),
            "throughput_pps": round(pps, 2),
            "throughput_mbps": round(mbps, 3),
            "total_bytes": self.total_bytes_processed,
            "dropped_events": self.dropped_events_count,
            "drop_rate_pct": round(drop_rate_pct, 4),
            "stage_latencies_us": stage_profiles,
            "ml_substage_latencies_us": ml_substage_profiles,
            "detection_latency_event_time": det_lat_stats,
            "dominant_bottleneck": dominant_stage,
        }
