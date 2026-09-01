"""Concept Drift Monitoring & Statistical Change Detection Engine (M20).

Implements:
1. Population Stability Index (PSI): Multi-bin distribution drift monitoring.
   - PSI < 0.10: No significant shift (STABLE)
   - 0.10 <= PSI < 0.25: Moderate shift (MONITOR)
   - PSI >= 0.25: Significant distribution change (DRIFT_DETECTED)
2. Adaptive Windowing (ADWIN): Streaming mean change detection with bounded adaptive sub-windows.
3. Multi-Feature Drift Monitor: Continuously monitors stable aggregate features:
   - packet rate
   - byte rate
   - flow rate
   - destination diversity
   - DNS query rate
   - TLS fingerprint novelty distribution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


class DriftSeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DriftEvent:
    """Standardized event emitted when statistical drift is detected on a monitored feature."""
    event_id: str
    feature_name: str
    baseline_window: str
    current_window: str
    metric: str
    drift_score: float
    threshold: float
    is_drift: bool
    severity: DriftSeverity
    event_time: float
    timestamp_iso: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "feature_name": self.feature_name,
            "baseline_window": self.baseline_window,
            "current_window": self.current_window,
            "metric": self.metric,
            "drift_score": round(self.drift_score, 4),
            "threshold": round(self.threshold, 4),
            "is_drift": self.is_drift,
            "severity": self.severity.value,
            "event_time": self.event_time,
            "timestamp_iso": self.timestamp_iso,
            "details": self.details,
        }


class PSIDriftDetector:
    """Population Stability Index (PSI) Drift Evaluator for continuous feature distributions."""

    def __init__(self, num_bins: int = 10, threshold: float = 0.25, eps: float = 1e-4):
        self.num_bins = num_bins
        self.threshold = threshold
        self.eps = eps

    def calculate_psi(
        self,
        baseline: np.ndarray,
        target: np.ndarray,
    ) -> Tuple[float, DriftSeverity]:
        """Compute PSI between baseline (reference) and target (current) distributions."""
        if len(baseline) == 0 or len(target) == 0:
            return 0.0, DriftSeverity.NONE

        b_clean = np.asarray(baseline, dtype=np.float64)
        t_clean = np.asarray(target, dtype=np.float64)

        b_clean = b_clean[~np.isnan(b_clean) & ~np.isinf(b_clean)]
        t_clean = t_clean[~np.isnan(t_clean) & ~np.isinf(t_clean)]

        if len(b_clean) == 0 or len(t_clean) == 0:
            return 0.0, DriftSeverity.NONE

        # Compute quantile bins from baseline
        quantiles = np.linspace(0, 100, self.num_bins + 1)
        bin_edges = np.percentile(b_clean, quantiles)
        bin_edges = np.unique(bin_edges)

        if len(bin_edges) <= 1:
            return 0.0, DriftSeverity.NONE

        # Ensure bounds cover all data
        bin_edges[0] = -np.inf
        bin_edges[-1] = np.inf

        b_counts, _ = np.histogram(b_clean, bins=bin_edges)
        t_counts, _ = np.histogram(t_clean, bins=bin_edges)

        # Standard Laplace pseudocount smoothing to handle sparse bins gracefully
        b_pct = (b_counts + 1.0) / (len(b_clean) + len(b_counts))
        t_pct = (t_counts + 1.0) / (len(t_clean) + len(t_counts))

        psi_val = float(np.sum((t_pct - b_pct) * np.log(t_pct / b_pct)))
        psi_val = max(0.0, psi_val)

        if psi_val < 0.10:
            sev = DriftSeverity.NONE
        elif psi_val < 0.25:
            sev = DriftSeverity.MODERATE
        elif psi_val < 0.50:
            sev = DriftSeverity.HIGH
        else:
            sev = DriftSeverity.CRITICAL

        return round(psi_val, 4), sev


class ADWINDriftDetector:
    """Adaptive Windowing (ADWIN) change detector for real-time streaming feature metrics."""

    def __init__(self, delta: float = 0.002, max_window: int = 1000):
        self.delta = delta
        self.max_window = max_window
        self.window: List[float] = []
        self.total: float = 0.0
        self.variance: float = 0.0

    def add_element(self, val: float) -> bool:
        """Add sample and check if a statistically significant mean change occurred."""
        if math.isnan(val) or math.isinf(val):
            return False

        self.window.append(val)
        self.total += val

        if len(self.window) > self.max_window:
            removed = self.window.pop(0)
            self.total -= removed

        # Check sub-windows for cut-point drift
        drift_detected = False
        n = len(self.window)
        if n >= 30:
            # Test split at midpoint
            n0 = n // 2
            n1 = n - n0
            w0 = self.window[:n0]
            w1 = self.window[n0:]

            m0 = sum(w0) / n0
            m1 = sum(w1) / n1

            # Harmonic mean of subwindow lengths
            m_harmonic = 1.0 / (1.0 / n0 + 1.0 / n1)
            # Bound calculation
            eps_cut = math.sqrt((1.0 / (2.0 * m_harmonic)) * math.log(4.0 * n / self.delta))

            if abs(m0 - m1) > eps_cut:
                drift_detected = True
                # Adapt window by dropping older segment
                self.window = w1
                self.total = sum(self.window)

        return drift_detected


class MultiFeatureDriftMonitor:
    """Central monitor tracking distribution stability across key feature aggregations."""

    MONITORED_FEATURES = (
        "packets_per_sec",
        "bytes_per_sec",
        "flow_count",
        "destination_diversity",
        "dns_query_rate",
        "tls_fingerprint_novelty",
    )

    def __init__(
        self,
        baseline_data: Optional[Dict[str, List[float]]] = None,
        psi_threshold: float = 0.25,
    ):
        self.psi_detector = PSIDriftDetector(threshold=psi_threshold)
        self.adwin_detectors = {f: ADWINDriftDetector() for f in self.MONITORED_FEATURES}
        self.baseline_buffers: Dict[str, List[float]] = baseline_data or {f: [] for f in self.MONITORED_FEATURES}
        self.current_buffers: Dict[str, List[float]] = {f: [] for f in self.MONITORED_FEATURES}
        self.detected_events: List[DriftEvent] = []

    def set_baseline(self, feature_name: str, values: List[float]) -> None:
        """Establish reference baseline distribution for a feature."""
        self.baseline_buffers[feature_name] = [v for v in values if not math.isnan(v) and not math.isinf(v)]

    def observe(self, feature_values: Dict[str, float], event_time: float) -> List[DriftEvent]:
        """Ingest new feature observation, update streaming monitors, and evaluate drift."""
        events: List[DriftEvent] = []
        ts_iso = datetime.fromtimestamp(event_time, tz=timezone.utc).isoformat()

        for feat, val in feature_values.items():
            if feat not in self.current_buffers or math.isnan(val) or math.isinf(val):
                continue

            self.current_buffers[feat].append(val)
            if len(self.current_buffers[feat]) > 500:
                self.current_buffers[feat].pop(0)

            # ADWIN streaming check
            adwin_fired = self.adwin_detectors[feat].add_element(val)
            if adwin_fired:
                evt = DriftEvent(
                    event_id=f"drift-adwin-{feat}-{int(event_time)}",
                    feature_name=feat,
                    baseline_window="streaming_history",
                    current_window="current_adaptive_window",
                    metric="ADWIN_MEAN_CHANGE",
                    drift_score=1.0,
                    threshold=self.adwin_detectors[feat].delta,
                    is_drift=True,
                    severity=DriftSeverity.MODERATE,
                    event_time=event_time,
                    timestamp_iso=ts_iso,
                    details={"trigger": "AdaptiveWindowMeanShift"},
                )
                events.append(evt)
                self.detected_events.append(evt)

        return events

    def evaluate_batch_psi(self, current_event_time: float) -> List[DriftEvent]:
        """Run batch PSI evaluation comparing baseline vs current buffer across all features."""
        events: List[DriftEvent] = []
        ts_iso = datetime.fromtimestamp(current_event_time, tz=timezone.utc).isoformat()

        for feat in self.MONITORED_FEATURES:
            base = np.array(self.baseline_buffers.get(feat, []))
            curr = np.array(self.current_buffers.get(feat, []))

            if len(base) < 20 or len(curr) < 20:
                continue

            psi_score, sev = self.psi_detector.calculate_psi(base, curr)
            is_drift = psi_score >= self.psi_detector.threshold

            if is_drift:
                evt = DriftEvent(
                    event_id=f"drift-psi-{feat}-{int(current_event_time)}",
                    feature_name=feat,
                    baseline_window="reference_baseline",
                    current_window="recent_sliding_window",
                    metric="POPULATION_STABILITY_INDEX",
                    drift_score=psi_score,
                    threshold=self.psi_detector.threshold,
                    is_drift=True,
                    severity=sev,
                    event_time=current_event_time,
                    timestamp_iso=ts_iso,
                    details={
                        "baseline_samples": len(base),
                        "current_samples": len(curr),
                        "baseline_mean": round(float(np.mean(base)), 3),
                        "current_mean": round(float(np.mean(curr)), 3),
                    },
                )
                events.append(evt)
                self.detected_events.append(evt)

        return events
