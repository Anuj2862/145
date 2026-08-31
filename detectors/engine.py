"""
Unified Detection Engine for Member-2 (UniGuard AI — PS 26145).

Orchestrates all six deterministic baseline detectors and returns
an ordered list of DetectionSignal objects.

DESIGN PRINCIPLES:
    - Each detector runs independently; one failure cannot block others.
    - The engine performs NO score fusion, NO risk aggregation, and
      NO cross-signal correlation. That is Member-3's responsibility.
    - Output ordering is deterministic (registration order).
    - Detectors can be individually enabled/disabled after registration.
    - Duplicate detector types are guarded by a stable identity check.
    - The engine is extensible: future ML detectors implement the same
      callable interface and can be registered without changes to this file.

DETECTOR INTERFACES SUPPORTED:
    FeatureVector-based detectors  : DDoSBaselineDetector, C2BeaconDetector,
                                     DNSAnomalyDetector, EncryptedThreatDetector
    ReconFeatures-based detector   : ReconDetector
    ExfiltrationFeatures-based     : ExfiltrationDetector

Each detector receives only the input it actually requires via a
DetectionContext that carries all available inputs for the current window.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import List, Optional, Any
from datetime import datetime, timezone

from schemas import DetectionSignal, FeatureVector
from features.recon_features import ReconFeatures
from features.exfil_features import ExfiltrationFeatures


# ---------------------------------------------------------------------------
# DetectionContext
# ---------------------------------------------------------------------------

@dataclass
class DetectionContext:
    """
    Lightweight, engine-internal container holding all inputs available for a
    single entity/window evaluation pass.

    The context is NOT a shared schema. It is internal to Member-2's engine
    and must not be imported by Members 1 or 3.
    """
    source_entity: str
    timestamp_iso: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Feature-vector-based inputs (single-flow or window summary)
    feature_vector: Optional[FeatureVector] = None

    # observation_count: Number of flow events that contributed to the
    # TemporalFeatures inside feature_vector.  Required by C2BeaconDetector.
    observation_count: int = 0

    # Window-level aggregations (separate from single-flow FeatureVector)
    recon_features: Optional[ReconFeatures] = None
    exfil_features: Optional[ExfiltrationFeatures] = None


# ---------------------------------------------------------------------------
# DetectorResult — wraps success OR failure for a single detector run
# ---------------------------------------------------------------------------

@dataclass
class DetectorResult:
    """Wraps a single detector's outcome — either a signal or an error."""
    detector_name: str
    signal: Optional[DetectionSignal] = None
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.signal is not None


# ---------------------------------------------------------------------------
# BaseDetectorWrapper — normalises the heterogeneous evaluate() signatures
# ---------------------------------------------------------------------------

class _DetectorWrapper:
    """
    Wraps a concrete detector instance and handles the routing logic
    (which fields from DetectionContext to pass to which detector).

    Each detector's evaluate() has a different signature; this wrapper
    dispatches the correct arguments so the engine doesn't need to know
    the internal signatures of individual detectors.
    """

    def __init__(self, detector: Any, name: str):
        self.detector = detector
        self.name = name
        self.enabled = True

    def run(self, ctx: DetectionContext) -> DetectorResult:
        if not self.enabled:
            return DetectorResult(detector_name=self.name)  # no signal, no error

        try:
            from detectors.ddos_detector import DDoSBaselineDetector
            from detectors.c2_detector import C2BeaconDetector
            from detectors.dns_detector import DNSAnomalyDetector
            from detectors.encrypted_detector import EncryptedThreatDetector
            from detectors.recon_detector import ReconDetector
            from detectors.exfil_detector import ExfiltrationDetector

            d = self.detector

            if isinstance(d, (DDoSBaselineDetector, DNSAnomalyDetector, EncryptedThreatDetector)):
                # These expect a FeatureVector
                if ctx.feature_vector is None:
                    return DetectorResult(
                        detector_name=self.name,
                        error="FeatureVector not provided in DetectionContext",
                    )
                signal = d.evaluate(ctx.feature_vector)

            elif isinstance(d, C2BeaconDetector):
                if ctx.feature_vector is None:
                    return DetectorResult(
                        detector_name=self.name,
                        error="FeatureVector not provided in DetectionContext",
                    )
                signal = d.evaluate(ctx.feature_vector,
                                    observation_count=ctx.observation_count)

            elif isinstance(d, ReconDetector):
                if ctx.recon_features is None:
                    return DetectorResult(
                        detector_name=self.name,
                        error="ReconFeatures not provided in DetectionContext",
                    )
                signal = d.evaluate(
                    ctx.recon_features,
                    source_entity=ctx.source_entity,
                    timestamp_iso=ctx.timestamp_iso,
                )

            elif isinstance(d, ExfiltrationDetector):
                if ctx.exfil_features is None:
                    return DetectorResult(
                        detector_name=self.name,
                        error="ExfiltrationFeatures not provided in DetectionContext",
                    )
                signal = d.evaluate(
                    ctx.exfil_features,
                    source_entity=ctx.source_entity,
                    timestamp_iso=ctx.timestamp_iso,
                )

            else:
                # Future extensibility: attempt a generic evaluate(ctx) call.
                # Future ML detectors (LightGBM, XGBoost, IsolationForest) can
                # implement evaluate(ctx: DetectionContext) -> DetectionSignal.
                signal = d.evaluate(ctx)

            return DetectorResult(detector_name=self.name, signal=signal)

        except Exception as exc:
            return DetectorResult(
                detector_name=self.name,
                error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
            )


# ---------------------------------------------------------------------------
# DetectionEngine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Orchestrates all registered Member-2 detectors for a given entity window.

    Usage:
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        engine.register(C2BeaconDetector())
        ...
        results = engine.run(ctx)               # -> List[DetectorResult]
        signals = engine.signals(ctx)           # -> List[DetectionSignal]

    Output ordering is deterministic and follows registration order.
    """

    def __init__(self):
        self._wrappers: List[_DetectorWrapper] = []
        self._registered_types: set = set()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, detector: Any, *, allow_duplicate: bool = False) -> "DetectionEngine":
        """
        Register a detector instance.

        Args:
            detector: Any detector instance with an evaluate() method.
            allow_duplicate: Set to True to allow multiple instances of the
                             same type (e.g., two DDoS detectors with different
                             thresholds).  Default False.

        Returns:
            self  (for chaining)

        Raises:
            ValueError: If the same type is registered twice without
                        allow_duplicate=True.
        """
        dtype = type(detector)
        name = dtype.__name__

        if not allow_duplicate and dtype in self._registered_types:
            raise ValueError(
                f"Detector '{name}' is already registered. "
                "Pass allow_duplicate=True to register multiple instances."
            )

        self._registered_types.add(dtype)
        self._wrappers.append(_DetectorWrapper(detector=detector, name=name))
        return self

    def enable(self, detector_type: type) -> None:
        """Enable a previously disabled detector."""
        for w in self._wrappers:
            if isinstance(w.detector, detector_type):
                w.enabled = True

    def disable(self, detector_type: type) -> None:
        """Disable a registered detector (skips execution, no error)."""
        for w in self._wrappers:
            if isinstance(w.detector, detector_type):
                w.enabled = False

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, ctx: DetectionContext) -> List[DetectorResult]:
        """
        Run all enabled detectors and return DetectorResult objects in
        registration order.  Detector failures do not block other detectors.
        """
        results: List[DetectorResult] = []
        for wrapper in self._wrappers:
            result = wrapper.run(ctx)
            results.append(result)
        return results

    def signals(self, ctx: DetectionContext) -> List[DetectionSignal]:
        """
        Convenience method: run all detectors and return only successful
        DetectionSignal objects (failures are silently excluded from the list
        but are still observable via run()).
        """
        return [r.signal for r in self.run(ctx) if r.succeeded]

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def registered_names(self) -> List[str]:
        """Ordered list of registered detector names."""
        return [w.name for w in self._wrappers]

    def __len__(self) -> int:
        return len(self._wrappers)
