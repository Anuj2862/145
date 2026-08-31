"""
Tests for the Unified Detection Engine.

Uses real detector instances and lightweight FlowEvent fixtures.
Mocks/stubs are used only for failure-isolation and future-extensibility tests.
"""

import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from schemas import (
    FeatureVector, FlowFeatures, TemporalFeatures, DNSFeatures, TLSFeatures,
    DetectionSignal, ThreatClass, DetectorType, Severity, FlowEvent,
)
from features.recon_features import aggregate_recon_features, ReconFeatures
from features.exfil_features import aggregate_exfil_features, ExfiltrationFeatures

from detectors.ddos_detector import DDoSBaselineDetector
from detectors.c2_detector import C2BeaconDetector
from detectors.dns_detector import DNSAnomalyDetector
from detectors.encrypted_detector import EncryptedThreatDetector
from detectors.recon_detector import ReconDetector
from detectors.exfil_detector import ExfiltrationDetector
from detectors.engine import DetectionEngine, DetectionContext, DetectorResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ENTITY = "10.0.0.1"
TS = "2026-08-30T10:00:00Z"


def make_fv(pps=1.0, syn=0.0, periodicity=None, jitter=None,
            entropy=None, ja3=None, sni=None) -> FeatureVector:
    tf = None
    if periodicity is not None:
        tf = TemporalFeatures(
            inter_arrival_mean_ms=1000.0,
            inter_arrival_std_ms=0.0,
            periodicity_score=periodicity,
            jitter_pct=jitter or 0.0,
        )
    df = None
    if entropy is not None:
        df = DNSFeatures(entropy_mean=entropy, nxdomain_count=0)
    tlsf = None
    if ja3 or sni:
        tlsf = TLSFeatures(ja3_hash=ja3, sni=sni)

    return FeatureVector(
        feature_id="fv-engine-test",
        entity_ip=ENTITY,
        flow_id=f"{ENTITY}:50000-1.2.3.4:443-6",
        window_size_sec=5,
        timestamp_iso=TS,
        flow_features=FlowFeatures(
            packets_per_sec=pps,
            bytes_per_sec=pps * 100,
            syn_ratio=syn,
        ),
        temporal_features=tf,
        dns_features=df,
        tls_features=tlsf,
    )


def make_flow_event(dst_ip="1.2.3.4", dst_port=443, byte_count=500) -> FlowEvent:
    return FlowEvent(
        flow_id=f"{ENTITY}:50000-{dst_ip}:{dst_port}-6",
        src_ip=ENTITY, dst_ip=dst_ip,
        src_port=50000, dst_port=dst_port,
        protocol=6,
        start_time_iso=TS, end_time_iso=TS,
        duration_sec=60.0, packet_count=10,
        byte_count=byte_count,
    )


def benign_context() -> DetectionContext:
    fv = make_fv()
    flows = [make_flow_event() for _ in range(3)]
    rf = aggregate_recon_features(flows)
    ef = aggregate_exfil_features(flows, entity_ip=ENTITY, min_flows_required=3)
    return DetectionContext(
        source_entity=ENTITY,
        timestamp_iso=TS,
        feature_vector=fv,
        observation_count=5,
        recon_features=rf,
        exfil_features=ef,
    )


def all_six_detectors():
    return [
        DDoSBaselineDetector(),
        C2BeaconDetector(),
        DNSAnomalyDetector(),
        EncryptedThreatDetector(),
        ReconDetector(),
        ExfiltrationDetector(),
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDetectionEngine(unittest.TestCase):

    # 1. Empty engine
    def test_empty_engine_returns_empty_results(self):
        engine = DetectionEngine()
        ctx = benign_context()
        results = engine.run(ctx)
        self.assertEqual(results, [])
        self.assertEqual(engine.signals(ctx), [])

    # 2. Single detector
    def test_single_detector_registration(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        ctx = benign_context()
        results = engine.run(ctx)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].detector_name, "DDoSBaselineDetector")

    # 3. Multiple detectors
    def test_multiple_detectors(self):
        engine = DetectionEngine()
        for d in [DDoSBaselineDetector(), C2BeaconDetector()]:
            engine.register(d)
        ctx = benign_context()
        results = engine.run(ctx)
        self.assertEqual(len(results), 2)

    # 4. All six detectors produce signals
    def test_all_six_detectors_produce_signals(self):
        engine = DetectionEngine()
        for d in all_six_detectors():
            engine.register(d)
        ctx = benign_context()
        signals = engine.signals(ctx)
        self.assertEqual(len(signals), 6)
        for sig in signals:
            self.assertIsInstance(sig, DetectionSignal)

    # 5. Deterministic ordering (registration order)
    def test_deterministic_ordering(self):
        engine = DetectionEngine()
        for d in all_six_detectors():
            engine.register(d)
        ctx = benign_context()

        expected_order = [
            "DDoSBaselineDetector",
            "C2BeaconDetector",
            "DNSAnomalyDetector",
            "EncryptedThreatDetector",
            "ReconDetector",
            "ExfiltrationDetector",
        ]
        actual_order = [r.detector_name for r in engine.run(ctx)]
        self.assertEqual(actual_order, expected_order)

    # 6. Enable / disable
    def test_disable_prevents_execution(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        engine.register(C2BeaconDetector())
        engine.disable(DDoSBaselineDetector)

        ctx = benign_context()
        results = engine.run(ctx)

        # DDoS result should have no signal and no error (just disabled)
        ddos_result = results[0]
        self.assertIsNone(ddos_result.signal)
        self.assertIsNone(ddos_result.error)
        self.assertFalse(ddos_result.succeeded)

        # C2 result should succeed
        self.assertTrue(results[1].succeeded)

    def test_enable_restores_execution(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        engine.disable(DDoSBaselineDetector)
        engine.enable(DDoSBaselineDetector)

        ctx = benign_context()
        results = engine.run(ctx)
        self.assertTrue(results[0].succeeded)

    # 7. Detector failure isolation
    def test_failing_detector_does_not_block_others(self):
        engine = DetectionEngine()

        # Register a broken detector via a mock that raises
        broken = MagicMock()
        broken.__class__ = type("BrokenDetector", (), {})
        broken.evaluate.side_effect = RuntimeError("Simulated crash")

        # Manually inject via internal _DetectorWrapper to bypass isinstance dispatch
        from detectors.engine import _DetectorWrapper
        engine._wrappers.append(_DetectorWrapper(detector=broken, name="BrokenDetector"))
        engine.register(DDoSBaselineDetector())

        ctx = benign_context()
        results = engine.run(ctx)

        self.assertEqual(len(results), 2)
        broken_result = results[0]
        ddos_result   = results[1]

        # Broken detector should record error, not crash everything
        self.assertFalse(broken_result.succeeded)
        self.assertIsNotNone(broken_result.error)
        self.assertIn("RuntimeError", broken_result.error)

        # Good detector still produced a signal
        self.assertTrue(ddos_result.succeeded)

    # 8. Failure visibility
    def test_failure_is_observable(self):
        engine = DetectionEngine()
        broken = MagicMock()
        broken.evaluate.side_effect = ValueError("Bad input")

        from detectors.engine import _DetectorWrapper
        engine._wrappers.append(_DetectorWrapper(detector=broken, name="BadDetector"))

        results = engine.run(benign_context())
        self.assertEqual(results[0].error, None if results[0].succeeded else results[0].error)
        self.assertFalse(results[0].succeeded)
        self.assertIn("ValueError", results[0].error)

    # 9. Duplicate detector guard
    def test_duplicate_registration_raises(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        with self.assertRaises(ValueError):
            engine.register(DDoSBaselineDetector())

    def test_allow_duplicate_flag(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        engine.register(DDoSBaselineDetector(), allow_duplicate=True)
        self.assertEqual(len(engine), 2)

    # 10. DetectionSignal propagation — signals are unchanged
    def test_signals_propagated_unmodified(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        ctx = benign_context()
        results = engine.run(ctx)
        signal = results[0].signal

        self.assertEqual(signal.threat_class, ThreatClass.VOLUMETRIC_DDOS)
        self.assertEqual(signal.detector_type, DetectorType.DETERMINISTIC_BASELINE)
        self.assertIsInstance(signal.confidence, float)

    # 11. Evidence preserved (indicators not stripped)
    def test_evidence_preserved_in_indicators(self):
        fv = make_fv(pps=6000.0, syn=0.9)
        ctx = DetectionContext(source_entity=ENTITY, timestamp_iso=TS, feature_vector=fv)
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        results = engine.run(ctx)
        sig = results[0].signal
        self.assertTrue(len(sig.indicators) > 0)

    # 12. Engine does NOT modify scores
    def test_engine_does_not_modify_scores(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        ctx = benign_context()
        sig = engine.signals(ctx)[0]
        # Score is 0.0 for benign traffic
        self.assertEqual(sig.confidence, 0.0)

    # 13. Engine does NOT merge signals
    def test_engine_does_not_merge_signals(self):
        engine = DetectionEngine()
        for d in [DDoSBaselineDetector(), C2BeaconDetector()]:
            engine.register(d)
        ctx = benign_context()
        signals = engine.signals(ctx)
        # Should have two separate, distinct signals
        self.assertEqual(len(signals), 2)
        classes = {s.threat_class for s in signals}
        self.assertIn(ThreatClass.VOLUMETRIC_DDOS, classes)
        self.assertIn(ThreatClass.BOTNET_C2_BEACONING, classes)

    # 14. Future detector compatibility (generic evaluate(ctx) path)
    def test_future_detector_generic_interface(self):
        """A future ML detector implementing evaluate(ctx) can be registered."""
        class FakeMLDetector:
            def evaluate(self, ctx: DetectionContext) -> DetectionSignal:
                return DetectionSignal(
                    signal_id="sig-ml-fake",
                    threat_class=ThreatClass.UNKNOWN_ANOMALY,
                    detector_type=DetectorType.LIGHTWEIGHT_ML,
                    confidence=0.5,
                    severity=Severity.MEDIUM,
                    source_entity=ctx.source_entity,
                    timestamp_iso=ctx.timestamp_iso,
                    indicators={"ml_score": 0.5},
                )

        engine = DetectionEngine()
        engine.register(FakeMLDetector())
        ctx = benign_context()
        signals = engine.signals(ctx)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].threat_class, ThreatClass.UNKNOWN_ANOMALY)
        self.assertEqual(signals[0].detector_type, DetectorType.LIGHTWEIGHT_ML)

    # 15. Registered names introspection
    def test_registered_names_in_order(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        engine.register(C2BeaconDetector())
        self.assertEqual(engine.registered_names,
                         ["DDoSBaselineDetector", "C2BeaconDetector"])

    # 16. Missing context inputs handled gracefully
    def test_missing_recon_features_returns_error_not_crash(self):
        engine = DetectionEngine()
        engine.register(ReconDetector())
        # Context with no recon_features
        ctx = DetectionContext(source_entity=ENTITY, timestamp_iso=TS, feature_vector=make_fv())
        results = engine.run(ctx)
        self.assertFalse(results[0].succeeded)
        self.assertIsNotNone(results[0].error)

    def test_missing_feature_vector_returns_error_not_crash(self):
        engine = DetectionEngine()
        engine.register(DDoSBaselineDetector())
        # Context with no feature_vector
        ctx = DetectionContext(source_entity=ENTITY, timestamp_iso=TS)
        results = engine.run(ctx)
        self.assertFalse(results[0].succeeded)


if __name__ == "__main__":
    unittest.main()
