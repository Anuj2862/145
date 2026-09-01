"""Multi-Signal Fusion, Entity Correlation and Risk Scoring Engine (Member 3 - M17 / M17.5 Integrity).

Provides transparent, deterministic, and configurable fusion across:
1. Behavioral detector signals (DDoS, C2, DNS/DGA, Encrypted, Recon, Exfiltration)
2. Native calibrated ML probabilities (LightGBM / Random Forest)
3. Unsupervised Isolation Forest anomaly scores
4. Entity baseline deviations & novelty context (M14)
5. Event-time temporal persistence (tracked per entity + threat class) and decay
6. Evidence source diversity (multi-source confirmation)

Maintains bounded memory with strict LRU eviction and event-time ordering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import OrderedDict, defaultdict
import uuid

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
from entity.graph import EntityBehaviourGraph, NodeType, EdgeType
from models.inference.ml_inference import (
    ClassificationResult,
    AnomalyResult,
    UnifiedMLResult,
)


SUPPORTING_THREAT_RELATIONSHIPS: Dict[ThreatClass, Set[ThreatClass]] = {
    ThreatClass.RECON_PORT_SCAN: {
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.VOLUMETRIC_DDOS,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.BOTNET_C2_BEACONING: {
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.DGA_DNS_TUNNELLING: {
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.ENCRYPTED_MALWARE: {
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.DATA_EXFILTRATION: {
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.VOLUMETRIC_DDOS: {
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.UNKNOWN_ANOMALY: {
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.VOLUMETRIC_DDOS,
        ThreatClass.DATA_EXFILTRATION,
    },
}


@dataclass
class FusionConfig:
    """Configurable weights, windows, and thresholds for multi-signal fusion."""
    # Normalized Fusion Weights (Sum = 1.00)
    w_detector: float = 0.30
    w_ml: float = 0.25
    w_anomaly: float = 0.15
    w_context: float = 0.15
    w_persistence: float = 0.10
    w_diversity: float = 0.05

    # Temporal windows & decay (in seconds)
    correlation_window_sec: float = 300.0
    decay_half_life_sec: float = 300.0
    max_signals_per_entity: int = 100
    max_entities: int = 10000  # P1-3: Global bounded entity state cache

    # Severity Risk Thresholds
    threshold_critical: float = 0.85
    threshold_high: float = 0.65
    threshold_medium: float = 0.40
    threshold_low: float = 0.15


# Compatible supporting threat relationships
SUPPORTING_THREAT_RELATIONSHIPS: Dict[ThreatClass, Set[ThreatClass]] = {
    ThreatClass.VOLUMETRIC_DDOS: {ThreatClass.RECON_PORT_SCAN, ThreatClass.UNKNOWN_ANOMALY},
    ThreatClass.BOTNET_C2_BEACONING: {ThreatClass.DGA_DNS_TUNNELLING, ThreatClass.ENCRYPTED_MALWARE, ThreatClass.UNKNOWN_ANOMALY},
    ThreatClass.DGA_DNS_TUNNELLING: {ThreatClass.BOTNET_C2_BEACONING, ThreatClass.DATA_EXFILTRATION, ThreatClass.UNKNOWN_ANOMALY},
    ThreatClass.ENCRYPTED_MALWARE: {ThreatClass.BOTNET_C2_BEACONING, ThreatClass.DATA_EXFILTRATION, ThreatClass.UNKNOWN_ANOMALY},
    ThreatClass.RECON_PORT_SCAN: {ThreatClass.VOLUMETRIC_DDOS, ThreatClass.DATA_EXFILTRATION, ThreatClass.UNKNOWN_ANOMALY},
    ThreatClass.DATA_EXFILTRATION: {ThreatClass.DGA_DNS_TUNNELLING, ThreatClass.ENCRYPTED_MALWARE, ThreatClass.UNKNOWN_ANOMALY},
    ThreatClass.UNKNOWN_ANOMALY: set(ThreatClass),
}


class EntityCorrelationState:
    """Bounded, entity-isolated event-time signal tracking and threat-specific persistence buffer."""

    def __init__(self, entity_id: str, config: FusionConfig):
        self.entity_id = entity_id
        self.config = config
        self.signals: List[DetectionSignal] = []
        self._dedup_map: Dict[str, DetectionSignal] = {}
        self.first_seen_event_time: Optional[float] = None
        self.latest_event_time: Optional[float] = None

        # P1-5: Threat-specific persistence tracking (entity_id + threat_class)
        self._threat_first_seen: Dict[ThreatClass, float] = {}
        self._threat_latest_seen: Dict[ThreatClass, float] = {}

    def add_signal(self, signal: DetectionSignal) -> bool:
        """Ingest a DetectionSignal with deterministic deduplication and event-time tracking."""
        if signal.source_entity != self.entity_id and signal.entity_id != self.entity_id:
            # Reject signals belonging to another entity (strict entity isolation)
            return False

        t = signal.event_time or (
            datetime.fromisoformat(signal.timestamp_iso.replace("Z", "+00:00")).timestamp()
            if signal.timestamp_iso else 0.0
        )

        if self.first_seen_event_time is None or t < self.first_seen_event_time:
            self.first_seen_event_time = t
        if self.latest_event_time is None or t > self.latest_event_time:
            self.latest_event_time = t

        # Update threat-specific timestamps (P1-5)
        tc = signal.threat_class
        if tc not in self._threat_first_seen or t < self._threat_first_seen[tc]:
            self._threat_first_seen[tc] = t
        if tc not in self._threat_latest_seen or t > self._threat_latest_seen[tc]:
            self._threat_latest_seen[tc] = t

        # Deterministic deduplication key (10s time bucket)
        det_key = str(signal.detector_id or signal.detector_type.value)
        flow_key = str(signal.flow_id or "noflow")
        bucket = round(t / 10.0)
        dedup_key = f"{self.entity_id}|{det_key}|{signal.threat_class.value}|{flow_key}|{bucket}"

        if dedup_key in self._dedup_map:
            # Update existing observation with higher confidence / latest data without double-counting
            existing = self._dedup_map[dedup_key]
            if signal.confidence > existing.confidence:
                self._dedup_map[dedup_key] = signal
            return False

        self._dedup_map[dedup_key] = signal
        self.signals.append(signal)

        # Enforce bounded history
        if len(self.signals) > self.config.max_signals_per_entity:
            oldest = self.signals.pop(0)
            # Cleanup dedup map
            keys_to_del = [k for k, s in self._dedup_map.items() if s.signal_id == oldest.signal_id]
            for k in keys_to_del:
                del self._dedup_map[k]

        return True

    def get_persistence_duration(
        self,
        threat_class: Optional[ThreatClass] = None,
        current_event_time: Optional[float] = None,
    ) -> float:
        """Calculate threat-specific event-time persistence duration in seconds (P1-5)."""
        if not self.signals:
            return 0.0

        if threat_class is not None and threat_class in self._threat_first_seen:
            t_first = self._threat_first_seen[threat_class]
            t_latest = self._threat_latest_seen.get(threat_class, t_first)
            t_curr = current_event_time or t_latest
            return max(0.0, t_curr - t_first)

        if self.first_seen_event_time is None:
            return 0.0
        t_curr = current_event_time or self.latest_event_time or self.first_seen_event_time
        return max(0.0, t_curr - self.first_seen_event_time)

    def get_evidence_source_families(self) -> Set[SignalFamily]:
        """Collect distinct evidence source categories active for this entity (P1-7)."""
        families: Set[SignalFamily] = set()
        for sig in self.signals:
            if sig.detector_type == DetectorType.DETERMINISTIC_BASELINE:
                families.add(SignalFamily.HEURISTIC_DETECTOR)
            elif sig.detector_type == DetectorType.LIGHTWEIGHT_ML:
                families.add(SignalFamily.CALIBRATED_ML)
            elif sig.detector_type == DetectorType.UNSUPERVISED_ANOMALY:
                families.add(SignalFamily.UNSUPERVISED_ANOMALY)
            else:
                families.add(SignalFamily.HEURISTIC_DETECTOR)
        return families

    def compute_decayed_detector_score(
        self,
        current_event_time: Optional[float] = None,
    ) -> Tuple[float, ThreatClass, Optional[DetectionSignal]]:
        """Compute highest exponentially-decayed detector score and primary threat class."""
        if not self.signals:
            return 0.0, ThreatClass.UNKNOWN_ANOMALY, None

        t_curr = current_event_time or self.latest_event_time or 0.0
        tau = self.config.decay_half_life_sec

        best_score = 0.0
        best_threat = ThreatClass.UNKNOWN_ANOMALY
        best_sig = None

        for sig in self.signals:
            sig_time = sig.event_time or (
                datetime.fromisoformat(sig.timestamp_iso.replace("Z", "+00:00")).timestamp()
                if sig.timestamp_iso else t_curr
            )
            dt = max(0.0, t_curr - sig_time)
            decay = math.exp(-dt / tau) if tau > 0 else 1.0
            decayed = (sig.score if sig.score is not None else sig.confidence) * decay

            if decayed > best_score:
                best_score = decayed
                best_threat = sig.threat_class
                best_sig = sig

        return min(1.0, max(0.0, best_score)), best_threat, best_sig


class ActiveCorrelationGroup:
    """Backward-compatible tracking container for active correlated entity signals (P1-4)."""

    def __init__(self, primary_entity: str, window_duration_sec: int = 300):
        self.group_id = f"GRP-{uuid.uuid4().hex[:8]}"
        self.primary_entity = primary_entity
        self.window_duration_sec = window_duration_sec
        self.signals: List[DetectionSignal] = []
        self.created_at = datetime.now(timezone.utc)
        self.last_updated = self.created_at
        self.last_event_time: Optional[float] = None

    def add_signal(self, signal: DetectionSignal) -> None:
        self.signals.append(signal)
        self.last_updated = datetime.now(timezone.utc)
        if signal.event_time is not None:
            self.last_event_time = signal.event_time

    def is_expired(self, current_time: Optional[Union[datetime, float]] = None) -> bool:
        """Check if group has expired using event_time when available (P1-4)."""
        if isinstance(current_time, (int, float)) and self.last_event_time is not None:
            return (current_time - self.last_event_time) > self.window_duration_sec
        
        now = current_time if isinstance(current_time, datetime) else datetime.now(timezone.utc)
        return (now - self.last_updated).total_seconds() > self.window_duration_sec

    def compute_composite_risk(self, baseline_deviation: float = 0.0) -> Tuple[float, Severity]:
        """Compute composite risk score [0.0, 1.0] and overall severity."""
        if not self.signals:
            return 0.0, Severity.INFO

        max_conf = max((s.score if s.score is not None else s.confidence) for s in self.signals)
        threat_classes = {s.threat_class for s in self.signals}
        diversity_bonus = min(0.25, (len(threat_classes) - 1) * 0.10)
        detector_types = {s.detector_type for s in self.signals}
        agreement_bonus = 0.10 if len(detector_types) > 1 else 0.0
        deviation_bonus = min(0.15, max(0.0, (baseline_deviation - 2.0) * 0.03)) if baseline_deviation > 2.0 else 0.0

        fused_score = min(0.99, max_conf + diversity_bonus + agreement_bonus + deviation_bonus)

        if fused_score >= 0.90 or Severity.CRITICAL in [s.severity for s in self.signals]:
            severity = Severity.CRITICAL
        elif fused_score >= 0.70 or Severity.HIGH in [s.severity for s in self.signals]:
            severity = Severity.HIGH
        elif fused_score >= 0.40:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return round(fused_score, 3), severity


class MultiSignalFusionEngine:
    """Production Multi-Signal Fusion Engine (M17 / M17.5).

    Coordinates entity-level correlation, weighted risk aggregation, conflict resolution,
    and structured evidence contribution tracking across detectors and ML pipelines.
    Enforces bounded memory with LRU eviction and event-time ordering.
    """

    def __init__(
        self,
        config: Optional[FusionConfig] = None,
        correlation_window_sec: Optional[int] = None,
    ):
        self.config = config or FusionConfig()
        if correlation_window_sec is not None:
            self.config.correlation_window_sec = float(correlation_window_sec)

        # P1-3: Global bounded entity state cache using OrderedDict for LRU eviction
        self._entity_states: OrderedDict[str, EntityCorrelationState] = OrderedDict()
        self._active_groups: Dict[str, ActiveCorrelationGroup] = {}

    def _get_or_create_state(self, entity_id: str) -> EntityCorrelationState:
        """Retrieve or create entity correlation state with bounded LRU eviction (P1-3)."""
        if entity_id in self._entity_states:
            self._entity_states.move_to_end(entity_id)
            return self._entity_states[entity_id]

        # Enforce max_entities bound
        if len(self._entity_states) >= self.config.max_entities:
            # Evict oldest LRU entity
            evicted_id, evicted_state = self._entity_states.popitem(last=False)
            evicted_state.signals.clear()
            evicted_state._dedup_map.clear()

        new_state = EntityCorrelationState(entity_id, self.config)
        self._entity_states[entity_id] = new_state
        return new_state

    def fuse(
        self,
        signals: List[DetectionSignal],
        ml_result: Optional[Union[UnifiedMLResult, ClassificationResult]] = None,
        anomaly_result: Optional[AnomalyResult] = None,
        entity_profile: Optional[EntityProfile] = None,
        event_time: Optional[float] = None,
        mode: str = "F4",
    ) -> FusionResult:
        """Execute multi-signal weighted fusion for an entity.

        Args:
            signals: List of DetectionSignals for the primary entity.
            ml_result: Supervised ML classification result (calibrated probabilities).
            anomaly_result: Isolation Forest unsupervised anomaly result.
            entity_profile: M14 EntityProfile providing baselines & novelty.
            event_time: Current evaluation epoch event time.
            mode: Evaluation hook ('F0': max detector, 'F1': weighted, 'F2': +persistence, 'F3': +entity context, 'F4': full fusion).
        """
        if not signals and not ml_result and not anomaly_result:
            raise ValueError("FusionEngine requires at least one signal, ML result, or anomaly score.")

        # Determine primary entity ID
        primary_entity = "unknown"
        if signals:
            primary_entity = signals[0].source_entity or signals[0].entity_id or "unknown"
        elif ml_result and hasattr(ml_result, "source_entity"):
            primary_entity = ml_result.source_entity
        elif entity_profile:
            primary_entity = entity_profile.entity_id

        state = self._get_or_create_state(primary_entity)

        # Ingest incoming signals into entity correlation buffer
        for sig in signals:
            state.add_signal(sig)

        t_eval = event_time or state.latest_event_time or (
            datetime.now(timezone.utc).timestamp()
        )

        evidence_items: List[FusionEvidenceItem] = []
        conflict_detected = False

        # 1. Behavioral Detector Contribution
        det_score, det_threat, best_sig = state.compute_decayed_detector_score(t_eval)
        w_det = self.config.w_detector if mode != "F0" else 1.0
        det_contrib = det_score * w_det
        if best_sig:
            evidence_items.append(FusionEvidenceItem(
                component_name="detector_signal",
                raw_value=round(det_score, 4),
                weight=w_det,
                weighted_contribution=round(det_contrib, 4),
                description=f"Active detector '{best_sig.detector_id or best_sig.detector_type.value}' signal ({det_threat.value}) with decayed score {det_score:.3f}",
            ))

        # 2. Calibrated ML Classification Contribution
        ml_prob = 0.0
        ml_threat = ThreatClass.UNKNOWN_ANOMALY
        clf = ml_result.classification if isinstance(ml_result, UnifiedMLResult) else ml_result

        if clf is not None and mode in {"F1", "F2", "F3", "F4"}:
            w_ml = self.config.w_ml
            ml_prob = float(clf.confidence)
            ml_threat = clf.threat_class or ThreatClass.UNKNOWN_ANOMALY
            ml_contrib = ml_prob * w_ml
            evidence_items.append(FusionEvidenceItem(
                component_name="calibrated_ml",
                raw_value=round(ml_prob, 4),
                weight=w_ml,
                weighted_contribution=round(ml_contrib, 4),
                description=f"Calibrated ML model '{clf.model_name}' predicted {clf.predicted_class_name} with probability {ml_prob:.3f}",
            ))

            # Conflict Detection between Detector and ML
            if det_score >= 0.60 and clf.predicted_class_name == "BENIGN" and ml_prob >= 0.70:
                conflict_detected = True
                evidence_items.append(FusionEvidenceItem(
                    component_name="conflict_disagreement",
                    raw_value="DETECTOR_THREAT_VS_ML_BENIGN",
                    weight=0.0,
                    weighted_contribution=0.0,
                    description=f"Conflict detected: Detector flagged {det_threat.value} ({det_score:.2f}) but ML predicted BENIGN ({ml_prob:.2f})",
                ))
            elif det_score >= 0.60 and ml_prob >= 0.60 and det_threat != ml_threat and ml_threat != ThreatClass.UNKNOWN_ANOMALY:
                # Check if threats are compatible
                compatible_threats = SUPPORTING_THREAT_RELATIONSHIPS.get(det_threat, set())
                if ml_threat not in compatible_threats:
                    conflict_detected = True
                    evidence_items.append(FusionEvidenceItem(
                        component_name="conflict_disagreement",
                        raw_value=f"{det_threat.value}_VS_{ml_threat.value}",
                        weight=0.0,
                        weighted_contribution=0.0,
                        description=f"Threat class mismatch: Detector flagged {det_threat.value} but ML predicted {ml_threat.value}",
                    ))
        else:
            ml_contrib = 0.0

        # 3. Isolation Forest Anomaly Contribution
        anom_val = 0.0
        anom = anomaly_result or (ml_result.anomaly if isinstance(ml_result, UnifiedMLResult) else None)
        if anom is not None and mode in {"F1", "F2", "F3", "F4"}:
            w_anom = self.config.w_anomaly
            anom_val = float(anom.normalized_confidence) if hasattr(anom, "normalized_confidence") else (
                0.80 if anom.is_anomaly else 0.10
            )
            anom_contrib = anom_val * w_anom
            evidence_items.append(FusionEvidenceItem(
                component_name="anomaly_score",
                raw_value=round(anom.anomaly_score, 4),
                weight=w_anom,
                weighted_contribution=round(anom_contrib, 4),
                description=f"Unsupervised anomaly detector ({anom.model_name}) anomaly score {anom.anomaly_score:.3f} (normalized risk: {anom_val:.2f})",
            ))
        else:
            anom_contrib = 0.0

        # 4. Entity Baseline & Novelty Context (M14)
        ctx_score = 0.0
        entity_dev_val = 0.0
        if entity_profile is not None and mode in {"F3", "F4"}:
            w_ctx = self.config.w_context
            z_score = abs(entity_profile.pps_baseline.compute_z_score(entity_profile.pps_history[-1] if entity_profile.pps_history else 0.0))
            entity_dev_val = z_score
            z_norm = min(1.0, z_score / 5.0) if z_score > 2.0 else 0.0
            
            novelty_count = (
                len([d for d, m in entity_profile.destination_meta.items() if m.get("count", 0) <= 1])
                + len([p for p, m in entity_profile.port_meta.items() if m.get("count", 0) <= 1])
            )
            novelty_norm = min(1.0, novelty_count / 10.0)
            ctx_score = min(1.0, 0.6 * z_norm + 0.4 * novelty_norm)
            ctx_contrib = ctx_score * w_ctx

            if ctx_score > 0.0:
                evidence_items.append(FusionEvidenceItem(
                    component_name="entity_context",
                    raw_value=round(z_score, 3),
                    weight=w_ctx,
                    weighted_contribution=round(ctx_contrib, 4),
                    description=f"Entity baseline deviation Z-score {z_score:.2f} with {novelty_count} newly observed destinations/ports",
                ))
        else:
            ctx_contrib = 0.0

        # 5. Threat-Specific Temporal Persistence Contribution (P1-5)
        pers_duration = state.get_persistence_duration(threat_class=det_threat, current_event_time=t_eval)
        pers_score = 0.0
        if mode in {"F2", "F4"} and pers_duration > 0.0:
            w_pers = self.config.w_persistence
            pers_score = min(1.0, pers_duration / 300.0)
            pers_contrib = pers_score * w_pers
            evidence_items.append(FusionEvidenceItem(
                component_name="temporal_persistence",
                raw_value=round(pers_duration, 2),
                weight=w_pers,
                weighted_contribution=round(pers_contrib, 4),
                description=f"Threat signals ({det_threat.value}) persisted over {pers_duration:.1f} seconds of event time",
            ))
        else:
            pers_contrib = 0.0

        # 6. Evidence Source Diversity Contribution (P1-7)
        signal_families = state.get_evidence_source_families()
        if clf is not None and clf.is_threat:
            signal_families.add(SignalFamily.CALIBRATED_ML)
        if anom is not None and anom.is_anomaly:
            signal_families.add(SignalFamily.UNSUPERVISED_ANOMALY)
        if entity_profile is not None and entity_dev_val > 2.5:
            signal_families.add(SignalFamily.ENTITY_BASELINE)

        div_count = max(1, len(signal_families))
        div_score = 0.0
        if mode == "F4" and div_count > 1:
            w_div = self.config.w_diversity
            div_score = min(1.0, (div_count - 1) / 3.0)
            div_contrib = div_score * w_div
            evidence_items.append(FusionEvidenceItem(
                component_name="signal_diversity",
                raw_value=div_count,
                weight=w_div,
                weighted_contribution=round(div_contrib, 4),
                description=f"Multi-source confirmation across {div_count} distinct evidence source families: {', '.join(f.value for f in signal_families)}",
            ))
        else:
            div_contrib = 0.0

        # -------------------------------------------------------------------
        # Composite Fused Risk & Final Threat Hypothesis Calculation
        # -------------------------------------------------------------------
        if mode == "F0":
            fused_risk = det_score
        else:
            fused_risk = min(1.0, max(0.0, det_contrib + ml_contrib + anom_contrib + ctx_contrib + pers_contrib + div_contrib))

        # Final threat hypothesis determination
        if det_threat != ThreatClass.UNKNOWN_ANOMALY and (det_score >= ml_prob or det_score >= 0.80 or (clf is not None and not clf.is_threat)):
            final_threat = det_threat
        elif ml_threat != ThreatClass.UNKNOWN_ANOMALY and (clf is not None and clf.is_threat):
            final_threat = ml_threat
        elif det_threat != ThreatClass.UNKNOWN_ANOMALY:
            final_threat = det_threat
        elif anom is not None and anom.is_anomaly:
            final_threat = ThreatClass.UNKNOWN_ANOMALY
        else:
            final_threat = ThreatClass.UNKNOWN_ANOMALY

        # Explicit Confidence metric
        base_confidence = max(det_score, ml_prob)
        conflict_penalty = 0.70 if conflict_detected else 1.00
        diversity_boost = 1.0 + min(0.20, (div_count - 1) * 0.05)
        confidence = min(1.0, max(0.0, base_confidence * conflict_penalty * diversity_boost))

        # Severity Determination
        if fused_risk >= self.config.threshold_critical:
            severity = Severity.CRITICAL
        elif fused_risk >= self.config.threshold_high:
            severity = Severity.HIGH
        elif fused_risk >= self.config.threshold_medium:
            severity = Severity.MEDIUM
        elif fused_risk >= self.config.threshold_low:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        # Active detectors list & signal IDs
        signal_ids = [s.signal_id for s in state.signals]
        contributing_detectors = list({s.detector_id or s.detector_type.value for s in state.signals})

        fusion_res = FusionResult(
            fusion_id=f"FUS-{uuid.uuid4().hex[:8]}",
            entity_id=primary_entity,
            threat_class=final_threat,
            fused_risk=round(fused_risk, 4),
            confidence=round(confidence, 4),
            severity=severity,
            detector_score=round(det_score, 4),
            calibrated_ml_probability=round(ml_prob, 4),
            anomaly_score=round(anom.anomaly_score if anom else 0.0, 4),
            entity_deviation=round(entity_dev_val, 4),
            signal_ids=signal_ids,
            contributing_detectors=contributing_detectors,
            independent_signal_family_count=div_count,
            persistence_duration_sec=round(pers_duration, 2),
            conflict_detected=conflict_detected,
            evidence=evidence_items,
            event_time=t_eval,
            window_start=state.first_seen_event_time,
            window_end=state.latest_event_time,
            timestamp_iso=datetime.fromtimestamp(t_eval, tz=timezone.utc).isoformat(),
        )

        return fusion_res

    def process_signal(
        self,
        signal: DetectionSignal,
        entity_memory: Optional[EntityMemory] = None,
        graph: Optional[EntityBehaviourGraph] = None,
    ) -> Tuple[ActiveCorrelationGroup, float, Severity]:
        """Backward-compatible entrypoint: Ingest a DetectionSignal, update active group & graph."""
        entity_id = signal.source_entity or signal.entity_id or "unknown"

        # Maintain backward-compatible ActiveCorrelationGroup
        if entity_id not in self._active_groups or self._active_groups[entity_id].is_expired(signal.event_time):
            self._active_groups[entity_id] = ActiveCorrelationGroup(
                primary_entity=entity_id,
                window_duration_sec=int(self.config.correlation_window_sec),
            )

        group = self._active_groups[entity_id]
        group.add_signal(signal)

        # Retrieve entity profile and compute baseline deviation if available
        deviation = 0.0
        if entity_memory:
            profile = entity_memory.get_profile(entity_id)
            if profile:
                pps_val = signal.indicators.get("packets_per_sec", 0.0)
                deviation = abs(profile.compute_pps_z_score(pps_val))

        # Compute group composite risk
        risk, severity = group.compute_composite_risk(baseline_deviation=deviation)

        # Update entity graph if present
        if graph:
            graph.add_node(entity_id, NodeType.HOST_IP, {"last_risk": risk})
            if signal.target_entity:
                graph.add_node(signal.target_entity, NodeType.EXTERNAL_IP)
                graph.add_edge(
                    entity_id,
                    signal.target_entity,
                    EdgeType.COMMUNICATES_WITH,
                    {"threat": signal.threat_class.value, "confidence": signal.confidence},
                )

        return group, risk, severity
