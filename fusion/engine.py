"""Multi-Signal Fusion and Risk Aggregation Engine (Member 3).

Correlates multiple weak or independent detection signals belonging to the same
entity across temporal windows into high-confidence composite risk assessments.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Tuple
import uuid

from schemas import DetectionSignal, ThreatClass, Severity, DetectorType
from entity.memory import EntityMemory
from entity.graph import EntityBehaviourGraph, NodeType, EdgeType


class ActiveCorrelationGroup:
    """Tracks a cluster of correlated detection signals for an entity within a temporal window."""

    def __init__(self, primary_entity: str, window_duration_sec: int = 300):
        self.group_id = f"GRP-{uuid.uuid4().hex[:8]}"
        self.primary_entity = primary_entity
        self.window_duration_sec = window_duration_sec
        self.signals: List[DetectionSignal] = []
        self.created_at = datetime.now(timezone.utc)
        self.last_updated = self.created_at

    def add_signal(self, signal: DetectionSignal) -> None:
        self.signals.append(signal)
        self.last_updated = datetime.now(timezone.utc)

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        now = current_time or datetime.now(timezone.utc)
        return (now - self.last_updated).total_seconds() > self.window_duration_sec

    def compute_composite_risk(self, baseline_deviation: float = 0.0) -> Tuple[float, Severity]:
        """Compute consolidated risk score [0.0, 1.0] and overall severity."""
        if not self.signals:
            return 0.0, Severity.INFO

        # 1. Highest individual signal confidence
        max_conf = max(s.confidence for s in self.signals)
        
        # 2. Distinct threat class diversity boost (up to +0.25)
        threat_classes = {s.threat_class for s in self.signals}
        diversity_bonus = min(0.25, (len(threat_classes) - 1) * 0.10)

        # 3. Multi-detector agreement boost (Heuristic + ML agreement)
        detector_types = {s.detector_type for s in self.signals}
        agreement_bonus = 0.10 if len(detector_types) > 1 else 0.0

        # 4. Host baseline deviation boost
        deviation_bonus = min(0.15, max(0.0, (baseline_deviation - 2.0) * 0.03)) if baseline_deviation > 2.0 else 0.0

        # Composite fused risk score
        fused_score = min(0.99, max_conf + diversity_bonus + agreement_bonus + deviation_bonus)

        # Determine severity
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
    """Coordinates signal correlation, risk aggregation, and graph edge formation."""

    def __init__(self, correlation_window_sec: int = 300):
        self.correlation_window_sec = correlation_window_sec
        self._active_groups: Dict[str, ActiveCorrelationGroup] = {}

    def process_signal(
        self,
        signal: DetectionSignal,
        entity_memory: Optional[EntityMemory] = None,
        graph: Optional[EntityBehaviourGraph] = None,
    ) -> Tuple[ActiveCorrelationGroup, float, Severity]:
        """Ingest a DetectionSignal, correlate with active entity group, and return composite risk."""
        entity_id = signal.source_entity

        # Retrieve or create active correlation group for this entity
        if entity_id not in self._active_groups or self._active_groups[entity_id].is_expired():
            self._active_groups[entity_id] = ActiveCorrelationGroup(
                primary_entity=entity_id,
                window_duration_sec=self.correlation_window_sec,
            )

        group = self._active_groups[entity_id]
        group.add_signal(signal)

        # Query baseline deviation if entity_memory is provided
        deviation = 0.0
        if entity_memory:
            profile = entity_memory.get_or_create_profile(entity_id)
            pps_val = signal.indicators.get("packets_per_sec", 0.0)
            deviation = profile.compute_pps_z_score(pps_val)

        # Add node and edges to EntityBehaviourGraph if graph is provided
        if graph:
            graph.add_node(entity_id, NodeType.HOST_IP)
            graph.add_node(signal.signal_id, NodeType.SIGNAL, properties={
                "threat_class": signal.threat_class.value,
                "confidence": signal.confidence,
                "severity": signal.severity.value,
            })
            graph.add_edge(entity_id, signal.signal_id, EdgeType.GENERATED_SIGNAL)

            if signal.target_entity:
                tgt_type = NodeType.DOMAIN if ("." in signal.target_entity and not signal.target_entity.replace(".", "").isdigit()) else NodeType.EXTERNAL_IP
                graph.add_node(signal.target_entity, tgt_type)
                graph.add_edge(entity_id, signal.target_entity, EdgeType.COMMUNICATES_WITH)
                graph.add_edge(signal.signal_id, signal.target_entity, EdgeType.TARGETED_BY)

        composite_risk, severity = group.compute_composite_risk(baseline_deviation=deviation)
        return group, composite_risk, severity

    def get_active_groups(self) -> Dict[str, ActiveCorrelationGroup]:
        """Return non-expired active correlation groups."""
        now = datetime.now(timezone.utc)
        return {k: v for k, v in self._active_groups.items() if not v.is_expired(now)}
