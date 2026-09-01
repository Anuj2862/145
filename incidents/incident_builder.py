"""Incident Builder component (Member 3).

Assembles multi-stage correlated detection signals, entity historical baselines,
and evidence chains into structured Incident dossiers.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import uuid

from schemas import Incident, Alert, DetectionSignal, ThreatStage, Severity, FusionResult
from fusion.engine import ActiveCorrelationGroup
from evidence.engine import EvidenceEngine
from entity.memory import EntityMemory
from entity.graph import EntityBehaviourGraph, NodeType, EdgeType
from incidents.alert_builder import build_alert_from_signal


class IncidentBuilder:
    """Constructs and manages Incident dossiers and linked Alert streams."""

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}

    def build_incident_from_group(
        self,
        group: ActiveCorrelationGroup,
        entity_memory: Optional[EntityMemory] = None,
        graph: Optional[EntityBehaviourGraph] = None,
        fusion_result: Optional[FusionResult] = None,
    ) -> Incident:
        """Construct a validated Incident model from an ActiveCorrelationGroup or FusionResult."""
        if not group.signals:
            raise ValueError("Cannot build incident from empty correlation group")

        primary_entity = group.primary_entity
        sorted_signals = sorted(group.signals, key=lambda s: s.timestamp_iso)

        # Baseline deviation
        deviation = 0.0
        if entity_memory:
            profile = entity_memory.get_or_create_profile(primary_entity)
            pps_val = sorted_signals[-1].indicators.get("packets_per_sec", 0.0)
            deviation = profile.compute_pps_z_score(pps_val)

        # Canonical Fused Risk & Severity (P1-8: Single source of truth)
        if fusion_result is not None:
            risk_score = fusion_result.fused_risk
            severity = fusion_result.severity
        else:
            risk_score, severity = group.compute_composite_risk(baseline_deviation=deviation)

        # Build chronological threat stages
        threat_stages: List[ThreatStage] = [
            EvidenceEngine.map_to_threat_stage(sig) for sig in sorted_signals
        ]

        # Consolidate evidence items
        evidence_set: List[str] = []
        for sig in sorted_signals:
            items = EvidenceEngine.generate_evidence_items(sig, baseline_deviation=deviation)
            for item in items:
                if item not in evidence_set:
                    evidence_set.append(item)

        # Recommended action based on most severe threat
        most_severe_sig = max(sorted_signals, key=lambda s: s.confidence)
        recommended_action = EvidenceEngine.get_recommended_action(most_severe_sig.threat_class)

        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{group.group_id.replace('GRP-', '')}"

        incident = Incident(
            incident_id=incident_id,
            primary_entity=primary_entity,
            risk_score=risk_score,
            overall_severity=severity,
            status="OPEN",
            first_seen_iso=sorted_signals[0].timestamp_iso,
            last_seen_iso=sorted_signals[-1].timestamp_iso,
            threat_stages=threat_stages,
            evidence_items=evidence_set,
            recommended_action=recommended_action,
        )

        self._incidents[incident_id] = incident

        # Link Incident in EntityBehaviourGraph
        if graph:
            graph.add_node(incident_id, NodeType.INCIDENT, properties={
                "risk_score": risk_score,
                "severity": severity.value,
                "primary_entity": primary_entity,
                "stages_count": len(threat_stages),
            })
            graph.add_edge(primary_entity, incident_id, EdgeType.PART_OF_INCIDENT)
            for sig in sorted_signals:
                graph.add_edge(sig.signal_id, incident_id, EdgeType.PART_OF_INCIDENT)

        return incident

    def build_incident_alert(self, incident: Incident, signal: DetectionSignal) -> Alert:
        """Create a standardized Alert linked directly to the parent Incident."""
        summary = (
            f"Correlated Incident {incident.incident_id}: {signal.threat_class.value} "
            f"on {incident.primary_entity} (Risk: {incident.risk_score:.2f}, Stages: {len(incident.threat_stages)})"
        )
        return build_alert_from_signal(
            signal=signal,
            incident_id=incident.incident_id,
            custom_summary=summary,
        )

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def get_all_incidents(self) -> Dict[str, Incident]:
        return self._incidents
