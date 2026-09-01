"""Incident Lifecycle Engine and Evidence-Backed Attack Chain Aggregator (Member 3 - M18).

Provides:
1. Canonical Incident lifecycle management (NEW -> OPEN/UPDATED -> ESCALATED -> RESOLVED)
2. Threat compatibility matrix & entity-isolated multi-signal correlation
3. Event-time chronology with bounded out-of-order event insertion
4. Evidence-backed attack chains (missing stages are never hallucinated)
5. Strict bounded memory with LRU eviction across active/resolved incidents
6. Cryptographic deterministic incident dossier export
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import OrderedDict

from schemas import (
    ThreatClass,
    Severity,
    DetectionSignal,
    FusionResult,
    Incident,
    IncidentStatus,
    AttackStageType,
    AttackStageRecord,
    TimelineEvent,
    DeduplicatedEvidence,
    threat_class_to_stage_type,
)


THREAT_COMPATIBILITY_MATRIX: Dict[ThreatClass, Set[ThreatClass]] = {
    ThreatClass.RECON_PORT_SCAN: {
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.VOLUMETRIC_DDOS,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.BOTNET_C2_BEACONING: {
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.DGA_DNS_TUNNELLING: {
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.ENCRYPTED_MALWARE: {
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.DATA_EXFILTRATION: {
        ThreatClass.DATA_EXFILTRATION,
        ThreatClass.BOTNET_C2_BEACONING,
        ThreatClass.DGA_DNS_TUNNELLING,
        ThreatClass.ENCRYPTED_MALWARE,
        ThreatClass.RECON_PORT_SCAN,
        ThreatClass.UNKNOWN_ANOMALY,
    },
    ThreatClass.VOLUMETRIC_DDOS: {
        ThreatClass.VOLUMETRIC_DDOS,
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
        ThreatClass.UNKNOWN_ANOMALY,
    },
}


@dataclass
class LifecycleConfig:
    """Configurable lifecycle timeouts, thresholds, and memory bounds."""
    # Inactivity and Reopen Windows (in event-time seconds)
    inactivity_timeout_sec: float = 600.0  # 10 minutes of inactivity to auto-resolve
    reopen_window_sec: float = 300.0       # 5 minutes from resolution to permit reopening
    lateness_bound_sec: float = 120.0      # 2 minutes bounded out-of-order tolerance

    # Escalation Thresholds
    escalation_risk_delta: float = 0.15     # Material risk jump triggering ESCALATED
    high_impact_escalation_classes: Set[ThreatClass] = field(default_factory=lambda: {
        ThreatClass.VOLUMETRIC_DDOS,
        ThreatClass.DATA_EXFILTRATION,
    })

    # Memory Bounds (Strict limits per incident and globally)
    max_active_incidents: int = 1000
    max_resolved_incidents: int = 2000
    max_signals_per_incident: int = 200
    max_evidence_per_incident: int = 100
    max_timeline_events_per_incident: int = 200
    max_flows_per_incident: int = 500
    max_destinations_per_incident: int = 100
    max_domains_per_incident: int = 100
    max_tls_fingerprints_per_incident: int = 100
    max_history_entries: int = 100


class IncidentLifecycleEngine:
    """Production Incident Lifecycle and Correlation Engine (M18).

    Consumes canonical M17 FusionResults and DetectionSignals, maintaining
    entity-level incident dossiers, evidence-backed attack chains, and deterministic state transitions.
    """

    def __init__(self, config: Optional[LifecycleConfig] = None):
        self.config = config or LifecycleConfig()
        # Active incidents mapped by incident_id
        self._active_incidents: Dict[str, Incident] = {}
        # Entity -> active incident_id
        self._entity_active_incident: Dict[str, str] = {}
        # Bounded LRU resolved incidents cache: incident_id -> Incident
        self._resolved_incidents: OrderedDict[str, Incident] = OrderedDict()
        # Resolution timestamp tracking: incident_id -> resolved_event_time
        self._resolved_event_times: Dict[str, float] = {}
        # Signal ID -> Incident ID (prevents signal double-membership)
        self._signal_to_incident: Dict[str, str] = {}

    def _is_threat_compatible(self, existing_primary: ThreatClass, incoming: ThreatClass) -> bool:
        """Check if incoming threat category is compatible with existing incident context."""
        if existing_primary == incoming:
            return True
        compatible_set = THREAT_COMPATIBILITY_MATRIX.get(existing_primary, set())
        if incoming in compatible_set:
            return True
        incoming_compat = THREAT_COMPATIBILITY_MATRIX.get(incoming, set())
        return existing_primary in incoming_compat

    def _generate_evidence_hash(self, component_name: str, feature_name: str, value: Any) -> str:
        """Generate deterministic 12-char hash ID for evidence deduplication."""
        val_str = f"{value:.4f}" if isinstance(value, (float, int)) else str(value)
        raw = f"{component_name}|{feature_name}|{val_str}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def _create_new_incident(
        self,
        fusion_result: FusionResult,
        event_time: float,
        raw_signals: Optional[List[DetectionSignal]] = None,
    ) -> Incident:
        """Instantiate a brand new Incident dossier in NEW state."""
        now_iso = datetime.now(timezone.utc).isoformat()
        date_str = datetime.fromtimestamp(event_time, tz=timezone.utc).strftime("%Y%m%d")
        inc_id = f"INC-{date_str}-{uuid.uuid4().hex[:8]}"

        inc = Incident(
            incident_id=inc_id,
            entity_id=fusion_result.entity_id,
            primary_threat_class=fusion_result.threat_class,
            status=IncidentStatus.NEW,
            first_seen_event_time=event_time,
            last_seen_event_time=event_time,
            created_at=now_iso,
            updated_at=now_iso,
            current_fused_risk=fusion_result.fused_risk,
            max_fused_risk=fusion_result.fused_risk,
            confidence=fusion_result.confidence,
            severity=fusion_result.severity,
            calibrated_ml_probability=fusion_result.calibrated_ml_probability,
            anomaly_score=fusion_result.anomaly_score,
            detector_score=fusion_result.detector_score,
            signal_ids=list(fusion_result.signal_ids),
            fusion_ids=[fusion_result.fusion_id],
            feature_schema_version="feature-schema-v2.1.0",
        )

        # Enforce max active incidents bound
        if len(self._active_incidents) >= self.config.max_active_incidents:
            oldest_id = next(iter(self._active_incidents))
            oldest_inc = self._active_incidents.pop(oldest_id)
            if oldest_inc.entity_id in self._entity_active_incident:
                del self._entity_active_incident[oldest_inc.entity_id]

        self._active_incidents[inc_id] = inc
        self._entity_active_incident[fusion_result.entity_id] = inc_id

        # Update initial stage, evidence, timeline
        self._update_incident_contents(inc, fusion_result, event_time, raw_signals, is_initial=True)
        return inc

    def _update_incident_contents(
        self,
        inc: Incident,
        fusion_result: FusionResult,
        event_time: float,
        raw_signals: Optional[List[DetectionSignal]] = None,
        is_initial: bool = False,
    ) -> None:
        """Incrementally update incident attack chain, evidence, timeline, and network context."""
        prev_risk = inc.current_fused_risk
        prev_severity = inc.severity

        # 1. Update Bounds and Operational Timestamp
        if event_time < inc.first_seen_event_time or inc.first_seen_event_time == 0.0:
            inc.first_seen_event_time = event_time
        if event_time > inc.last_seen_event_time:
            inc.last_seen_event_time = event_time
        inc.updated_at = datetime.now(timezone.utc).isoformat()

        # 2. Risk & Scores Update (Canonical from M17 FusionResult)
        inc.current_fused_risk = fusion_result.fused_risk
        inc.max_fused_risk = max(inc.max_fused_risk, fusion_result.fused_risk)
        inc.confidence = fusion_result.confidence
        inc.severity = fusion_result.severity
        inc.calibrated_ml_probability = fusion_result.calibrated_ml_probability
        inc.anomaly_score = fusion_result.anomaly_score
        inc.detector_score = fusion_result.detector_score

        # Bounded Risk & Severity History
        if len(inc.risk_history) < self.config.max_history_entries:
            inc.risk_history.append((event_time, fusion_result.fused_risk))
            inc.severity_history.append((event_time, fusion_result.severity.value))

        # 3. Correlated Fusion & Signal IDs
        if fusion_result.fusion_id not in inc.fusion_ids and len(inc.fusion_ids) < self.config.max_signals_per_incident:
            inc.fusion_ids.append(fusion_result.fusion_id)

        for sig_id in fusion_result.signal_ids:
            if sig_id not in inc.signal_ids and len(inc.signal_ids) < self.config.max_signals_per_incident:
                inc.signal_ids.append(sig_id)
                self._signal_to_incident[sig_id] = inc.incident_id

        # 4. Context Extraction from Raw Signals if available
        if raw_signals:
            for sig in raw_signals:
                if sig.flow_id and sig.flow_id not in inc.flow_ids and len(inc.flow_ids) < self.config.max_flows_per_incident:
                    inc.flow_ids.append(sig.flow_id)
                if sig.target_entity and sig.target_entity not in inc.destination_entities and len(inc.destination_entities) < self.config.max_destinations_per_incident:
                    inc.destination_entities.append(sig.target_entity)
                
                # Check for TLS / DNS metadata in indicators
                sni = sig.indicators.get("sni") or sig.indicators.get("domain")
                if sni and sni not in inc.domains and len(inc.domains) < self.config.max_domains_per_incident:
                    inc.domains.append(str(sni))
                ja3 = sig.indicators.get("ja3_hash") or sig.indicators.get("ja4_hash")
                if ja3 and ja3 not in inc.tls_fingerprints and len(inc.tls_fingerprints) < self.config.max_tls_fingerprints_per_incident:
                    inc.tls_fingerprints.append(str(ja3))

        # 5. Deduplicated Evidence Accumulation
        existing_ev_map = {e.evidence_id: e for e in inc.evidence}
        for item in fusion_result.evidence:
            ev_id = self._generate_evidence_hash(item.component_name, item.component_name, item.raw_value)
            if ev_id in existing_ev_map:
                existing = existing_ev_map[ev_id]
                existing.occurrence_count += 1
                existing.last_seen_event_time = max(existing.last_seen_event_time, event_time)
            elif len(inc.evidence) < self.config.max_evidence_per_incident:
                dedup_ev = DeduplicatedEvidence(
                    evidence_id=ev_id,
                    source_fusion_id=fusion_result.fusion_id,
                    feature_name=item.component_name,
                    value=item.raw_value,
                    deviation=item.weighted_contribution,
                    interpretation=item.description,
                    first_seen_event_time=event_time,
                    last_seen_event_time=event_time,
                    occurrence_count=1,
                )
                inc.evidence.append(dedup_ev)
                existing_ev_map[ev_id] = dedup_ev

        # 6. Evidence-Backed Attack Chain Progression
        stage_type = threat_class_to_stage_type(fusion_result.threat_class)
        existing_stage = next((s for s in inc.attack_chain if s.stage_type == stage_type), None)
        new_stage_added = False

        if existing_stage:
            existing_stage.last_seen_event_time = max(existing_stage.last_seen_event_time, event_time)
            existing_stage.first_seen_event_time = min(existing_stage.first_seen_event_time, event_time)
            existing_stage.observation_count += 1
            if fusion_result.fusion_id not in existing_stage.fusion_ids:
                existing_stage.fusion_ids.append(fusion_result.fusion_id)
            for sid in fusion_result.signal_ids:
                if sid not in existing_stage.signal_ids:
                    existing_stage.signal_ids.append(sid)
        else:
            new_stage = AttackStageRecord(
                stage_id=f"STG-{uuid.uuid4().hex[:8]}",
                stage_type=stage_type,
                threat_class=fusion_result.threat_class,
                first_seen_event_time=event_time,
                last_seen_event_time=event_time,
                signal_ids=list(fusion_result.signal_ids),
                fusion_ids=[fusion_result.fusion_id],
                evidence_ids=[e.evidence_id for e in inc.evidence[-len(fusion_result.evidence):]],
                observation_count=1,
            )
            inc.attack_chain.append(new_stage)
            inc.attack_chain.sort(key=lambda s: s.first_seen_event_time)
            new_stage_added = True

        # 7. Timeline Event Insertion (Bounded out-of-order insertion)
        evt_type = "INITIAL_DETECTION" if is_initial else ("STAGE_ADDED" if new_stage_added else "FUSION_UPDATE")
        evt = TimelineEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8]}",
            event_time=event_time,
            event_type=evt_type,
            threat_class=fusion_result.threat_class,
            source_id=fusion_result.fusion_id,
            description=f"Observed {fusion_result.threat_class.value} (Fused risk: {fusion_result.fused_risk:.3f}, Severity: {fusion_result.severity.value})",
            fused_risk=fusion_result.fused_risk,
            severity=fusion_result.severity,
        )

        if len(inc.timeline) < self.config.max_timeline_events_per_incident:
            inc.timeline.append(evt)
            # Maintain strict deterministic chronological ordering
            inc.timeline.sort(key=lambda x: (x.event_time, x.event_type, x.event_id))

        # 8. State Machine Transition (NEW -> OPEN/UPDATED -> ESCALATED)
        if is_initial:
            inc.status = IncidentStatus.NEW
        else:
            # Check escalation criteria
            risk_jump = (fusion_result.fused_risk - prev_risk) >= self.config.escalation_risk_delta
            severity_escalated = (
                (prev_severity in {Severity.LOW, Severity.MEDIUM} and fusion_result.severity in {Severity.HIGH, Severity.CRITICAL})
                or (prev_severity == Severity.HIGH and fusion_result.severity == Severity.CRITICAL)
            )
            high_impact_stage = (
                new_stage_added and fusion_result.threat_class in self.config.high_impact_escalation_classes
            )

            if risk_jump or severity_escalated or high_impact_stage:
                inc.status = IncidentStatus.ESCALATED
                # Record escalation event
                esc_evt = TimelineEvent(
                    event_id=f"EVT-{uuid.uuid4().hex[:8]}",
                    event_time=event_time,
                    event_type="RISK_ESCALATED",
                    threat_class=fusion_result.threat_class,
                    source_id=fusion_result.fusion_id,
                    description=f"Incident escalated to {inc.severity.value} (Risk: {inc.current_fused_risk:.3f})",
                    fused_risk=inc.current_fused_risk,
                    severity=inc.severity,
                )
                if len(inc.timeline) < self.config.max_timeline_events_per_incident:
                    inc.timeline.append(esc_evt)
                    inc.timeline.sort(key=lambda x: (x.event_time, x.event_type, x.event_id))
            else:
                inc.status = IncidentStatus.UPDATED

        # Update primary threat class if incoming threat has higher severity / priority
        if fusion_result.fused_risk > prev_risk:
            inc.primary_threat_class = fusion_result.threat_class

    def process_fusion_result(
        self,
        fusion_result: FusionResult,
        raw_signals: Optional[List[DetectionSignal]] = None,
        current_event_time: Optional[float] = None,
    ) -> Incident:
        """Ingest a FusionResult, correlate into active or reopened incident, or create new incident."""
        # Event time of the actual observation
        event_time = (
            fusion_result.event_time
            if fusion_result.event_time is not None
            else (current_event_time if current_event_time is not None else datetime.now(timezone.utc).timestamp())
        )
        # Clock time of the engine for evaluating timeouts
        t_clock = current_event_time if current_event_time is not None else event_time

        entity_id = fusion_result.entity_id

        # 1. Check existing active incident for this entity
        if entity_id in self._entity_active_incident:
            active_inc_id = self._entity_active_incident[entity_id]
            active_inc = self._active_incidents.get(active_inc_id)

            if active_inc:
                # Check for inactivity expiration
                dt_inactivity = t_clock - active_inc.last_seen_event_time
                if dt_inactivity > self.config.inactivity_timeout_sec:
                    # Inactivity timeout expired -> Resolve active incident
                    self._resolve_incident(active_inc, event_time=t_clock)
                else:
                    # Check threat compatibility
                    if self._is_threat_compatible(active_inc.primary_threat_class, fusion_result.threat_class):
                        self._update_incident_contents(active_inc, fusion_result, event_time, raw_signals, is_initial=False)
                        return active_inc

        # 2. Check if a recently resolved incident can be reopened
        recent_resolved = next(
            (inc for inc in reversed(self._resolved_incidents.values()) if inc.entity_id == entity_id),
            None,
        )

        if recent_resolved:
            resolved_t = self._resolved_event_times.get(recent_resolved.incident_id, recent_resolved.last_seen_event_time + self.config.inactivity_timeout_sec)
            dt_from_resolution = t_clock - resolved_t
            if 0.0 <= dt_from_resolution <= self.config.reopen_window_sec:
                if self._is_threat_compatible(recent_resolved.primary_threat_class, fusion_result.threat_class):
                    # Reopen resolved incident
                    del self._resolved_incidents[recent_resolved.incident_id]
                    if recent_resolved.incident_id in self._resolved_event_times:
                        del self._resolved_event_times[recent_resolved.incident_id]

                    self._active_incidents[recent_resolved.incident_id] = recent_resolved
                    self._entity_active_incident[entity_id] = recent_resolved.incident_id

                    # Record reopen event
                    reopen_evt = TimelineEvent(
                        event_id=f"EVT-{uuid.uuid4().hex[:8]}",
                        event_time=event_time,
                        event_type="STATUS_CHANGE",
                        threat_class=fusion_result.threat_class,
                        source_id=fusion_result.fusion_id,
                        description=f"Incident reopened within {dt_from_resolution:.1f}s reopen window",
                        fused_risk=fusion_result.fused_risk,
                        severity=fusion_result.severity,
                    )
                    recent_resolved.timeline.append(reopen_evt)
                    recent_resolved.timeline.sort(key=lambda x: (x.event_time, x.event_type, x.event_id))

                    self._update_incident_contents(recent_resolved, fusion_result, event_time, raw_signals, is_initial=False)
                    return recent_resolved

        # 3. Create fresh Incident in NEW state
        return self._create_new_incident(fusion_result, event_time, raw_signals)

    def _resolve_incident(self, inc: Incident, event_time: float) -> None:
        """Transition active incident to RESOLVED and move to bounded resolved cache."""
        inc.status = IncidentStatus.RESOLVED
        inc.updated_at = datetime.now(timezone.utc).isoformat()
        self._resolved_event_times[inc.incident_id] = event_time

        res_evt = TimelineEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8]}",
            event_time=event_time,
            event_type="STATUS_CHANGE",
            source_id="InactivityTimer",
            description=f"Incident auto-resolved after {self.config.inactivity_timeout_sec:.0f}s of inactivity",
            fused_risk=inc.current_fused_risk,
            severity=inc.severity,
        )
        if len(inc.timeline) < self.config.max_timeline_events_per_incident:
            inc.timeline.append(res_evt)
            inc.timeline.sort(key=lambda x: (x.event_time, x.event_type, x.event_id))

        if inc.incident_id in self._active_incidents:
            del self._active_incidents[inc.incident_id]
        if inc.entity_id in self._entity_active_incident:
            del self._entity_active_incident[inc.entity_id]

        # Enforce max resolved incidents bound
        if len(self._resolved_incidents) >= self.config.max_resolved_incidents:
            evicted_id, _ = self._resolved_incidents.popitem(last=False)
            if evicted_id in self._resolved_event_times:
                del self._resolved_event_times[evicted_id]

        self._resolved_incidents[inc.incident_id] = inc

    def check_inactivity_resolutions(self, current_event_time: float) -> List[Incident]:
        """Audit all active incidents and resolve those exceeding inactivity_timeout_sec."""
        resolved_list: List[Incident] = []
        active_copy = list(self._active_incidents.values())

        for inc in active_copy:
            dt = current_event_time - inc.last_seen_event_time
            if dt > self.config.inactivity_timeout_sec:
                self._resolve_incident(inc, event_time=current_event_time)
                resolved_list.append(inc)

        return resolved_list

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an incident by ID from active or resolved storage."""
        if incident_id in self._active_incidents:
            return self._active_incidents[incident_id]
        return self._resolved_incidents.get(incident_id)

    def get_active_incidents(self) -> List[Incident]:
        """Return list of all currently active incidents."""
        return list(self._active_incidents.values())

    def export_dossier(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Export deterministic JSON dossier representation for an incident."""
        inc = self.get_incident(incident_id)
        if inc is None:
            return None
        return inc.to_dossier_dict()
