"""Canonical Incident, Attack Chain and Timeline Schemas for PS 26145 (Member 3 - M18).

Provides standardized Pydantic contract models for:
1. Incident lifecycle state machine (NEW, OPEN, UPDATED, ESCALATED, RESOLVED)
2. Evidence-backed attack chains (strictly supported by observations, never hallucinated)
3. Deterministic event-time timeline ordering
4. Deduplicated evidence containers
5. Canonical incident dossiers with cryptographic hashing
6. Full backward-compatibility with legacy Incident consumers
"""

from __future__ import annotations
from schemas.provenance import FEATURE_SCHEMA_VERSION, DETECTOR_VERSIONS, MODEL_VERSIONS

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict, model_validator

from schemas import ThreatClass, Severity, EvidenceItem


class IncidentStatus(str, Enum):
    """Deterministic lifecycle states for an incident."""
    NEW = "NEW"
    OPEN = "OPEN"
    UPDATED = "UPDATED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"


class AttackStageType(str, Enum):
    """Categorized attack progression stages."""
    RECONNAISSANCE = "RECONNAISSANCE"
    C2_ESTABLISHMENT = "C2_ESTABLISHMENT"
    DNS_ANOMALY = "DNS_ANOMALY"
    ENCRYPTED_ACTIVITY = "ENCRYPTED_ACTIVITY"
    VOLUMETRIC_DDOS = "VOLUMETRIC_DDOS"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


def threat_class_to_stage_type(threat_class: ThreatClass) -> AttackStageType:
    """Map canonical threat category to attack stage."""
    mapping = {
        ThreatClass.RECON_PORT_SCAN: AttackStageType.RECONNAISSANCE,
        ThreatClass.BOTNET_C2_BEACONING: AttackStageType.C2_ESTABLISHMENT,
        ThreatClass.DGA_DNS_TUNNELLING: AttackStageType.DNS_ANOMALY,
        ThreatClass.ENCRYPTED_MALWARE: AttackStageType.ENCRYPTED_ACTIVITY,
        ThreatClass.VOLUMETRIC_DDOS: AttackStageType.VOLUMETRIC_DDOS,
        ThreatClass.DATA_EXFILTRATION: AttackStageType.DATA_EXFILTRATION,
        ThreatClass.UNKNOWN_ANOMALY: AttackStageType.UNKNOWN_ANOMALY,
    }
    return mapping.get(threat_class, AttackStageType.UNKNOWN_ANOMALY)


class AttackStageRecord(BaseModel):
    """Evidence-backed individual stage within an attack campaign."""
    model_config = ConfigDict(extra="ignore")

    stage_id: str = Field(..., description="Unique stage identifier (e.g. STG-xxxxxxxx)")
    stage_type: AttackStageType = Field(..., description="Stage type")
    threat_class: ThreatClass = Field(..., description="Observed threat class")
    first_seen_event_time: float = Field(..., description="Earliest event timestamp (epoch sec)")
    last_seen_event_time: float = Field(..., description="Latest event timestamp (epoch sec)")
    signal_ids: List[str] = Field(default_factory=list, description="IDs of detection signals supporting stage")
    fusion_ids: List[str] = Field(default_factory=list, description="IDs of fusion results supporting stage")
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of evidence items supporting stage")
    observation_count: int = Field(default=1, ge=1, description="Number of observed detections in stage")


class TimelineEvent(BaseModel):
    """Deterministic chronological lifecycle event."""
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(..., description="Unique event identifier")
    event_time: float = Field(..., description="Event timestamp in epoch seconds")
    event_type: str = Field(..., description="Event category: DETECTION_SIGNAL, FUSION_UPDATE, STAGE_ADDED, RISK_ESCALATED, STATUS_CHANGE")
    threat_class: Optional[ThreatClass] = Field(default=None, description="Associated threat category")
    source_id: str = Field(..., description="Source signal ID or fusion ID")
    description: str = Field(..., description="Human-readable event summary")
    fused_risk: Optional[float] = Field(default=None, description="Fused risk score at event time")
    severity: Optional[Severity] = Field(default=None, description="Operational severity at event time")


class DeduplicatedEvidence(BaseModel):
    """Hash-deduplicated analytical evidence item."""
    model_config = ConfigDict(extra="ignore")

    evidence_id: str = Field(..., description="Unique deterministic hash ID of evidence")
    source_signal_id: Optional[str] = Field(default=None, description="Source signal ID")
    source_fusion_id: Optional[str] = Field(default=None, description="Source fusion result ID")
    feature_name: str = Field(..., description="Telemetry metric or feature name")
    value: Any = Field(..., description="Observed value")
    baseline: Optional[float] = Field(default=None, description="Entity historical baseline")
    deviation: Optional[float] = Field(default=None, description="Statistical deviation or Z-score")
    interpretation: str = Field(..., description="Analytical explanation")
    first_seen_event_time: float = Field(..., description="Earliest event timestamp")
    last_seen_event_time: float = Field(..., description="Latest event timestamp")
    occurrence_count: int = Field(default=1, ge=1, description="Number of times evidence was confirmed")


class ThreatStage(BaseModel):
    """Legacy threat stage container (backward-compatibility)."""
    model_config = ConfigDict(extra="ignore")

    stage: str = Field(..., description="Stage name: RECONNAISSANCE, C2_ESTABLISHMENT, etc.")
    timestamp_iso: str = Field(..., description="Timestamp when stage was observed")
    threat_class: ThreatClass = Field(..., description="Threat class detected")
    confidence: float = Field(..., ge=0.0, le=1.0)


class Incident(BaseModel):
    """Canonical Consolidated Incident Dossier (M18).

    Aggregates multi-stage correlated detection signals, M17 FusionResult assessments,
    evidence-backed attack chains, and chronological timelines for an entity.
    """
    model_config = ConfigDict(extra="ignore")

    incident_id: str = Field(..., description="Unique incident identifier (e.g. INC-20260901-001)")
    entity_id: str = Field(default="unknown", description="Primary affected entity IP or host identity")
    primary_threat_class: ThreatClass = Field(default=ThreatClass.UNKNOWN_ANOMALY, description="Leading threat hypothesis")
    status: IncidentStatus = Field(default=IncidentStatus.NEW, description="Lifecycle status")

    # Event-Time Bounds (Event Time Only for behavior/lifecycle)
    first_seen_event_time: float = Field(default=0.0, description="Earliest evidence event timestamp in epoch seconds")
    last_seen_event_time: float = Field(default=0.0, description="Latest evidence event timestamp in epoch seconds")

    # Operational Timestamps (Wall Clock for metadata only)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO 8601 creation timestamp")
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO 8601 last update timestamp")

    # Canonical Risk & Severity (from M17 FusionResult)
    current_fused_risk: float = Field(default=0.0, ge=0.0, le=1.0, description="Latest fused operational risk score")
    max_fused_risk: float = Field(default=0.0, ge=0.0, le=1.0, description="Maximum fused risk observed across lifecycle")
    confidence: float = Field(default=0.80, ge=0.0, le=1.0, description="Confidence in threat assessment")
    severity: Severity = Field(default=Severity.MEDIUM, description="Operational severity rating")

    # Distinct separated scoring components (M17 contract)
    calibrated_ml_probability: Optional[float] = Field(default=None, description="Calibrated ML probability")
    anomaly_score: Optional[float] = Field(default=None, description="Isolation Forest anomaly decision score")
    detector_score: Optional[float] = Field(default=None, description="Top behavioral detector score")

    # Correlated Entity & Network Context
    signal_ids: List[str] = Field(default_factory=list, description="IDs of correlated detection signals")
    fusion_ids: List[str] = Field(default_factory=list, description="IDs of contributing fusion results")
    flow_ids: List[str] = Field(default_factory=list, description="Associated network flow IDs")
    conversation_ids: List[str] = Field(default_factory=list, description="Associated bidirectional conversation IDs")
    destination_entities: List[str] = Field(default_factory=list, description="External destination IPs contacted")
    domains: List[str] = Field(default_factory=list, description="DNS domain names queried")
    tls_fingerprints: List[str] = Field(default_factory=list, description="Observed JA3/JA4 TLS fingerprint hashes")

    # Chronological Attack Chain & Timeline
    timeline: List[TimelineEvent] = Field(default_factory=list, description="Strictly sorted event-time timeline")
    attack_chain: List[AttackStageRecord] = Field(default_factory=list, description="Evidence-backed attack stages")
    evidence: List[DeduplicatedEvidence] = Field(default_factory=list, description="Deduplicated evidence items")

    # Risk & Severity History
    risk_history: List[Tuple[float, float]] = Field(default_factory=list, description="History of (event_time, fused_risk)")
    severity_history: List[Tuple[float, str]] = Field(default_factory=list, description="History of (event_time, severity)")

    # Provenance
    feature_schema_version: str = Field(default=FEATURE_SCHEMA_VERSION, description="Feature schema contract version")
    detector_versions: Dict[str, str] = Field(default_factory=lambda: dict(DETECTOR_VERSIONS), description="Active detector versions")
    model_versions: Dict[str, str] = Field(default_factory=lambda: dict(MODEL_VERSIONS), description="Active model versions")

    # Backward-compatible fields
    primary_entity: Optional[str] = None
    risk_score: Optional[float] = None
    overall_severity: Optional[Severity] = None
    threat_stages: List[ThreatStage] = Field(default_factory=list)
    evidence_items: List[str] = Field(default_factory=list)
    recommended_action: Optional[str] = None
    first_seen_iso: Optional[str] = None
    last_seen_iso: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Normalize primary_entity -> entity_id
            if "primary_entity" in data and ("entity_id" not in data or data["entity_id"] == "unknown"):
                data["entity_id"] = data["primary_entity"]
            elif "entity_id" in data and ("primary_entity" not in data or data["primary_entity"] is None):
                data["primary_entity"] = data["entity_id"]

            # Normalize risk_score -> current_fused_risk & max_fused_risk
            if "risk_score" in data and ("current_fused_risk" not in data or data["current_fused_risk"] == 0.0):
                data["current_fused_risk"] = data["risk_score"]
                data["max_fused_risk"] = data["risk_score"]
            elif "current_fused_risk" in data and ("risk_score" not in data or data["risk_score"] is None):
                data["risk_score"] = data["current_fused_risk"]

            # Normalize overall_severity -> severity
            if "overall_severity" in data and "severity" not in data:
                data["severity"] = data["overall_severity"]
            elif "severity" in data and "overall_severity" not in data:
                data["overall_severity"] = data["severity"]
        return data

    def to_dossier_dict(self) -> Dict[str, Any]:
        """Generate deterministic serializable dictionary representation for SOC dossier."""
        dossier = {
            "incident_id": self.incident_id,
            "entity_id": self.entity_id,
            "primary_threat_class": self.primary_threat_class.value,
            "status": self.status.value,
            "first_seen_event_time": round(self.first_seen_event_time, 4),
            "last_seen_event_time": round(self.last_seen_event_time, 4),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "current_fused_risk": round(self.current_fused_risk, 4),
            "max_fused_risk": round(self.max_fused_risk, 4),
            "confidence": round(self.confidence, 4),
            "severity": self.severity.value,
            "calibrated_ml_probability": round(self.calibrated_ml_probability, 4) if self.calibrated_ml_probability is not None else None,
            "anomaly_score": round(self.anomaly_score, 4) if self.anomaly_score is not None else None,
            "detector_score": round(self.detector_score, 4) if self.detector_score is not None else None,
            "signal_ids": sorted(list(set(self.signal_ids))),
            "fusion_ids": sorted(list(set(self.fusion_ids))),
            "flow_ids": sorted(list(set(self.flow_ids))),
            "conversation_ids": sorted(list(set(self.conversation_ids))),
            "destination_entities": sorted(list(set(self.destination_entities))),
            "domains": sorted(list(set(self.domains))),
            "tls_fingerprints": sorted(list(set(self.tls_fingerprints))),
            "timeline": [t.model_dump() for t in sorted(self.timeline, key=lambda x: (x.event_time, x.event_type, x.event_id))],
            "attack_chain": [s.model_dump() for s in sorted(self.attack_chain, key=lambda x: x.first_seen_event_time)],
            "evidence": [e.model_dump() for e in sorted(self.evidence, key=lambda x: x.evidence_id)],
            "risk_history": [(round(t, 4), round(r, 4)) for t, r in self.risk_history],
            "severity_history": [(round(t, 4), s) for t, s in self.severity_history],
            "provenance": {
                "feature_schema_version": self.feature_schema_version,
                "detector_versions": self.detector_versions,
                "model_versions": self.model_versions,
            },
        }
        return dossier

    def to_dossier_json(self, indent: int = 2) -> str:
        """Export deterministic JSON dossier."""
        return json.dumps(self.to_dossier_dict(), indent=indent, sort_keys=True)

    def compute_dossier_hash(self) -> str:
        """Compute cryptographic SHA-256 hash of deterministic incident dossier."""
        serialized = json.dumps(self.to_dossier_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
