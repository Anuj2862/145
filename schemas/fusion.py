"""Schemas for Multi-Signal Fusion, Correlation and Risk Scoring (M17).

Defines standardized Pydantic contract models for fusion output, itemized mathematical
evidence contributions, and multi-signal aggregation states.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict

from schemas import ThreatClass, Severity


class SignalFamily(str, Enum):
    """Independent source categories of evidence for diversity evaluation."""
    HEURISTIC_DETECTOR = "HEURISTIC_DETECTOR"
    CALIBRATED_ML = "CALIBRATED_ML"
    UNSUPERVISED_ANOMALY = "UNSUPERVISED_ANOMALY"
    ENTITY_BASELINE = "ENTITY_BASELINE"
    DNS_TELEMETRY = "DNS_TELEMETRY"
    TLS_TELEMETRY = "TLS_TELEMETRY"
    FLOW_TELEMETRY = "FLOW_TELEMETRY"


class FusionEvidenceItem(BaseModel):
    """Itemized mathematical contribution to composite fused risk score."""
    model_config = ConfigDict(extra="ignore")

    component_name: str = Field(..., description="Source component (e.g. detector_signal, calibrated_ml)")
    raw_value: Any = Field(..., description="Raw metric or score value")
    weight: float = Field(default=0.0, description="Configured weight coefficient")
    weighted_contribution: float = Field(default=0.0, description="Contribution to fused_risk")
    description: str = Field(..., description="Human-readable analytical explanation")


class FusionResult(BaseModel):
    """Production Multi-Signal Fusion output record (M17).

    Encapsulates consolidated operational risk, calibrated ML probabilities,
    unsupervised anomaly score, and itemized evidence contributions.
    """
    model_config = ConfigDict(extra="ignore")

    fusion_id: str = Field(..., description="Unique fusion assessment identifier")
    entity_id: str = Field(..., description="Primary originating host IP or entity identity")
    threat_class: ThreatClass = Field(..., description="Primary classified threat hypothesis")
    fused_risk: float = Field(..., ge=0.0, le=1.0, description="Composite operational risk score in [0.0, 1.0]")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in primary threat hypothesis")
    severity: Severity = Field(default=Severity.INFO, description="Operational severity rating")

    # Distinct separated scoring components (NOT conflated with fused_risk)
    detector_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Top behavioral detector score")
    calibrated_ml_probability: float = Field(default=0.0, ge=0.0, le=1.0, description="Calibrated ML probability for primary class")
    anomaly_score: float = Field(default=0.0, description="Isolation Forest raw anomaly decision score")
    entity_deviation: float = Field(default=0.0, description="Entity baseline robust Z-score deviation")

    # Multi-signal provenance & context
    signal_ids: List[str] = Field(default_factory=list, description="IDs of correlated detection signals")
    contributing_detectors: List[str] = Field(default_factory=list, description="Names of active detectors")
    independent_signal_family_count: int = Field(default=1, ge=1, description="Count of distinct signal families")
    persistence_duration_sec: float = Field(default=0.0, ge=0.0, description="Event-time duration of signal persistence")
    conflict_detected: bool = Field(default=False, description="Flag indicating disagreement between detector and ML")

    # Itemized evidence
    evidence: List[FusionEvidenceItem] = Field(default_factory=list, description="Itemized weighted contributions")

    # Temporal bounds (Event Time)
    event_time: Optional[float] = Field(default=None, description="Assessment epoch event timestamp")
    window_start: Optional[float] = Field(default=None, description="Earliest evidence epoch timestamp")
    window_end: Optional[float] = Field(default=None, description="Latest evidence epoch timestamp")
    timestamp_iso: str = Field(..., description="ISO 8601 evaluation timestamp")
