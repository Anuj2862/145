"""Shared contract schemas for Unidirectional IP Threat Detection System (PS 26145).

These Pydantic models define the data exchange contracts between modules:
    FlowEvent       -> Output of flow/ (5-tuple flow state and window summaries)
    FeatureVector   -> Output of features/ (extracted flow, DNS, TLS, temporal, entity features)
    DetectionSignal -> Output of detectors/ (individual threat detector outputs)
    EntityEvent     -> Output of entity/ (entity profile and baseline deviations)
    Incident        -> Output of fusion/ and incidents/ (multi-signal correlated incident)
    Alert           -> Output for SOC dashboard and external SIEM ingestion
"""

from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict, model_validator

from schemas.telemetry import UNKNOWN_SENSOR_ID
from schemas.telemetry import canonical_conversation_id
from schemas.telemetry import canonical_entity_id


class ThreatClass(str, Enum):
    """Seven required threat classes under PS 26145."""
    VOLUMETRIC_DDOS = "VOLUMETRIC_DDOS"
    BOTNET_C2_BEACONING = "BOTNET_C2_BEACONING"
    DGA_DNS_TUNNELLING = "DGA_DNS_TUNNELLING"
    ENCRYPTED_MALWARE = "ENCRYPTED_MALWARE"
    RECON_PORT_SCAN = "RECON_PORT_SCAN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


class DetectorType(str, Enum):
    """Detector implementation types."""
    DETERMINISTIC_BASELINE = "DETERMINISTIC_BASELINE"
    LIGHTWEIGHT_ML = "LIGHTWEIGHT_ML"
    UNSUPERVISED_ANOMALY = "UNSUPERVISED_ANOMALY"
    CORRELATION_FUSION = "CORRELATION_FUSION"


class Severity(str, Enum):
    """Threat severity levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TCPFlags(BaseModel):
    """TCP flag counter summary."""
    model_config = ConfigDict(extra="ignore")
    
    syn_count: int = Field(default=0, ge=0)
    ack_count: int = Field(default=0, ge=0)
    fin_count: int = Field(default=0, ge=0)
    rst_count: int = Field(default=0, ge=0)
    psh_count: int = Field(default=0, ge=0)
    urg_count: int = Field(default=0, ge=0)


class DNSMetadata(BaseModel):
    """Optional passively observed DNS metadata."""
    model_config = ConfigDict(extra="ignore")

    query_name: Optional[str] = None
    query_type: Optional[str] = None
    response_code: Optional[str] = None
    answer_count: Optional[int] = Field(default=None, ge=0)


class TLSMetadata(BaseModel):
    """Optional TLS metadata visible without payload decryption."""
    model_config = ConfigDict(extra="ignore")

    sni: Optional[str] = None
    alpn: Optional[str] = None
    ja3_hash: Optional[str] = None
    ja4_hash: Optional[str] = None
    tls_version: Optional[str] = None


class QUICMetadata(BaseModel):
    """Optional QUIC metadata visible from passive observation."""
    model_config = ConfigDict(extra="ignore")

    sni: Optional[str] = None
    alpn: Optional[str] = None
    version: Optional[str] = None
    connection_id: Optional[str] = None


class FlowEvent(BaseModel):
    """5-Tuple unidirectional flow state record.
    
    Produced by: flow/ (Member 1)
    Consumed by: features/ (Member 2)
    """
    model_config = ConfigDict(extra="ignore")

    flow_id: str = Field(..., description="Unique flow identifier: src_ip:src_port-dst_ip:dst_port-proto")
    conversation_id: Optional[str] = Field(default=None, description="Deterministic bidirectional grouping key")
    entity_id: Optional[str] = Field(default=None, description="Behavioral aggregation entity identifier")
    sensor_id: str = Field(default=UNKNOWN_SENSOR_ID, description="Passive sensor identifier")
    src_ip: str = Field(..., description="Source IPv4/IPv6 address")
    dst_ip: str = Field(..., description="Destination IPv4/IPv6 address")
    src_port: int = Field(..., ge=0, le=65535, description="Source transport port")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination transport port")
    protocol: int = Field(..., ge=0, le=255, description="IP protocol number (e.g. 6=TCP, 17=UDP, 1=ICMP)")
    event_time: Optional[float] = Field(default=None, description="Packet/capture event timestamp in epoch seconds")
    ingest_time: Optional[float] = Field(default=None, description="Ingestion timestamp in epoch seconds")
    processing_time: Optional[float] = Field(default=None, description="Processing timestamp in epoch seconds")
    alert_time: Optional[float] = Field(default=None, description="Alert emission timestamp in epoch seconds, if applicable")
    start_time_iso: str = Field(..., description="ISO 8601 start timestamp")
    end_time_iso: str = Field(..., description="ISO 8601 end timestamp")
    duration_sec: float = Field(default=0.0, ge=0.0, description="Flow duration in seconds")
    packet_count: int = Field(default=1, ge=1, description="Total packet count in flow")
    byte_count: int = Field(default=0, ge=0, description="Total byte count in flow")
    tcp_flags: Optional[TCPFlags] = Field(default=None, description="TCP flag counts if TCP")
    packet_lengths: List[int] = Field(default_factory=list, description="Sequence of observed packet sizes")
    inter_arrival_times_ms: List[float] = Field(default_factory=list, description="Packet inter-arrival intervals in ms")
    dns: Optional[DNSMetadata] = Field(default=None, description="Passively observed DNS metadata, if available")
    tls: Optional[TLSMetadata] = Field(default=None, description="Passively observed TLS metadata, if available")
    quic: Optional[QUICMetadata] = Field(default=None, description="Passively observed QUIC metadata, if available")

    @model_validator(mode="after")
    def populate_canonical_ids(self) -> "FlowEvent":
        if self.conversation_id is None:
            self.conversation_id = canonical_conversation_id(
                src_ip=self.src_ip,
                src_port=self.src_port,
                dst_ip=self.dst_ip,
                dst_port=self.dst_port,
                protocol=self.protocol,
            )
        if self.entity_id is None:
            self.entity_id = canonical_entity_id(
                src_ip=self.src_ip,
                sensor_id=self.sensor_id,
            )
        return self


class FlowFeatures(BaseModel):
    """Flow velocity and cardinality features."""
    model_config = ConfigDict(extra="ignore")
    
    packets_per_sec: float = Field(default=0.0, ge=0.0)
    bytes_per_sec: float = Field(default=0.0, ge=0.0)
    syn_ratio: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    fan_out_dest_count: Optional[int] = Field(default=None, ge=0)
    dst_port_cardinality: Optional[int] = Field(default=None, ge=0)


class DNSFeatures(BaseModel):
    """Passively observed DNS metadata features (no payload decryption required)."""
    model_config = ConfigDict(extra="ignore")
    
    query_length_mean: Optional[float] = Field(default=None, ge=0.0)
    entropy_mean: Optional[float] = Field(default=None, ge=0.0)
    nxdomain_count: int = Field(default=0, ge=0)
    txt_record_ratio: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    subdomain_count: Optional[int] = Field(default=None, ge=0)


class TLSFeatures(BaseModel):
    """Passively observable TLS/QUIC handshake metadata (if available in cleartext header)."""
    model_config = ConfigDict(extra="ignore")
    
    ja3_hash: Optional[str] = Field(default=None, description="JA3 client fingerprint string if observable")
    ja4_hash: Optional[str] = Field(default=None, description="JA4 fingerprint if observable")
    sni: Optional[str] = Field(default=None, description="Server Name Indication if observable")
    alpn: Optional[str] = Field(default=None, description="Application Layer Protocol Negotiation string")


class TemporalFeatures(BaseModel):
    """Inter-arrival timing and periodicity metrics."""
    model_config = ConfigDict(extra="ignore")
    
    inter_arrival_mean_ms: Optional[float] = Field(default=None, ge=0.0)
    inter_arrival_std_ms: Optional[float] = Field(default=None, ge=0.0)
    periodicity_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    jitter_pct: Optional[float] = Field(default=None, ge=0.0)


class EntityFeatures(BaseModel):
    """Entity-relative baseline metrics."""
    model_config = ConfigDict(extra="ignore")
    
    historical_mean_pps: Optional[float] = Field(default=None, ge=0.0)
    historical_std_pps: Optional[float] = Field(default=None, ge=0.0)
    pps_z_score: Optional[float] = Field(default=None)
    is_new_destination: Optional[bool] = Field(default=None)


class FeatureVector(BaseModel):
    """Normalized feature vector extracted across 5 families.
    
    Produced by: features/ (Member 2)
    Consumed by: detectors/ (Member 2)
    """
    model_config = ConfigDict(extra="ignore")

    feature_id: str = Field(..., description="Unique feature vector ID")
    entity_ip: str = Field(..., description="Primary entity IP address being profiled")
    flow_id: Optional[str] = Field(default=None, description="Associated flow ID if applicable")
    window_size_sec: int = Field(default=5, ge=1, description="Sliding window size in seconds")
    timestamp_iso: str = Field(..., description="Extraction timestamp")
    flow_features: FlowFeatures = Field(default_factory=FlowFeatures)
    dns_features: Optional[DNSFeatures] = Field(default=None)
    tls_features: Optional[TLSFeatures] = Field(default=None)
    temporal_features: Optional[TemporalFeatures] = Field(default=None)
    entity_features: Optional[EntityFeatures] = Field(default=None)


class EvidenceItem(BaseModel):
    """Structured forensic evidence item supporting a detection decision."""
    model_config = ConfigDict(extra="ignore")

    feature_name: str = Field(..., description="Canonical feature name")
    value: Any = Field(..., description="Observed feature value")
    baseline: Optional[Any] = Field(default=None, description="Historical entity baseline or reference value")
    deviation: Optional[Any] = Field(default=None, description="Deviation metric (e.g. z-score, ratio)")
    interpretation: str = Field(default="", description="Human-readable analytical explanation")


class SignalProvenance(BaseModel):
    """Forensic and scientific provenance metadata for a DetectionSignal (Phase 2C)."""
    model_config = ConfigDict(extra="ignore")

    detector_id: str = Field(..., description="Identifying name of detector algorithm")
    detector_version: str = Field(default="1.0.0", description="Semantic version of detector")
    decision_reason: List[str] = Field(default_factory=list, description="Machine-readable trigger criteria")
    observable_features: Dict[str, Any] = Field(default_factory=dict, description="Exact feature values used in decision")
    window_start_iso: Optional[str] = Field(default=None, description="Start of temporal observation window")
    window_end_iso: Optional[str] = Field(default=None, description="End of temporal observation window")
    experiment_id: Optional[str] = Field(default=None, description="Evaluation experiment ID if applicable")
    capture_id: Optional[str] = Field(default=None, description="PCAP capture ID if applicable")
    ground_truth_label: Optional[str] = Field(default=None, description="Manifest ground-truth label during evaluation")


class DetectionSignal(BaseModel):
    """Individual threat detector output signal with forensic provenance and structured evidence.
    
    Produced by: detectors/ (Member 2)
    Consumed by: entity/ & fusion/ (Member 3)
    """
    model_config = ConfigDict(extra="ignore")

    signal_id: str = Field(..., description="Unique detection signal ID")
    threat_class: ThreatClass = Field(..., description="Classified threat category")
    detector_type: DetectorType = Field(default=DetectorType.DETERMINISTIC_BASELINE)
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence score (0.0 - 1.0)")
    score: Optional[float] = Field(default=None, description="Threat suspicion score (0.0 - 1.0)")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity rating")
    source_entity: str = Field(..., description="Source IP address or Host entity")
    entity_id: Optional[str] = Field(default=None, description="Canonical entity identifier")
    target_entity: Optional[str] = Field(default=None, description="Target/victim IP or domain")
    flow_id: Optional[str] = Field(default=None, description="Associated flow identifier if applicable")
    event_time: Optional[float] = Field(default=None, description="Event timestamp in epoch seconds")
    window_start: Optional[float] = Field(default=None, description="Window start timestamp in epoch seconds")
    window_end: Optional[float] = Field(default=None, description="Window end timestamp in epoch seconds")
    timestamp_iso: str = Field(..., description="Detection timestamp in ISO 8601")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Structured evidence items")
    indicators: Dict[str, Any] = Field(default_factory=dict, description="Key metrics triggering detection")
    feature_schema_version: str = Field(default="feature-schema-v2.0.0", description="Feature schema contract version")
    detector_version: Optional[str] = Field(default="2.0.0", description="Semantic version of detector")

    # Phase 2C Provenance & Explainability (Backwards-compatible)
    detector_id: Optional[str] = Field(default=None, description="Identifying name of detector algorithm")
    decision_reason: List[str] = Field(default_factory=list, description="Machine-readable trigger criteria")
    observable_features: Dict[str, Any] = Field(default_factory=dict, description="Exact feature values used in decision")
    provenance: Optional[SignalProvenance] = Field(default=None, description="Structured provenance container")

    @model_validator(mode="after")
    def populate_defaults(self) -> "DetectionSignal":
        if self.entity_id is None:
            self.entity_id = self.source_entity
        if self.score is None:
            self.score = self.confidence
        return self


class EntityEvent(BaseModel):
    """Rolling host baseline and relationship snapshot.
    
    Produced by: entity/ (Member 3)
    Consumed by: fusion/ (Member 3)
    """
    model_config = ConfigDict(extra="ignore")

    entity_id: str = Field(..., description="Entity IP address or domain")
    entity_type: str = Field(default="HOST_IP", description="HOST_IP, DOMAIN, or SUBNET")
    timestamp_iso: str = Field(..., description="Evaluation timestamp")
    active_signals: List[str] = Field(default_factory=list, description="IDs of currently active signals")
    baseline_deviation_score: float = Field(default=0.0, ge=0.0, description="Statistical deviation from historical norm")
    known_destinations_count: int = Field(default=0, ge=0)
    new_destinations_count: int = Field(default=0, ge=0)


from schemas.incident import (
    IncidentStatus,
    AttackStageType,
    threat_class_to_stage_type,
    AttackStageRecord,
    TimelineEvent,
    DeduplicatedEvidence,
    ThreatStage,
    Incident,
)


class Alert(BaseModel):
    """Standardized alert for real-time dispatch and SOC dashboard.
    
    Produced by: incidents/ & detectors/ (Members 2 & 3)
    Consumed by: api/ & dashboard/ (Member 3)
    """
    model_config = ConfigDict(extra="ignore")

    alert_id: str = Field(..., description="Unique alert identifier (e.g. ALT-20260830-001)")
    incident_id: Optional[str] = Field(default=None, description="Linked incident ID if correlated")
    timestamp_iso: str = Field(..., description="ISO 8601 timestamp")
    threat_class: ThreatClass = Field(..., description="Threat category")
    severity: Severity = Field(default=Severity.HIGH)
    confidence: float = Field(..., ge=0.0, le=1.0)
    source_ip: str = Field(..., description="Originating source IP")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP")
    protocol: Optional[int] = Field(default=None, ge=0, le=255)
    summary: str = Field(..., description="Human-readable threat summary")
    evidence_count: int = Field(default=1, ge=0, description="Number of supporting evidence items")

    # Phase 2C Provenance Extensions (Backwards-compatible)
    detector_id: Optional[str] = Field(default=None, description="Identifying name of detector algorithm")
    decision_reason: List[str] = Field(default_factory=list, description="Machine-readable trigger criteria")
    observable_features: Dict[str, Any] = Field(default_factory=dict, description="Exact feature values used in decision")


from schemas.fusion import (
    SignalFamily,
    FusionEvidenceItem,
    FusionResult,
)
