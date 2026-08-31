"""Ground-Truth Manifest Schema for PS 26145 Evaluation Infrastructure.

Defines Pydantic v2 data models for associating network traffic captures (PCAPs),
temporal windows, labeled ground truth, and capture provenance for evaluation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict


class EvaluationTrafficClass(str, Enum):
    """Evaluation traffic taxonomy aligned with PS 26145 threat classes and benign traffic."""
    BENIGN = "BENIGN"
    VOLUMETRIC_DDOS = "VOLUMETRIC_DDOS"
    BOTNET_C2_BEACONING = "BOTNET_C2_BEACONING"
    DGA_DNS_TUNNELLING = "DGA_DNS_TUNNELLING"
    ENCRYPTED_MALWARE = "ENCRYPTED_MALWARE"
    RECON_PORT_SCAN = "RECON_PORT_SCAN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


class DatasetSplit(str, Enum):
    """Dataset partition assignment for leakage prevention."""
    TRAIN = "TRAIN"
    VALIDATION = "VAL"
    TEST = "TEST"
    EVALUATION_HOLD_OUT = "EVALUATION_HOLD_OUT"


class GenerationMethod(str, Enum):
    """Method used to generate or capture the traffic trace."""
    SYNTHETIC_LAB = "SYNTHETIC_LAB"
    PUBLIC_BENCHMARK = "PUBLIC_BENCHMARK"
    PHYSICAL_TAP = "PHYSICAL_TAP"
    HYBRID_OVERLAY = "HYBRID_OVERLAY"


class TemporalWindow(BaseModel):
    """Defines a closed time interval within a capture."""
    model_config = ConfigDict(extra="forbid")

    start_time_iso: str = Field(
        ...,
        description="ISO 8601 UTC timestamp of window start",
        examples=["2026-08-31T12:00:00Z"]
    )
    end_time_iso: str = Field(
        ...,
        description="ISO 8601 UTC timestamp of window end",
        examples=["2026-08-31T12:05:00Z"]
    )
    start_offset_sec: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Offset in seconds from the beginning of the PCAP file"
    )
    end_offset_sec: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Offset in seconds from the beginning of the PCAP file"
    )

    @model_validator(mode="after")
    def validate_time_ordering(self) -> "TemporalWindow":
        try:
            start_dt = datetime.fromisoformat(self.start_time_iso.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(self.end_time_iso.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"Invalid ISO 8601 timestamp format in temporal window: {e}")

        if start_dt > end_dt:
            raise ValueError(
                f"Invalid temporal window: start_time ({self.start_time_iso}) must precede or equal end_time ({self.end_time_iso})"
            )

        if self.start_offset_sec is not None and self.end_offset_sec is not None:
            if self.start_offset_sec > self.end_offset_sec:
                raise ValueError(
                    f"Invalid offset bounds: start_offset_sec ({self.start_offset_sec}) cannot exceed end_offset_sec ({self.end_offset_sec})"
                )

        return self


class GroundTruthEvent(BaseModel):
    """An individual labeled threat or activity event within a capture trace."""
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(
        ...,
        min_length=3,
        description="Unique identifier for this ground-truth event",
        examples=["EVT-DDOS-001"]
    )
    traffic_class: EvaluationTrafficClass = Field(
        ...,
        description="Ground-truth traffic or threat classification"
    )
    time_window: TemporalWindow = Field(
        ...,
        description="Temporal boundaries when this event is active"
    )
    source_entity: str = Field(
        ...,
        description="Originating host IP, subnet, or entity ID"
    )
    target_entity: Optional[str] = Field(
        default=None,
        description="Target external IP, domain, or subnet"
    )
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    target_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[int] = Field(default=None, ge=0, le=255)
    confidence_level: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Analyst confidence in the ground-truth labeling"
    )
    observable_indicators: Dict[str, Any] = Field(
        default_factory=dict,
        description="Concrete, verifiable protocol metadata characterizing the event"
    )
    notes: Optional[str] = Field(default=None, description="Contextual analyst notes")


class CaptureRecord(BaseModel):
    """Complete ground-truth profile and metadata for an individual PCAP trace."""
    model_config = ConfigDict(extra="forbid")

    capture_id: str = Field(
        ...,
        min_length=3,
        description="Unique standardized identifier for this capture",
        examples=["CAP-BENIGN-001", "CAP-DDOS-SYN-001"]
    )
    file_path: str = Field(
        ...,
        min_length=1,
        description="Relative path from repository root to the PCAP file",
        examples=["dataset/pcaps/ddos/syn_flood_10kpps.pcap"]
    )
    file_sha256: Optional[str] = Field(
        default=None,
        pattern=r"^[a-fA-F0-9]{64}$",
        description="SHA-256 integrity hash of the raw PCAP file"
    )
    traffic_type: str = Field(
        ...,
        description="High-level category: BENIGN, ATTACK, or MIXED",
        examples=["BENIGN", "ATTACK", "MIXED"]
    )
    primary_label: EvaluationTrafficClass = Field(
        ...,
        description="Primary overall classification label"
    )
    capture_start_iso: str = Field(..., description="Timestamp of first packet in trace")
    capture_end_iso: str = Field(..., description="Timestamp of last packet in trace")
    duration_sec: float = Field(..., ge=0.0, description="Total capture duration in seconds")
    packet_count: Optional[int] = Field(default=None, ge=0, description="Total packets in capture")
    byte_count: Optional[int] = Field(default=None, ge=0, description="Total bytes in capture")
    source_ips: List[str] = Field(default_factory=list, description="List of source IPs present")
    target_ips: List[str] = Field(default_factory=list, description="List of destination IPs present")
    protocols: List[int] = Field(default_factory=list, description="List of transport protocols (6=TCP, 17=UDP)")
    generation_method: GenerationMethod = Field(
        default=GenerationMethod.SYNTHETIC_LAB,
        description="Environment or source where traffic was generated"
    )
    dataset_source: str = Field(
        default="UniGuard Isolated Lab Diode Testbed",
        description="Source dataset citation, generator tool, or capture enclave"
    )
    split: DatasetSplit = Field(
        default=DatasetSplit.EVALUATION_HOLD_OUT,
        description="Designated dataset partition"
    )
    labeled_events: List[GroundTruthEvent] = Field(
        default_factory=list,
        description="Chronological list of labeled threat/activity intervals"
    )
    notes: Optional[str] = Field(default=None, description="Detailed environment setup or scenario notes")

    @model_validator(mode="after")
    def validate_capture_bounds(self) -> "CaptureRecord":
        try:
            start_dt = datetime.fromisoformat(self.capture_start_iso.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(self.capture_end_iso.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"Invalid capture timestamp format: {e}")

        if start_dt > end_dt:
            raise ValueError(
                f"Invalid capture bounds: capture_start ({self.capture_start_iso}) exceeds capture_end ({self.capture_end_iso})"
            )

        # Validate that all internal labeled events fall within capture temporal boundaries
        for evt in self.labeled_events:
            evt_start = datetime.fromisoformat(evt.time_window.start_time_iso.replace("Z", "+00:00"))
            evt_end = datetime.fromisoformat(evt.time_window.end_time_iso.replace("Z", "+00:00"))

            if evt_start < start_dt or evt_end > end_dt:
                raise ValueError(
                    f"Event {evt.event_id} time interval [{evt.time_window.start_time_iso} -> {evt.time_window.end_time_iso}] "
                    f"falls outside parent capture boundaries [{self.capture_start_iso} -> {self.capture_end_iso}]"
                )

        return self


class GroundTruthManifest(BaseModel):
    """Root container for all registered evaluation ground-truth captures."""
    model_config = ConfigDict(extra="forbid")

    manifest_version: str = Field(default="1.0.0", description="Manifest format version")
    schema_version: str = Field(default="1.0", description="Ground truth schema specification version")
    created_at_iso: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Creation timestamp"
    )
    updated_at_iso: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Last modification timestamp"
    )
    description: str = Field(
        default="UniGuard AI ground-truth evaluation manifest for PS 26145 unidirectional IP traffic benchmarking.",
        description="Description of evaluation suite"
    )
    captures: Dict[str, CaptureRecord] = Field(
        default_factory=dict,
        description="Dictionary mapping capture_id to CaptureRecord"
    )

    @model_validator(mode="after")
    def validate_unique_capture_ids(self) -> "GroundTruthManifest":
        for cap_id, record in self.captures.items():
            if cap_id != record.capture_id:
                raise ValueError(
                    f"Key mismatch in captures mapping: dictionary key '{cap_id}' does not match record.capture_id '{record.capture_id}'"
                )
        return self
