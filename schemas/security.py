from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

class SecurityBoundaryEventType(str, Enum):
    NETWORK_WRITE_BLOCKED = "NETWORK_WRITE_BLOCKED"
    ACTIVE_RESPONSE_BLOCKED = "ACTIVE_RESPONSE_BLOCKED"
    PAYLOAD_DECRYPTION_BLOCKED = "PAYLOAD_DECRYPTION_BLOCKED"
    UNAUTHORIZED_PATH_BLOCKED = "UNAUTHORIZED_PATH_BLOCKED"
    WORKSPACE_INTEGRITY_VIOLATION = "WORKSPACE_INTEGRITY_VIOLATION"
    RECURSIVE_DIRECTORY_BLOCKED = "RECURSIVE_DIRECTORY_BLOCKED"
    MUTATION_ATTEMPT_BLOCKED = "MUTATION_ATTEMPT_BLOCKED"

class SecurityBoundaryEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    event_id: str = Field(default_factory=lambda: f"SEC-{uuid.uuid4().hex[:10].upper()}")
    event_time: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    timestamp_iso: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: SecurityBoundaryEventType = Field(...)
    component: str = Field(...)
    operation: str = Field(...)
    allowed: bool = Field(default=False)
    reason: str = Field(...)
    source_context: Dict[str, Any] = Field(default_factory=dict)
