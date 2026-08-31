from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DetectionAlert:
    timestamp: str
    flow_id: str
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)
