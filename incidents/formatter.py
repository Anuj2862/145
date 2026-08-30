"""Alert formatting and serialization utilities for Member 3 (Milestone 1).

Provides JSON serialization and terminal CLI formatting for standardized Alert models.
"""

import json
from typing import Optional, Dict, Any, List

from schemas import Alert, DetectionSignal


def alert_to_json(alert: Alert, indent: int = 2) -> str:
    """Serialize an Alert model to a deterministic, indented JSON string.

    Args:
        alert: Validated Alert instance.
        indent: Indentation level for pretty-printing (default: 2).

    Returns:
        JSON string conforming to schemas.Alert.
    """
    if not isinstance(alert, Alert):
        raise TypeError(f"Expected Alert instance, got {type(alert).__name__}")
    return alert.model_dump_json(indent=indent)


def alert_from_json(json_str: str) -> Alert:
    """Deserialize a JSON string into a validated Alert model.

    Args:
        json_str: JSON representation of an Alert.

    Returns:
        Validated Alert instance.

    Raises:
        pydantic.ValidationError / ValueError if JSON is malformed or non-conforming.
    """
    return Alert.model_validate_json(json_str)


def format_alert_cli(
    alert: Alert,
    indicators: Optional[Dict[str, Any]] = None,
    evidence_items: Optional[List[str]] = None,
) -> str:
    """Format an Alert into a clean, human-readable terminal/CLI presentation.

    Args:
        alert: Validated Alert model.
        indicators: Optional raw dictionary of metric indicators from DetectionSignal.
        evidence_items: Optional explicit list of supporting evidence strings.

    Returns:
        Multi-line formatted string suitable for terminal display.
    """
    protocol_str = ""
    if alert.protocol is not None:
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = proto_map.get(alert.protocol, "UNKNOWN")
        protocol_str = f"{alert.protocol} ({proto_name})"
    else:
        protocol_str = "N/A"

    lines = [
        "=" * 50,
        "SECURITY ALERT",
        "=" * 50,
        f"Alert ID     : {alert.alert_id}",
        f"Threat Class : {alert.threat_class.value}",
        f"Severity     : {alert.severity.value}",
        f"Confidence   : {alert.confidence:.2f}",
        f"Source       : {alert.source_ip}",
        f"Destination  : {alert.destination_ip or 'N/A'}",
        f"Protocol     : {protocol_str}",
        f"Timestamp    : {alert.timestamp_iso}",
        f"Summary      : {alert.summary}",
    ]

    if alert.incident_id:
        lines.insert(4, f"Incident ID  : {alert.incident_id}")

    # Supporting Evidence section
    lines.append("Evidence:")
    if evidence_items:
        for item in evidence_items:
            lines.append(f"  - {item}")
    elif indicators:
        for k, v in indicators.items():
            k_clean = k.replace("_", " ").title()
            if isinstance(v, float):
                lines.append(f"  - {k_clean}: {v:.2f}")
            else:
                lines.append(f"  - {k_clean}: {v}")
    else:
        lines.append(f"  - Automated passive detector signal ({alert.evidence_count} evidence item(s))")

    lines.append("=" * 50)
    return "\n".join(lines)
