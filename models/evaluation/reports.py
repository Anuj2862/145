"""Evaluation Report Generator for UniGuard ML Systems.

Formats evaluation metrics and experiment parameters into standardized, JSON-serializable
report artifacts.
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def generate_eval_report(
    model_name: str,
    metrics: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    split_evaluated: str = "validation",
) -> Dict[str, Any]:
    """Generate a structured, JSON-serializable evaluation report."""
    report = {
        "model_name": model_name,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "split_evaluated": split_evaluated,
        "metrics": metrics,
    }
    if config:
        report["configuration"] = config
    return report


def save_eval_report(report: Dict[str, Any], filepath: str) -> str:
    """Save an evaluation report to disk as JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    return filepath
