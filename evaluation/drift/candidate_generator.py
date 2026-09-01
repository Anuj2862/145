"""Retraining Candidate Generation & Production Safety Policy (M20).

Enforces strict human-in-the-loop governance:
- Automatic detection of statistical/concept drift creates an offline RetrainingCandidate.
- Production models MUST NEVER be automatically retrained or updated from live data streams.
- Every candidate requires:
  1. Drift evidence record
  2. Offline validation benchmark execution
  3. Strict human approval flag (`human_approved = True`) before graduation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional

from evaluation.drift.drift_detector import DriftEvent


@dataclass
class RetrainingCandidate:
    """Artifact representing a candidate retraining dataset & configuration flagged by drift."""
    candidate_id: str
    created_at_iso: str
    trigger_drift_events: List[Dict[str, Any]]
    monitored_features_drifted: List[str]
    proposed_training_window_start: str
    proposed_training_window_end: str
    offline_validation_required: bool = True
    human_approved: bool = False
    approval_notes: Optional[str] = None
    production_deployment_blocked: bool = True

    def approve_for_offline_validation(self, approver_name: str, notes: str) -> None:
        """Explicit human approval method for offline training/validation."""
        self.human_approved = True
        self.approval_notes = f"Approved by {approver_name} on {datetime.now(timezone.utc).isoformat()}: {notes}"
        # Production deployment remains blocked until full validation report is audited
        self.production_deployment_blocked = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "created_at_iso": self.created_at_iso,
            "trigger_drift_events": self.trigger_drift_events,
            "monitored_features_drifted": self.monitored_features_drifted,
            "proposed_training_window_start": self.proposed_training_window_start,
            "proposed_training_window_end": self.proposed_training_window_end,
            "offline_validation_required": self.offline_validation_required,
            "human_approved": self.human_approved,
            "approval_notes": self.approval_notes,
            "production_deployment_blocked": self.production_deployment_blocked,
        }


class RetrainingCandidateManager:
    """Manages creation, serialization, and safety gating for model retraining candidates."""

    def __init__(self, candidates_dir: str = "evaluation/candidates"):
        self.candidates_dir = os.path.abspath(candidates_dir)
        os.makedirs(self.candidates_dir, exist_ok=True)
        self.candidates: List[RetrainingCandidate] = []

    def evaluate_drift_and_propose_candidate(
        self,
        drift_events: List[DriftEvent],
        window_start_iso: str,
        window_end_iso: str,
    ) -> Optional[RetrainingCandidate]:
        """Examine active drift events and safely generate a human-review candidate if drift is verified."""
        if not drift_events:
            return None

        drifted_features = sorted(list(set(evt.feature_name for evt in drift_events if evt.is_drift)))
        if not drifted_features:
            return None

        now_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        cand_id = f"CAND-RETRAIN-{now_str}-{len(self.candidates) + 1:03d}"

        candidate = RetrainingCandidate(
            candidate_id=cand_id,
            created_at_iso=datetime.now(timezone.utc).isoformat(),
            trigger_drift_events=[evt.to_dict() for evt in drift_events],
            monitored_features_drifted=drifted_features,
            proposed_training_window_start=window_start_iso,
            proposed_training_window_end=window_end_iso,
            offline_validation_required=True,
            human_approved=False,
            production_deployment_blocked=True,  # Mandatory safety constraint
        )

        self.candidates.append(candidate)
        self._save_candidate(candidate)
        return candidate

    def _save_candidate(self, candidate: RetrainingCandidate) -> str:
        path = os.path.join(self.candidates_dir, f"{candidate.candidate_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(candidate.to_dict(), f, indent=2)
        return path
