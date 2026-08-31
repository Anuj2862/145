"""Ground-Truth Manifest Manager for PS 26145 Evaluation Infrastructure.

Provides loader, query engine, integrity validator, and serialization routines
for managing ground-truth dataset manifests.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

from dataset.manifest_schema import (
    GroundTruthManifest,
    CaptureRecord,
    GroundTruthEvent,
    EvaluationTrafficClass,
    DatasetSplit,
)


class ManifestManager:
    """Manages ground-truth manifest lifecycle, verification, and querying."""

    def __init__(self, manifest: Optional[GroundTruthManifest] = None):
        self.manifest: GroundTruthManifest = manifest or GroundTruthManifest()

    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> "ManifestManager":
        """Load and validate a ground-truth manifest from a JSON file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Ground-truth manifest file not found: {file_path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Malformed JSON in ground-truth manifest {file_path}: {e}")

        manifest = GroundTruthManifest.model_validate(data)
        return cls(manifest)

    def save_to_file(self, file_path: Union[str, Path], indent: int = 2) -> None:
        """Serialize and save the manifest to a JSON file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest.updated_at_iso = datetime.now(timezone.utc).isoformat()

        with open(path, "w", encoding="utf-8") as f:
            f.write(self.manifest.model_dump_json(indent=indent))

    def add_capture(self, record: CaptureRecord, overwrite: bool = False) -> None:
        """Register a new CaptureRecord into the manifest."""
        if record.capture_id in self.manifest.captures and not overwrite:
            raise ValueError(f"Capture ID '{record.capture_id}' already exists in manifest. Set overwrite=True to replace.")
        self.manifest.captures[record.capture_id] = record

    def get_capture(self, capture_id: str) -> Optional[CaptureRecord]:
        """Retrieve a CaptureRecord by ID."""
        return self.manifest.captures.get(capture_id)

    def get_captures_by_class(self, traffic_class: EvaluationTrafficClass) -> List[CaptureRecord]:
        """Retrieve all captures matching a specific primary traffic class."""
        return [c for c in self.manifest.captures.values() if c.primary_label == traffic_class]

    def get_captures_by_split(self, split: DatasetSplit) -> List[CaptureRecord]:
        """Retrieve all captures allocated to a designated dataset partition."""
        return [c for c in self.manifest.captures.values() if c.split == split]

    def get_ground_truth_for_time_window(
        self,
        capture_id: str,
        window_start_iso: str,
        window_end_iso: str,
    ) -> List[GroundTruthEvent]:
        """Retrieve any ground-truth events active within a specified time window for a capture."""
        capture = self.get_capture(capture_id)
        if not capture:
            raise KeyError(f"Capture ID '{capture_id}' not found in manifest")

        w_start = datetime.fromisoformat(window_start_iso.replace("Z", "+00:00"))
        w_end = datetime.fromisoformat(window_end_iso.replace("Z", "+00:00"))

        active_events = []
        for evt in capture.labeled_events:
            e_start = datetime.fromisoformat(evt.time_window.start_time_iso.replace("Z", "+00:00"))
            e_end = datetime.fromisoformat(evt.time_window.end_time_iso.replace("Z", "+00:00"))

            # Overlap check: max(start1, start2) <= min(end1, end2)
            if max(w_start, e_start) <= min(w_end, e_end):
                active_events.append(evt)

        return active_events

    def validate_file_paths(self, base_dir: Optional[Union[str, Path]] = None) -> Dict[str, bool]:
        """Verify existence of underlying PCAP files referenced in the manifest."""
        base = Path(base_dir) if base_dir else Path.cwd()
        results = {}
        for cap_id, record in self.manifest.captures.items():
            full_path = base / record.file_path
            results[cap_id] = full_path.exists()
        return results

    def summary(self) -> Dict[str, Any]:
        """Compute summary statistics of registered captures and labels."""
        class_counts: Dict[str, int] = {}
        split_counts: Dict[str, int] = {}
        total_events = 0

        for c in self.manifest.captures.values():
            c_class = c.primary_label.value
            class_counts[c_class] = class_counts.get(c_class, 0) + 1

            c_split = c.split.value
            split_counts[c_split] = split_counts.get(c_split, 0) + 1
            total_events += len(c.labeled_events)

        return {
            "total_captures": len(self.manifest.captures),
            "total_labeled_events": total_events,
            "classes_distribution": class_counts,
            "splits_distribution": split_counts,
            "manifest_version": self.manifest.manifest_version,
            "updated_at_iso": self.manifest.updated_at_iso,
        }
