"""Unit tests for Ground-Truth Dataset & Manifest Infrastructure (Phase 2A)."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from pydantic import ValidationError

from dataset.manifest_schema import (
    EvaluationTrafficClass,
    DatasetSplit,
    GenerationMethod,
    TemporalWindow,
    GroundTruthEvent,
    CaptureRecord,
    GroundTruthManifest,
)
from dataset.manifest_manager import ManifestManager


class TestGroundTruthManifest(unittest.TestCase):
    def setUp(self):
        self.valid_window = TemporalWindow(
            start_time_iso="2026-08-31T12:00:00Z",
            end_time_iso="2026-08-31T12:10:00Z",
            start_offset_sec=0.0,
            end_offset_sec=600.0,
        )

        self.valid_event = GroundTruthEvent(
            event_id="EVT-DDOS-001",
            traffic_class=EvaluationTrafficClass.VOLUMETRIC_DDOS,
            time_window=self.valid_window,
            source_entity="198.51.100.99",
            target_entity="10.0.0.1",
            source_port=None,
            target_port=80,
            protocol=6,
            confidence_level=1.0,
            observable_indicators={"packets_per_sec": 15000.0, "syn_ratio": 0.99},
        )

        self.valid_capture = CaptureRecord(
            capture_id="CAP-TEST-001",
            file_path="dataset/pcaps/ddos/test_syn_flood.pcap",
            file_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            traffic_type="ATTACK",
            primary_label=EvaluationTrafficClass.VOLUMETRIC_DDOS,
            capture_start_iso="2026-08-31T12:00:00Z",
            capture_end_iso="2026-08-31T12:15:00Z",
            duration_sec=900.0,
            packet_count=50000,
            byte_count=32000000,
            source_ips=["198.51.100.99"],
            target_ips=["10.0.0.1"],
            protocols=[6],
            generation_method=GenerationMethod.SYNTHETIC_LAB,
            dataset_source="UniGuard Testbed",
            split=DatasetSplit.EVALUATION_HOLD_OUT,
            labeled_events=[self.valid_event],
        )

    def test_valid_manifest_record_creation(self):
        """Test instantiation of a valid CaptureRecord and GroundTruthManifest."""
        manifest = GroundTruthManifest(
            manifest_version="1.0.0",
            description="Test manifest",
            captures={"CAP-TEST-001": self.valid_capture},
        )
        self.assertEqual(len(manifest.captures), 1)
        self.assertEqual(manifest.captures["CAP-TEST-001"].primary_label, EvaluationTrafficClass.VOLUMETRIC_DDOS)

    def test_invalid_temporal_ordering_rejected(self):
        """Ensure start_time after end_time raises ValidationError."""
        with self.assertRaises(ValidationError):
            TemporalWindow(
                start_time_iso="2026-08-31T12:10:00Z",
                end_time_iso="2026-08-31T12:00:00Z",
            )

    def test_invalid_offset_ordering_rejected(self):
        """Ensure start_offset > end_offset raises ValidationError."""
        with self.assertRaises(ValidationError):
            TemporalWindow(
                start_time_iso="2026-08-31T12:00:00Z",
                end_time_iso="2026-08-31T12:10:00Z",
                start_offset_sec=500.0,
                end_offset_sec=100.0,
            )

    def test_event_outside_capture_bounds_rejected(self):
        """Ensure an event starting before or ending after parent capture boundaries is rejected."""
        out_of_bounds_window = TemporalWindow(
            start_time_iso="2026-08-31T12:00:00Z",
            end_time_iso="2026-08-31T13:00:00Z",  # Exceeds capture end of 12:15:00Z
        )
        out_of_bounds_event = GroundTruthEvent(
            event_id="EVT-OOB-001",
            traffic_class=EvaluationTrafficClass.VOLUMETRIC_DDOS,
            time_window=out_of_bounds_window,
            source_entity="198.51.100.99",
        )

        with self.assertRaises(ValidationError):
            CaptureRecord(
                capture_id="CAP-OOB-001",
                file_path="dataset/pcaps/ddos/oob.pcap",
                traffic_type="ATTACK",
                primary_label=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                capture_start_iso="2026-08-31T12:00:00Z",
                capture_end_iso="2026-08-31T12:15:00Z",
                duration_sec=900.0,
                labeled_events=[out_of_bounds_event],
            )

    def test_manifest_capture_id_mismatch_rejected(self):
        """Ensure mapping key mismatch with record.capture_id raises ValidationError."""
        with self.assertRaises(ValidationError):
            GroundTruthManifest(
                captures={"MISMATCHED_KEY": self.valid_capture}
            )

    def test_manifest_manager_file_round_trip(self):
        """Test saving and loading GroundTruthManifest to/from disk."""
        manifest = GroundTruthManifest(
            captures={"CAP-TEST-001": self.valid_capture}
        )
        manager = ManifestManager(manifest)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            manager.save_to_file(temp_path)
            loaded_manager = ManifestManager.load_from_file(temp_path)

            self.assertEqual(len(loaded_manager.manifest.captures), 1)
            cap = loaded_manager.get_capture("CAP-TEST-001")
            self.assertIsNotNone(cap)
            self.assertEqual(cap.capture_id, "CAP-TEST-001")
            self.assertEqual(cap.duration_sec, 900.0)
            self.assertEqual(len(cap.labeled_events), 1)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_manifest_manager_querying(self):
        """Test filtering captures by class, split, and time window."""
        manifest = GroundTruthManifest(
            captures={"CAP-TEST-001": self.valid_capture}
        )
        manager = ManifestManager(manifest)

        # Query by class
        ddos_caps = manager.get_captures_by_class(EvaluationTrafficClass.VOLUMETRIC_DDOS)
        self.assertEqual(len(ddos_caps), 1)
        c2_caps = manager.get_captures_by_class(EvaluationTrafficClass.BOTNET_C2_BEACONING)
        self.assertEqual(len(c2_caps), 0)

        # Query by split
        hold_out_caps = manager.get_captures_by_split(DatasetSplit.EVALUATION_HOLD_OUT)
        self.assertEqual(len(hold_out_caps), 1)

        # Query events within active time window
        active_events = manager.get_ground_truth_for_time_window(
            capture_id="CAP-TEST-001",
            window_start_iso="2026-08-31T12:02:00Z",
            window_end_iso="2026-08-31T12:05:00Z",
        )
        self.assertEqual(len(active_events), 1)
        self.assertEqual(active_events[0].event_id, "EVT-DDOS-001")

        # Query outside active window
        inactive_events = manager.get_ground_truth_for_time_window(
            capture_id="CAP-TEST-001",
            window_start_iso="2026-08-31T12:11:00Z",
            window_end_iso="2026-08-31T12:14:00Z",
        )
        self.assertEqual(len(inactive_events), 0)

    def test_malformed_json_raises_error(self):
        """Ensure loading malformed JSON raises ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{ malformed json content ...")
            temp_path = f.name

        try:
            with self.assertRaises(ValueError):
                ManifestManager.load_from_file(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_official_seed_manifest_validity(self):
        """Verify that the official seed manifest dataset/manifests/ground_truth.json loads cleanly."""
        manifest_path = Path("dataset/manifests/ground_truth.json")
        self.assertTrue(manifest_path.exists(), "Official ground_truth.json must exist")

        manager = ManifestManager.load_from_file(manifest_path)
        summary = manager.summary()

        self.assertGreaterEqual(summary["total_captures"], 3)
        self.assertIn("VOLUMETRIC_DDOS", summary["classes_distribution"])
        self.assertIn("BENIGN", summary["classes_distribution"])


if __name__ == "__main__":
    unittest.main()
