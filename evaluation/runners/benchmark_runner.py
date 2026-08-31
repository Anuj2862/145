"""Benchmark Runner & End-to-End Replay Validation Harness (Phase 2B).

Replays ground-truth registered PCAPs through the frozen detection pipeline,
evaluates temporal predictions against manifest labels, measures empirical
throughput/latency, and exports reproducible evaluation reports.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Dict, List, Optional, Any, Tuple

from dataset.manifest_schema import (
    GroundTruthManifest,
    CaptureRecord,
    EvaluationTrafficClass,
    DatasetSplit,
)
from dataset.manifest_manager import ManifestManager
from evaluation.metrics.confusion_matrix import MultiClassConfusionMatrix

# Frozen production modules reused without modification
from ingest.pcap_reader import iter_pcap
from flow.flow_key import FlowKey
from flow.flow_manager import FlowManager
from flow.windows import StreamingWindowManager
from features.flow_features import extract_flow_features
from detectors.unified_detector import UnifiedM2Orchestrator
from detectors.engine import DetectionContext
from schemas import FeatureVector, FlowFeatures as PydanticFlowFeatures, DetectionSignal


def get_git_commit_hash() -> str:
    """Safely obtain current repository git commit hash."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


class BenchmarkRunner:
    """Orchestrates end-to-end replay benchmarking across registered ground-truth captures."""

    def __init__(
        self,
        manifest_path: str = "dataset/manifests/ground_truth.json",
        artifact_dir: str = "models/artifacts",
        enable_ml: bool = True,
        enable_baseline: bool = True,
    ):
        self.manifest_path = manifest_path
        self.artifact_dir = artifact_dir
        self.enable_ml = enable_ml
        self.enable_baseline = enable_baseline
        self.manifest_manager = ManifestManager.load_from_file(manifest_path)

    def run_benchmark(
        self,
        capture_ids: Optional[List[str]] = None,
        target_split: Optional[DatasetSplit] = None,
        output_dir: str = "evaluation/results",
        report_dir: str = "evaluation/reports",
    ) -> Dict[str, Any]:
        """Execute benchmark evaluation across specified or all registered captures."""
        experiment_id = f"EXP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        git_hash = get_git_commit_hash()

        # Select captures to evaluate
        all_captures = self.manifest_manager.manifest.captures
        selected_records: List[CaptureRecord] = []

        for cap_id, record in all_captures.items():
            if capture_ids and cap_id not in capture_ids:
                continue
            if target_split and record.split != target_split:
                continue
            selected_records.append(record)

        matrix = MultiClassConfusionMatrix()
        total_packets = 0
        total_flows = 0
        evaluated_captures = []
        untested_captures = []

        wall_clock_start = time.perf_counter()

        for record in selected_records:
            pcap_path = Path(record.file_path)
            if not pcap_path.exists():
                matrix.mark_untested(
                    record.primary_label,
                    f"PCAP file missing on disk: {record.file_path}"
                )
                untested_captures.append({
                    "capture_id": record.capture_id,
                    "file_path": record.file_path,
                    "reason": "File does not exist on disk",
                })
                continue

            cap_stats = self._evaluate_single_pcap(record, matrix)
            total_packets += cap_stats["packets"]
            total_flows += cap_stats["flows"]
            evaluated_captures.append({
                "capture_id": record.capture_id,
                "file_path": record.file_path,
                "primary_label": record.primary_label.value,
                "packets_processed": cap_stats["packets"],
                "flows_tracked": cap_stats["flows"],
                "signals_emitted": cap_stats["signals"],
            })

        wall_clock_elapsed = max(0.001, time.perf_counter() - wall_clock_start)
        summary = matrix.compute_summary()

        overall_throughput_pps = total_packets / wall_clock_elapsed
        overall_throughput_fps = total_flows / wall_clock_elapsed

        report_data = {
            "experiment_id": experiment_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "git_commit": git_hash,
            "manifest_file": self.manifest_path,
            "pipeline_config": {
                "enable_ml": self.enable_ml,
                "enable_baseline": self.enable_baseline,
                "artifact_dir": self.artifact_dir,
            },
            "performance": {
                "total_packets_processed": total_packets,
                "total_flows_tracked": total_flows,
                "wall_clock_elapsed_sec": round(wall_clock_elapsed, 4),
                "sustained_throughput_pps": round(overall_throughput_pps, 1),
                "sustained_throughput_fps": round(overall_throughput_fps, 1),
            },
            "metrics": summary,
            "evaluated_captures": evaluated_captures,
            "untested_captures": untested_captures,
        }

        # Save JSON results
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        json_out = Path(output_dir) / f"{experiment_id}.json"
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # Generate and save Markdown Report
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        md_out = Path(report_dir) / f"{experiment_id}.md"
        self._write_markdown_report(md_out, report_data)

        return report_data

    def _evaluate_single_pcap(
        self,
        record: CaptureRecord,
        matrix: MultiClassConfusionMatrix,
    ) -> Dict[str, int]:
        """Process a single PCAP trace through frozen components and align with manifest intervals."""
        flow_manager = FlowManager()
        window_manager = StreamingWindowManager(burst_window_seconds=5.0, timing_window_seconds=30.0)
        orchestrator = UnifiedM2Orchestrator(
            artifact_dir=self.artifact_dir,
            enable_ml=self.enable_ml,
            enable_baseline=self.enable_baseline,
        )

        packet_count = 0
        signals_count = 0

        for raw_packet in iter_pcap(record.file_path):
            packet_count += 1
            flow_manager.process_packet(raw_packet)
            window_manager.update(raw_packet)

            key = FlowKey(
                src_ip=raw_packet.src_ip,
                dst_ip=raw_packet.dst_ip,
                src_port=raw_packet.src_port,
                dst_port=raw_packet.dst_port,
                protocol=raw_packet.protocol,
            )
            flow_state = flow_manager.flows.get(key)
            if flow_state is None:
                continue

            extracted = extract_flow_features(flow_state)
            pydantic_flow_features = PydanticFlowFeatures(
                packets_per_sec=extracted.packet_rate,
                bytes_per_sec=extracted.byte_rate,
                syn_ratio=extracted.syn_ratio,
                fan_out_dest_count=1,
                dst_port_cardinality=1,
            )

            now_iso = datetime.fromtimestamp(flow_state.last_seen, tz=timezone.utc).isoformat()
            src_ip = flow_state.key.src_ip
            dst_ip = flow_state.key.dst_ip

            fv = FeatureVector(
                feature_id=f"fv-{src_ip}-{int(flow_state.last_seen)}",
                entity_ip=src_ip,
                flow_id=f"{src_ip}:{flow_state.key.src_port}-{dst_ip}:{flow_state.key.dst_port}-{flow_state.key.protocol}",
                window_size_sec=5,
                timestamp_iso=now_iso,
                flow_features=pydantic_flow_features,
            )

            context = DetectionContext(
                source_entity=src_ip,
                timestamp_iso=now_iso,
                feature_vector=fv,
                observation_count=flow_state.packet_count,
            )

            # Measure evaluation latency
            t0 = time.perf_counter()
            signals = orchestrator.evaluate(context)
            lat_ms = (time.perf_counter() - t0) * 1000.0

            # Determine ground-truth label for this exact window
            active_events = self.manifest_manager.get_ground_truth_for_time_window(
                capture_id=record.capture_id,
                window_start_iso=now_iso,
                window_end_iso=now_iso,
            )
            
            if active_events:
                # Use class of first active ground truth event matching this source/target
                matching_evt = next((e for e in active_events if e.source_entity == src_ip), active_events[0])
                gt_class = matching_evt.traffic_class
            else:
                gt_class = EvaluationTrafficClass.BENIGN

            # Determine predicted class from signals
            if signals:
                signals_count += len(signals)
                # Map primary signal
                top_signal = max(signals, key=lambda s: s.confidence)
                try:
                    pred_class = EvaluationTrafficClass(top_signal.threat_class.value)
                except ValueError:
                    pred_class = EvaluationTrafficClass.UNKNOWN_ANOMALY
            else:
                pred_class = EvaluationTrafficClass.BENIGN

            matrix.record_match(ground_truth=gt_class, predicted=pred_class, latency_ms=lat_ms)

        return {
            "packets": packet_count,
            "flows": len(flow_manager.flows),
            "signals": signals_count,
        }

    def _write_markdown_report(self, file_path: Path, data: Dict[str, Any]) -> None:
        """Render evaluation results as a human-readable markdown verification dossier."""
        perf = data["performance"]
        metrics = data["metrics"]

        lines = [
            f"# Empirical Benchmark Report: {data['experiment_id']}",
            "",
            f"- **Timestamp (UTC):** {data['timestamp_utc']}",
            f"- **Git Commit:** `{data['git_commit']}`",
            f"- **Manifest File:** `{data['manifest_file']}`",
            f"- **Pipeline Config:** ML Enabled: `{data['pipeline_config']['enable_ml']}`, Baselines Enabled: `{data['pipeline_config']['enable_baseline']}`",
            "",
            "## 1. Measured Ingestion & Latency Performance",
            "",
            "| Performance Metric | Measured Value | Target / Baseline |",
            "| :--- | :---: | :---: |",
            f"| **Total Packets Ingested** | {perf['total_packets_processed']:,} packets | — |",
            f"| **Total Flows Tracked** | {perf['total_flows_tracked']:,} flows | — |",
            f"| **Elapsed Time** | {perf['wall_clock_elapsed_sec']} s | — |",
            f"| **Sustained Packet Throughput** | **{perf['sustained_throughput_pps']:,.1f} pps** | Engineering Target: >= 10,000 pps |",
            f"| **Median Evaluation Latency (p50)** | **{metrics['latency_median_ms']} ms** | Sub-second Target |",
            f"| **95th Percentile Latency (p95)** | **{metrics['latency_p95_ms']} ms** | Sub-second Target (< 1,000 ms) |",
            "",
            "## 2. Detection Accuracy & Macro Metrics",
            "",
            "| Metric | Score | Description |",
            "| :--- | :---: | :--- |",
            f"| **Macro Precision** | **{metrics['macro_precision']:.4f}** | Unweighted mean precision across tested threat classes |",
            f"| **Macro Recall** | **{metrics['macro_recall']:.4f}** | Unweighted mean sensitivity across tested threat classes |",
            f"| **Macro F1-Score** | **{metrics['macro_f1']:.4f}** | Overall harmonic mean score |",
            f"| **Benign False Positive Rate (FPR)** | **{metrics['benign_false_positive_rate']:.4f}** | Misclassification rate on benign traffic intervals |",
            f"| **Total Temporal Decisions** | {metrics['total_evaluations']:,} | Total window evaluation passes |",
            "",
            "## 3. Per-Class Scorecard Breakdown",
            "",
            "| Traffic Class | Status | TP | FP | FN | Precision | Recall | F1 Score |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]

        for cls_name, cls_data in metrics["per_class_breakdown"].items():
            if cls_data.get("status") == "NOT_TESTED":
                lines.append(f"| `{cls_name}` | ⚪ *NOT TESTED* | — | — | — | — | — | {cls_data.get('reason', '')} |")
            else:
                lines.append(
                    f"| `{cls_name}` | 🟢 TESTED | {cls_data['true_positives']} | {cls_data['false_positives']} | "
                    f"{cls_data['false_negatives']} | {cls_data['precision']:.4f} | {cls_data['recall']:.4f} | **{cls_data['f1_score']:.4f}** |"
                )

        lines.extend([
            "",
            "## 4. Evaluated PCAP Captures",
            "",
        ])
        if data["evaluated_captures"]:
            for cap in data["evaluated_captures"]:
                lines.append(f"- **`{cap['capture_id']}`** (`{cap['file_path']}`) &bull; Label: `{cap['primary_label']}` &bull; Packets: {cap['packets_processed']:,} &bull; Signals: {cap['signals_emitted']}")
        else:
            lines.append("- *No captures available on disk for evaluation.*")

        if data["untested_captures"]:
            lines.append("")
            lines.append("## 5. Untested Captures (Pending Trace Ingestion)")
            lines.append("")
            for cap in data["untested_captures"]:
                lines.append(f"- ⚪ **`{cap['capture_id']}`** (`{cap['file_path']}`): *{cap['reason']}*")

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UniGuard AI Baseline Benchmark Runner (Phase 2B)")
    parser.add_argument("--manifest", default="dataset/manifests/ground_truth.json", help="Path to ground_truth.json")
    parser.add_argument("--artifact-dir", default="models/artifacts", help="Path to model artifacts")
    parser.add_argument("--no-ml", action="store_true", help="Disable ML inference (heuristic only)")
    parser.add_argument("--no-baseline", action="store_true", help="Disable heuristic baselines (ML only)")
    parser.add_argument("--output-dir", default="evaluation/results", help="Directory for JSON results")
    parser.add_argument("--report-dir", default="evaluation/reports", help="Directory for Markdown reports")

    args = parser.parse_args()

    runner = BenchmarkRunner(
        manifest_path=args.manifest,
        artifact_dir=args.artifact_dir,
        enable_ml=not args.no_ml,
        enable_baseline=not args.no_baseline,
    )
    res = runner.run_benchmark(output_dir=args.output_dir, report_dir=args.report_dir)
    print(f"[SUCCESS] Benchmark complete. Report written to {args.report_dir}/")
