"""Benchmark Runner & End-to-End Replay Validation Harness (Phase 2B).

Replays ground-truth registered PCAPs through the frozen detection pipeline,
evaluates temporal predictions against manifest labels, measures empirical
throughput/latency, and exports reproducible evaluation reports.
"""

import argparse
from datetime import datetime, timezone
import json
import math
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
from schemas import (
    FeatureVector,
    FlowFeatures as PydanticFlowFeatures,
    TemporalFeatures,
    DNSFeatures,
    TLSFeatures,
    DetectionSignal,
)


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

        # Pre-parse ground truth events into epoch timestamps for high-speed temporal matching
        parsed_events = []
        for evt in record.labeled_events:
            s_dt = datetime.fromisoformat(evt.time_window.start_time_iso.replace("Z", "+00:00"))
            e_dt = datetime.fromisoformat(evt.time_window.end_time_iso.replace("Z", "+00:00"))
            parsed_events.append({
                "event": evt,
                "start_ts": s_dt.timestamp(),
                "end_ts": e_dt.timestamp(),
                "src": evt.source_entity,
                "class": evt.traffic_class,
            })

        packet_count = 0
        signals_count = 0
        last_eval_time_per_entity: Dict[str, float] = {}

        for raw_packet in iter_pcap(record.file_path):
            packet_count += 1
            flow_manager.process_packet(raw_packet)
            window_manager.update(raw_packet)

            src_ip = raw_packet.src_ip
            dst_ip = raw_packet.dst_ip

            # Stream-evaluation rate control: evaluate entity at 1.0s virtual window cadence
            last_eval = last_eval_time_per_entity.get(src_ip, 0.0)
            if (raw_packet.timestamp - last_eval) < 1.0:
                continue
            last_eval_time_per_entity[src_ip] = raw_packet.timestamp

            key = FlowKey(
                src_ip=src_ip,
                dst_ip=dst_ip,
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

            # 1. Temporal Features (from packet inter-arrival timestamps)
            temporal_feats = None
            if len(flow_state.inter_arrival_times_ms) >= 3:
                iats = flow_state.inter_arrival_times_ms
                iat_mean = sum(iats) / len(iats)
                variance = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
                iat_std = math.sqrt(variance)
                jitter_pct = (iat_std / iat_mean * 100.0) if iat_mean > 0 else 0.0
                periodicity = max(0.0, min(1.0, 1.0 - (jitter_pct / 50.0)))
                temporal_feats = TemporalFeatures(
                    inter_arrival_mean_ms=iat_mean,
                    inter_arrival_std_ms=iat_std,
                    periodicity_score=periodicity,
                    jitter_pct=jitter_pct,
                )

            # 2. DNS Features (when port 53 traffic is observed)
            dns_feats = None
            if 53 in (flow_state.key.src_port, flow_state.key.dst_port):
                dns_feats = DNSFeatures(
                    entropy_mean=4.2,
                    query_length_mean=32.0,
                    subdomain_count=1,
                )

            fv = FeatureVector(
                feature_id=f"fv-{src_ip}-{int(flow_state.last_seen)}",
                entity_ip=src_ip,
                flow_id=f"{src_ip}:{flow_state.key.src_port}-{dst_ip}:{flow_state.key.dst_port}-{flow_state.key.protocol}",
                window_size_sec=5,
                timestamp_iso=now_iso,
                flow_features=pydantic_flow_features,
                temporal_features=temporal_feats,
                dns_features=dns_feats,
            )

            # 3. Entity-level Reconnaissance Features
            entity_flows = [f for f in flow_manager.flows.values() if f.key.src_ip == src_ip]
            dst_ips = {f.key.dst_ip for f in entity_flows}
            dst_ports = {f.key.dst_port for f in entity_flows}
            failed_conns = sum(1 for f in entity_flows if f.byte_count == 0 or (f.syn_count > 0 and f.ack_count == 0))
            failed_ratio = failed_conns / len(entity_flows) if entity_flows else 0.0
            first_seen_ts = min((f.start_time for f in entity_flows), default=raw_packet.timestamp) if entity_flows else raw_packet.timestamp
            duration_sec = max(1.0, raw_packet.timestamp - first_seen_ts)

            from features.recon_features import ReconFeatures
            recon_feats = ReconFeatures(
                flow_count=len(entity_flows),
                unique_dst_ip_count=len(dst_ips),
                unique_dst_port_count=len(dst_ports),
                unique_dst_ips=dst_ips,
                unique_dst_ports=dst_ports,
                is_horizontal=len(dst_ips) > 5,
                is_vertical=len(dst_ports) > 5,
                failed_connection_count=failed_conns,
                failed_connection_ratio=failed_ratio,
                connection_rate_per_sec=len(entity_flows) / duration_sec,
            )

            # 4. Entity-level Exfiltration Features
            outbound_bytes = sum(f.byte_count for f in entity_flows)
            inbound_flows = [f for f in flow_manager.flows.values() if f.key.dst_ip == src_ip]
            inbound_bytes = sum(f.byte_count for f in inbound_flows)
            up_down_ratio = outbound_bytes / max(1.0, float(inbound_bytes)) if inbound_bytes > 0 else (100.0 if outbound_bytes > 10000 else 1.0)

            from features.exfil_features import ExfiltrationFeatures
            exfil_feats = ExfiltrationFeatures(
                flow_count=len(entity_flows),
                outbound_flow_count=len(entity_flows),
                inbound_flow_count=len(inbound_flows),
                total_outbound_bytes=outbound_bytes,
                total_inbound_bytes=inbound_bytes,
                upload_download_ratio=up_down_ratio,
                outbound_bytes_per_sec=outbound_bytes / duration_sec,
                maximum_single_flow_bytes=max((f.byte_count for f in entity_flows), default=0),
                destination_count=len(dst_ips),
                window_duration_sec=duration_sec,
            )

            context = DetectionContext(
                source_entity=src_ip,
                timestamp_iso=now_iso,
                feature_vector=fv,
                observation_count=len(entity_flows),
                recon_features=recon_feats,
                exfil_features=exfil_feats,
            )

            # Measure evaluation latency
            t0 = time.perf_counter()
            signals = orchestrator.evaluate(context)
            lat_ms = (time.perf_counter() - t0) * 1000.0

            # High-speed epoch temporal matching against ground-truth
            cur_pkt_ts = raw_packet.timestamp
            gt_class = EvaluationTrafficClass.BENIGN
            for pe in parsed_events:
                # Tolerance window: 5s for fast bursts
                if (pe["start_ts"] - 5.0) <= cur_pkt_ts <= (pe["end_ts"] + 5.0):
                    if pe["src"] == src_ip or pe["src"] == dst_ip:
                        gt_class = pe["class"]
                        break

            # Determine predicted class from active threat signals (filtering out INFO / non-threats)
            from schemas import Severity
            active_signals = [
                s for s in signals
                if s is not None and s.confidence >= 0.1 and s.severity != Severity.INFO
            ]
            if active_signals:
                signals_count += len(active_signals)
                for s in active_signals:
                    if s.provenance is not None:
                        s.provenance.capture_id = record.capture_id
                        s.provenance.ground_truth_label = gt_class.value
                top_signal = max(active_signals, key=lambda s: s.confidence)
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

        throughput_str = f"**{perf['sustained_throughput_pps']:,.1f} pps**" if perf["total_packets_processed"] > 0 else "*N/A (no packets evaluated)*"
        median_lat_str = f"**{metrics['latency_median_ms']} ms**" if metrics["latency_median_ms"] != "N/A" else "*N/A (no decisions)*"
        p95_lat_str = f"**{metrics['latency_p95_ms']} ms**" if metrics["latency_p95_ms"] != "N/A" else "*N/A (no decisions)*"

        lines = [
            f"# Empirical Benchmark Report: {data['experiment_id']}",
            "",
            f"- **Status:** `{metrics.get('evaluation_status', 'COMPLETED')}`",
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
            f"| **Sustained Packet Throughput** | {throughput_str} | Engineering Target: >= 10,000 pps |",
            f"| **Median Evaluation Latency (p50)** | {median_lat_str} | Sub-second Target |",
            f"| **95th Percentile Latency (p95)** | {p95_lat_str} | Sub-second Target (< 1,000 ms) |",
            "",
            "## 2. Detection Accuracy & Macro Metrics",
            "",
            "| Metric | Score | Description |",
            "| :--- | :---: | :--- |",
            f"| **Macro Precision** | **{metrics['macro_precision']}** | Unweighted mean precision across tested threat classes |",
            f"| **Macro Recall** | **{metrics['macro_recall']}** | Unweighted mean sensitivity across tested threat classes |",
            f"| **Macro F1-Score** | **{metrics['macro_f1']}** | Overall harmonic mean score |",
            f"| **Benign False Positive Rate (FPR)** | **{metrics['benign_false_positive_rate']}** | Misclassification rate on benign traffic intervals |",
            f"| **Total Temporal Decisions** | {metrics['total_evaluations']:,} | Total window evaluation passes |",
            "",
            "## 3. Per-Class Scorecard Breakdown",
            "",
            "| Traffic Class | Status | TP | FP | FN | TN | Support | Precision | Recall | F1 Score |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]

        for cls_name, cls_data in metrics["per_class_breakdown"].items():
            if cls_data.get("status") == "NOT_TESTED":
                lines.append(f"| `{cls_name}` | ⚪ *NOT TESTED* | — | — | — | — | — | — | — | *{cls_data.get('reason', '')}* |")
            else:
                p_str = f"{cls_data['precision']:.4f}" if isinstance(cls_data['precision'], (int, float)) else str(cls_data['precision'])
                r_str = f"{cls_data['recall']:.4f}" if isinstance(cls_data['recall'], (int, float)) else str(cls_data['recall'])
                f_str = f"**{cls_data['f1_score']:.4f}**" if isinstance(cls_data['f1_score'], (int, float)) else str(cls_data['f1_score'])

                lines.append(
                    f"| `{cls_name}` | 🟢 TESTED | {cls_data['true_positives']} | {cls_data['false_positives']} | "
                    f"{cls_data['false_negatives']} | {cls_data['true_negatives']} | {cls_data.get('support', 0)} | "
                    f"{p_str} | {r_str} | {f_str} |"
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
