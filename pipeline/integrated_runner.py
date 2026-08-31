"""Integrated Pipeline Runner for PS 26145.

Integrates:
  - Member 1 (Ingestion, 5-tuple Flow, Streaming Windows, PCAP Replay)
  - Member 2 (Feature Extraction, Baseline Detectors, LightGBM & Isolation Forest ML)
  - Member 3 (Entity Memory, Entity Behaviour Graph, Fusion Engine, Evidence & Incident Builder)
"""

import os
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timezone

from ingest.pcap_reader import iter_pcap, NormalizedPacket
from flow.flow_key import FlowKey
from flow.flow_manager import FlowManager
from flow.windows import StreamingWindowManager
from features.flow_features import extract_flow_features
from detectors.unified_detector import UnifiedM2Orchestrator
from detectors.engine import DetectionContext
from schemas import (
    FlowEvent,
    FeatureVector,
    FlowFeatures as PydanticFlowFeatures,
    DetectionSignal,
    Incident,
    Alert,
)
from entity.memory import EntityMemory
from entity.graph import EntityBehaviourGraph
from fusion.engine import MultiSignalFusionEngine
from incidents.incident_builder import IncidentBuilder
from incidents.formatter import alert_to_json, format_alert_cli


class PipelineStats:
    """Tracks runtime performance metrics for pipeline execution."""

    def __init__(self):
        self.packets_processed: int = 0
        self.flows_tracked: int = 0
        self.windows_emitted: int = 0
        self.signals_generated: int = 0
        self.incidents_created: int = 0
        self.alerts_dispatched: int = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def start(self):
        self.start_time = datetime.now(timezone.utc)

    def finish(self):
        self.end_time = datetime.now(timezone.utc)

    @property
    def elapsed_seconds(self) -> float:
        if not self.start_time:
            return 0.0
        end = self.end_time or datetime.now(timezone.utc)
        return max(0.001, (end - self.start_time).total_seconds())

    @property
    def packets_per_second(self) -> float:
        if not self.start_time or self.packets_processed == 0:
            return 0.0
        return self.packets_processed / max(0.001, self.elapsed_seconds)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets_processed": self.packets_processed,
            "flows_tracked": self.flows_tracked,
            "windows_emitted": self.windows_emitted,
            "signals_generated": self.signals_generated,
            "incidents_created": self.incidents_created,
            "alerts_dispatched": self.alerts_dispatched,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "packets_per_second": round(self.packets_per_second, 1),
        }


class IntegratedThreatPipeline:
    """Full-stack streaming cyber threat detection and intelligence pipeline."""

    def __init__(
        self,
        artifact_dir: str = "models/artifacts",
        burst_window_seconds: float = 5.0,
        timing_window_seconds: float = 30.0,
        window_size_sec: Optional[float] = None,
        step_size_sec: Optional[float] = None,
        enable_ml: bool = True,
        on_alert_callback: Optional[Callable[[Alert], None]] = None,
        on_incident_callback: Optional[Callable[[Incident], None]] = None,
    ):
        self.burst_window_seconds = window_size_sec or burst_window_seconds
        self.timing_window_seconds = timing_window_seconds
        self.on_alert = on_alert_callback
        self.on_incident = on_incident_callback

        # Member 1 components
        self.flow_manager = FlowManager()
        self.window_manager = StreamingWindowManager(
            burst_window_seconds=self.burst_window_seconds,
            timing_window_seconds=self.timing_window_seconds,
        )

        # Member 2 components
        self.orchestrator = UnifiedM2Orchestrator(artifact_dir=artifact_dir, enable_ml=enable_ml)

        # Member 3 components
        self.entity_memory = EntityMemory()
        self.entity_graph = EntityBehaviourGraph()
        self.fusion_engine = MultiSignalFusionEngine()
        self.incident_builder = IncidentBuilder()

        # In-memory stores
        self.alerts: List[Alert] = []
        self.incidents: List[Incident] = []
        self.stats = PipelineStats()

    def process_pcap(self, pcap_path: str) -> PipelineStats:
        """Process an offline PCAP file through the entire end-to-end pipeline."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        self.stats.start()

        for raw_packet in iter_pcap(pcap_path):
            self.stats.packets_processed += 1
            
            # Update flow manager
            self.flow_manager.process_packet(raw_packet)
            
            # Key for flow state lookup
            key = FlowKey(
                src_ip=raw_packet.src_ip,
                dst_ip=raw_packet.dst_ip,
                src_port=raw_packet.src_port,
                dst_port=raw_packet.dst_port,
                protocol=raw_packet.protocol,
            )
            flow_state = self.flow_manager.flows.get(key)

            # Update window manager
            self.window_manager.update(raw_packet)
            self.stats.windows_emitted += 1

            # Evaluate active flow upon significant state updates
            if flow_state is not None:
                self._evaluate_flow(flow_state)

        self.stats.flows_tracked = len(self.flow_manager.flows)
        self.stats.finish()
        return self.stats

    def _evaluate_flow(self, flow_state) -> None:
        """Process a flow state through M2 detection and M3 correlation."""
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
            window_size_sec=int(self.burst_window_seconds),
            timestamp_iso=now_iso,
            flow_features=pydantic_flow_features,
        )

        # Update Member 3 Entity Memory
        self.entity_memory.get_or_create_profile(fv.entity_ip).update_from_feature_vector(fv)

        context = DetectionContext(
            source_entity=src_ip,
            timestamp_iso=now_iso,
            feature_vector=fv,
            observation_count=flow_state.packet_count,
        )

        # Member 2 Evaluation: Heuristic + ML
        signals = self.orchestrator.evaluate(context)

        # Member 3 Fusion, Evidence & Incident Building
        for sig in signals:
            self.stats.signals_generated += 1
            self.entity_memory.record_signal(sig)

            # Correlate signal
            group, composite_risk, severity = self.fusion_engine.process_signal(
                signal=sig,
                entity_memory=self.entity_memory,
                graph=self.entity_graph,
            )

            # Build Incident & Alert
            incident = self.incident_builder.build_incident_from_group(
                group=group,
                entity_memory=self.entity_memory,
                graph=self.entity_graph,
            )
            self.incidents.append(incident)
            self.stats.incidents_created += 1
            if self.on_incident:
                self.on_incident(incident)

            alert = self.incident_builder.build_incident_alert(incident, sig)
            self.alerts.append(alert)
            self.stats.alerts_dispatched += 1
            if self.on_alert:
                self.on_alert(alert)
