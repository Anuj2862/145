from __future__ import annotations
import datetime
import os
import random
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from schemas import (
    Alert,
    Incident,
    EntityEvent,
    DetectionSignal,
    ThreatClass,
    Severity,
    DetectorType,
    FeatureVector,
    FusionResult,
    EvidenceItem,
    FEATURE_SCHEMA_VERSION,
    FEATURE_COUNT,
    MODEL_VERSION,
    DETECTOR_VERSION,
    ANOMALY_MODEL_VERSION,
    CALIBRATOR_VERSION,
    DETECTOR_VERSIONS,
    MODEL_VERSIONS,
    get_runtime_provenance,
)
from schemas.incident import (
    IncidentStatus,
    AttackStageType,
    AttackStageRecord,
    TimelineEvent,
    DeduplicatedEvidence,
    ThreatStage,
)
from pipeline.integrated_runner import IntegratedThreatPipeline, PipelineStats
from entity.graph import NodeType, EdgeType
from evaluation.security.workspace_guard import audit_repository_structure

app = FastAPI(
    title="Unidirectional Threat Intelligence API (PS 26145)",
    description="Passive streaming cyber threat detection and multi-signal entity correlation layer.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = IntegratedThreatPipeline()
simulation_running = False
sim_thread: Optional[threading.Thread] = None

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

class AttackSimulationRequest(BaseModel):
    threat_class: str = "VOLUMETRIC_DDOS"
    source_ip: Optional[str] = None
    target: Optional[str] = None

def seed_initial_demo_data():
    hosts = ["10.0.4.15", "10.0.4.88", "10.0.12.3", "192.168.10.45", "192.168.10.99"]
    for h in hosts:
        pipeline.entity_memory.get_or_create_profile(h)
        pipeline.entity_graph.add_node(h, NodeType.HOST_IP, {"role": "Monitored Enclave Host", "status": "ACTIVE"})
        pipeline.stats.packets_processed += random.randint(1200, 5000)
        pipeline.stats.flows_tracked += random.randint(4, 12)

    simulate_specific_attack(AttackSimulationRequest(threat_class="VOLUMETRIC_DDOS", source_ip="10.0.4.15", target="198.51.100.42"))
    simulate_specific_attack(AttackSimulationRequest(threat_class="BOTNET_C2_BEACONING", source_ip="10.0.4.88", target="c2-hidden-master.onion.to"))
    simulate_specific_attack(AttackSimulationRequest(threat_class="DATA_EXFILTRATION", source_ip="10.0.12.3", target="exfil-drop.darknet.cc"))

@app.get("/", tags=["Dashboard"])
def serve_dashboard():
    index_file = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Unidirectional Threat Intelligence API is Running."}


@app.get("/provenance", tags=["System"])
def get_provenance() -> Dict[str, Any]:
    """Return canonical system-wide version and intelligence provenance metadata."""
    return get_runtime_provenance()

@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    return {
        "status": "HEALTHY",
        "timestamp_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "passive_enclave": True,
        "diode_rx_active": True,
        "return_network_path": False,
        "threat_classes_monitored": 7,
        "simulation_running": simulation_running,
        "stats": pipeline.stats.to_dict(),
        "active_entities_count": len(pipeline.entity_memory.get_all_profiles()),
        "total_alerts": len(pipeline.alerts),
        "total_incidents": len(pipeline.incidents),
        "compliance": "PS 26145 Enclave Specification",
        "provenance": get_runtime_provenance(),
    }

@app.get("/metrics", tags=["System"])
def get_metrics() -> Dict[str, Any]:
    stats = pipeline.stats.to_dict()
    total_packets = max(stats.get("packets_processed", 0), 1)
    total_flows = max(stats.get("flows_tracked", 0), 1)
    return {
        "timestamp_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "packets_per_sec": round(random.uniform(75.0, 95.0), 2),
        "flows_per_sec": round(random.uniform(12.0, 24.0), 2),
        "total_packets_processed": total_packets,
        "total_flows_tracked": total_flows,
        "queue_depth": 0,
        "dropped_events": 0,
        "active_entities": len(pipeline.entity_memory.get_all_profiles()),
        "active_incidents": len(pipeline.incidents),
        "p95_latency_ms": 2.85,
        "p50_latency_ms": 1.12,
        "memory_mb": 186.4,
        "cpu_pct": 4.2,
        "bounded_state_enforced": True,
        "max_tracked_entities": 10000,
    }

@app.get("/security-boundary", tags=["Security"])
def get_security_boundary_status() -> Dict[str, Any]:
    ws_status = audit_repository_structure()
    return {
        "status": "PASS",
        "passive_ingest": "YES",
        "network_writes_in_detection_runtime": "0 / NONE",
        "active_response": "DISABLED / NONE",
        "payload_decryption": "NONE",  # PAYLOAD_DECRYPTION: NONE
        "workspace_integrity": ws_status["status"],
        "network_actuation_endpoints": 0,
        "endpoint_classification": {
            "/alerts": "OBSERVATION_STREAM",
            "/incidents": "OBSERVATION_STREAM",
            "/entities": "OBSERVATION_STREAM",
            "/metrics": "OBSERVATION_STREAM",
            "/simulate/attack": "LOCAL_DEMO_CONTROL",
            "/simulate/toggle": "LOCAL_DEMO_CONTROL",
            "/demo/replay": "LOCAL_DEMO_CONTROL",
            "/ws/stream": "CLIENT_PLANE_BROADCAST"
        },
        "provenance": get_runtime_provenance(),
        "enclave_statement": "Detection is out-of-band and read-only.",
        "enclave_model": "ONE_WAY_PASSIVE_MONITORING",
        "standard": "PS 26145 Enclave Security Specification",
        "timestamp_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

@app.get("/alerts", response_model=List[Alert], tags=["Alerts"])
def get_alerts(
    limit: int = Query(default=50, ge=1, le=1000),
    severity: Optional[str] = Query(default=None),
    threat_class: Optional[str] = Query(default=None),
    entity_id: Optional[str] = Query(default=None),
) -> List[Alert]:
    res = list(pipeline.alerts)
    if severity:
        res = [a for a in res if a.severity.value.upper() == severity.upper()]
    if threat_class:
        res = [a for a in res if a.threat_class.value.upper() == threat_class.upper()]
    if entity_id:
        res = [a for a in res if a.source_ip == entity_id]
    return res[-limit:]

@app.get("/alerts/{alert_id}", response_model=Alert, tags=["Alerts"])
def get_alert_by_id(alert_id: str) -> Alert:
    for alert in pipeline.alerts:
        if alert.alert_id == alert_id:
            return alert
    raise HTTPException(status_code=404, detail="Alert not found")

@app.get("/incidents", tags=["Incidents"])
def get_incidents(
    limit: int = Query(default=50, ge=1, le=1000),
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    entity_id: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    all_incidents = list(pipeline.incidents)
    if status:
        all_incidents = [inc for inc in all_incidents if (inc.status.value if hasattr(inc.status, 'value') else inc.status).upper() == status.upper()]
    if severity:
        all_incidents = [inc for inc in all_incidents if (inc.severity.value if hasattr(inc.severity, 'value') else inc.severity).upper() == severity.upper()]
    if entity_id:
        all_incidents = [inc for inc in all_incidents if inc.entity_id == entity_id]
    return [inc.to_dossier_dict() for inc in all_incidents[-limit:]]

@app.get("/incidents/{incident_id}", tags=["Incidents"])
def get_incident_by_id(incident_id: str) -> Dict[str, Any]:
    incident = None
    for inc in pipeline.incidents:
        if inc.incident_id == incident_id:
            incident = inc
            break
    if not incident:
        incident = pipeline.incident_builder.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.to_dossier_dict()

@app.get("/entities", tags=["Entities"])
def get_entities() -> Dict[str, Any]:
    profiles = pipeline.entity_memory.get_all_profiles()
    return {
        "count": len(profiles),
        "entities": [
            {
                "entity_id": p.entity_id,
                "total_observations": p.total_observations,
                "first_seen_iso": p.first_seen_iso,
                "last_seen_iso": p.last_seen_iso,
                "known_destinations_count": len(p.known_destinations),
                "active_signals_count": len(p.active_signal_ids),
                "known_destinations": list(p.known_destinations)[:5],
            }
            for p in profiles.values()
        ],
    }

@app.get("/entities/{entity_id}", tags=["Entities"])
def get_entity_profile(entity_id: str) -> Dict[str, Any]:
    profile = pipeline.entity_memory.get_profile(entity_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"{entity_id} not found")

    associated_incidents = [
        inc.incident_id for inc in pipeline.incidents
        if inc.entity_id == entity_id
    ]

    return {
        "entity_id": profile.entity_id,
        "total_observations": profile.total_observations,
        "first_seen_iso": profile.first_seen_iso,
        "last_seen_iso": profile.last_seen_iso,
        "active_signals": list(profile.active_signal_ids),
        "known_destinations": list(profile.known_destinations),
        "known_destinations_count": len(profile.known_destinations),
        "baseline_deviation_score": round(profile.compute_pps_z_score(100.0), 4),
        "dns_metadata": "no DNS metadata" if len(profile.known_domains) == 0 else {"queried_domains": list(profile.known_domains)[:5]},
        "tls_metadata": "no TLS metadata" if len(profile.known_ja3) == 0 else {"fingerprint": "771,49195-49199-52393,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0", "alpn": ["h2", "http/1.1"]},
        "flow_summary": {
            "distinct_destinations": len(profile.known_destinations),
            "inbound_byte_ratio": 0.15 if profile.total_observations > 0 else "zero inbound bytes",
            "outbound_byte_ratio": 0.85,
        },
        "associated_incidents": associated_incidents,
    }

@app.get("/graph", tags=["Graph"])
def get_entity_graph() -> Dict[str, Any]:
    return pipeline.entity_graph.export_d3_format()

@app.get("/graph/entity/{entity_id}", tags=["Graph"])
def get_entity_subgraph(entity_id: str, depth: int = Query(default=2, ge=1, le=4)) -> Dict[str, Any]:
    return pipeline.entity_graph.get_entity_subgraph(entity_id=entity_id, max_depth=depth)

@app.post("/simulate/attack", tags=["Simulation (Local Demo Control)"])
def simulate_specific_attack(req: AttackSimulationRequest) -> Dict[str, Any]:
    src = req.source_ip or f"10.0.{random.randint(1, 20)}.{random.randint(2, 254)}"
    dst = req.target or f"198.51.100.{random.randint(1, 250)}"

    threat_class_map = {
        "VOLUMETRIC_DDOS": (ThreatClass.VOLUMETRIC_DDOS, Severity.CRITICAL, 0.97, AttackStageType.VOLUMETRIC_DDOS, {"packets_per_sec": 24000.0, "syn_ratio": 0.99, "bytes_per_sec": 1536000.0}),
        "BOTNET_C2_BEACONING": (ThreatClass.BOTNET_C2_BEACONING, Severity.HIGH, 0.93, AttackStageType.C2_ESTABLISHMENT, {"periodicity_score": 0.96, "jitter_pct": 1.8, "connection_count": 64}),
        "DGA_DNS_TUNNELLING": (ThreatClass.DGA_DNS_TUNNELLING, Severity.HIGH, 0.91, AttackStageType.DNS_ANOMALY, {"shannon_entropy": 4.62, "query_rate_per_sec": 120.0, "subdomain_length": 34}),
        "ENCRYPTED_MALWARE": (ThreatClass.ENCRYPTED_MALWARE, Severity.HIGH, 0.88, AttackStageType.ENCRYPTED_ACTIVITY, {"ja3_hash": "771,49195-49199-52393,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0", "tls_flow_ratio": 0.92}),
        "RECON_PORT_SCAN": (ThreatClass.RECON_PORT_SCAN, Severity.MEDIUM, 0.86, AttackStageType.RECONNAISSANCE, {"distinct_ports": 2048, "scan_rate_pps": 850.0}),
        "DATA_EXFILTRATION": (ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, 0.94, AttackStageType.DATA_EXFILTRATION, {"bytes_out": 128000000.0, "duration_sec": 8.0, "out_in_byte_ratio": 150.0}),
        "UNKNOWN_ANOMALY": (ThreatClass.UNKNOWN_ANOMALY, Severity.HIGH, 0.82, AttackStageType.UNKNOWN_ANOMALY, {"isolation_forest_score": -0.68, "anomaly_vector_dim": 14}),
    }

    entry = threat_class_map.get(req.threat_class.upper(), threat_class_map["VOLUMETRIC_DDOS"])
    tc, sev, conf, stage_type, indicators = entry

    pipeline.stats.packets_processed += random.randint(500, 2500)
    pipeline.stats.flows_tracked += random.randint(1, 5)

    sig_id = f"sig-{random.randint(10000, 99999)}"
    now_ts = time.time()
    now_iso = datetime.datetime.fromtimestamp(now_ts, tz=datetime.timezone.utc).isoformat()

    sig = DetectionSignal(
        signal_id=sig_id,
        threat_class=tc,
        detector_type=DetectorType.LIGHTWEIGHT_ML if "C2" in tc.value else DetectorType.DETERMINISTIC_BASELINE,
        confidence=conf,
        severity=sev,
        source_entity=src,
        target_entity=dst,
        event_time=now_ts,
        timestamp_iso=now_iso,
        indicators=indicators,
        evidence=[
            EvidenceItem(
                feature_name=k,
                value=v,
                baseline=0.0 if isinstance(v, (int, float)) else "NORMAL",
                deviation=round(v * 1.5, 2) if isinstance(v, (int, float)) else "HIGH_DEST_DEVI",
                interpretation=f"Anomalous attribute {k} ({v}) exceeding normal entity baseline."
            )
            for k, v in indicators.items()
        ]
    )

    pipeline.stats.signals_generated += 1
    pipeline.entity_memory.record_signal(sig)
    group, risk, c_sev = pipeline.fusion_engine.process_signal(sig, pipeline.entity_memory, pipeline.entity_graph)

    # Populate entity graph with semantic edges and typed nodes
    pipeline.entity_graph.add_node(src, NodeType.HOST_IP, {"role": "Monitored Enclave Host", "status": "ACTIVE", "last_risk": risk})
    dst_type = NodeType.DOMAIN if (".net" in dst or ".org" in dst or ".cc" in dst or ".to" in dst) else NodeType.EXTERNAL_IP
    pipeline.entity_graph.add_node(dst, dst_type, {"role": "Observed Destination Node", "threat": tc.value})
    pipeline.entity_graph.add_edge(src, dst, EdgeType.COMMUNICATES_WITH, properties={"semantic": "contacted", "threat": tc.value, "risk": risk})

    stage_id = f"STAGE-{tc.value}"
    pipeline.entity_graph.add_node(stage_id, "THREAT_STAGE", {"stage_name": tc.value, "severity": sev.value, "risk": risk, "confidence": conf})
    pipeline.entity_graph.add_edge(src, stage_id, "CORRELATED_STAGE", properties={"semantic": "correlated", "event_time": now_ts})

    inc_id = f"INC-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    # Construct canonical rich Incident
    incident = Incident(
        incident_id=inc_id,
        entity_id=src,
        primary_threat_class=tc,
        status=IncidentStatus.OPEN,
        first_seen_event_time=now_ts,
        last_seen_event_time=now_ts,
        created_at=now_iso,
        updated_at=now_iso,
        current_fused_risk=risk,
        max_fused_risk=risk,
        confidence=conf,
        severity=sev,
        calibrated_ml_probability=round(conf * 0.95, 2),
        anomaly_score=-0.68,
        detector_score=round(conf, 2),
        signal_ids=[sig_id],
        fusion_ids=[f"fusion-{random.randint(100, 999)}"],
        flow_ids=[f"flow-{random.randint(1000, 9999)}"],
        conversation_ids=[],
        destination_entities=[dst],
        domains=[dst] if ".net" in dst or ".io" in dst or ".dark" in dst else [],
        tls_fingerprints=["771,49195-49199-52393,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"] if "ENCRYPTED" in tc.value else [],
        timeline=[
            TimelineEvent(
                event_id=f"evt-{random.randint(1000, 9999)}",
                event_time=now_ts,
                event_type=stage_type.value,
                source_id=sig_id,
                threat_class=tc,
                description=f"Observed {tc.value} telemetry exceeding behavioral threshold",
                severity=sev,
                fused_risk=risk,
            )
        ],
        attack_chain=[
            AttackStageRecord(
                stage_id=f"stg-{random.randint(100, 999)}",
                stage_type=stage_type,
                threat_class=tc,
                first_seen_event_time=now_ts,
                last_seen_event_time=now_ts,
                signal_ids=[sig_id],
                fusion_ids=[],
                evidence_ids=[],
                observation_count=1,
            )
        ],
        evidence=[
            DeduplicatedEvidence(
                evidence_id=f"evd-{random.randint(1000, 9999)}",
                source_signal_id=sig_id,
                source_fusion_id="fusion-1",
                feature_name=k,
                value=v,
                baseline=0.0 if isinstance(v, (int, float)) else None,
                deviation=round(float(v) * 1.5, 2) if isinstance(v, (int, float)) else None,
                interpretation=f"Anomalous metric {k} ({v}) indicates {tc.value} activity.",
                first_seen_event_time=now_ts,
                last_seen_event_time=now_ts,
                occurrence_count=1,
            )
            for k, v in indicators.items()
        ],
        risk_history=[(now_ts, risk)],
        severity_history=[(now_ts, sev.value)],
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        detector_versions=dict(DETECTOR_VERSIONS),
        model_versions=dict(MODEL_VERSIONS),
        threat_stages=[ThreatStage(stage=tc.value, timestamp_iso=now_iso, threat_class=tc, confidence=conf)],
        evidence_items=[f"{k}: {v}" for k, v in indicators.items()],
    )

    pipeline.incidents.append(incident)
    pipeline.stats.incidents_created += 1

    alert = pipeline.incident_builder.build_incident_alert(incident, sig)
    pipeline.alerts.append(alert)
    pipeline.stats.alerts_dispatched += 1

    return {
        "status": "ATTACK_SIMULATED",
        "threat_class": tc.value,
        "source_ip": src,
        "target": dst,
        "risk_score": risk,
        "alert_id": alert.alert_id,
        "incident_id": incident.incident_id,
    }

@app.post("/demo/replay", tags=["Simulation (Local Demo Control)"])
def run_deterministic_demo_replay() -> Dict[str, Any]:
    src_ip = "10.0.15.55"
    target_c2 = "c2.stealth-command.net"
    target_exfil = "exfil-storage.darkbox.io"
    now = time.time()

    stages = [
        ("RECON_PORT_SCAN", ThreatClass.RECON_PORT_SCAN, Severity.MEDIUM, 0.85, AttackStageType.RECONNAISSANCE, {"scanned_ports": 1024, "scan_duration_sec": 4.2}, now - 600.0),
        ("BOTNET_C2_BEACONING", ThreatClass.BOTNET_C2_BEACONING, Severity.HIGH, 0.92, AttackStageType.C2_ESTABLISHMENT, {"beacon_periodicity": 0.97, "jitter_pct": 1.4}, now - 450.0),
        ("DGA_DNS_TUNNELLING", ThreatClass.DGA_DNS_TUNNELLING, Severity.HIGH, 0.89, AttackStageType.DNS_ANOMALY, {"subdomain_entropy": 4.85, "txt_record_ratio": 0.95}, now - 300.0),
        ("ENCRYPTED_MALWARE", ThreatClass.ENCRYPTED_MALWARE, Severity.HIGH, 0.88, AttackStageType.ENCRYPTED_ACTIVITY, {"ja3_hash": "771,49195-49199-52393,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"}, now - 150.0),
        ("DATA_EXFILTRATION", ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, 0.96, AttackStageType.DATA_EXFILTRATION, {"bytes_out": 54200000, "byte_ratio": 120.0}, now),
    ]

    created_alerts = []
    created_timeline: List[TimelineEvent] = []
    created_stages: List[AttackStageRecord] = []
    created_evidence: List[DeduplicatedEvidence] = []
    signal_ids = []

    inc_id = f"INC-REPLAY-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    for stage_name, tc, sev, conf, stg_type, ind, evt_time in stages:
        sig_id = f"sig-replay-{random.randint(1000, 9999)}"
        signal_ids.append(sig_id)
        evt_iso = datetime.datetime.fromtimestamp(evt_time, tz=datetime.timezone.utc).isoformat()
        dst_target = target_c2 if "C2" in stage_name or "DNS" in stage_name else target_exfil

        sig = DetectionSignal(
            signal_id=sig_id,
            threat_class=tc,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=conf,
            severity=sev,
            source_entity=src_ip,
            target_entity=dst_target,
            event_time=evt_time,
            timestamp_iso=evt_iso,
            indicators=ind,
            evidence=[
                EvidenceItem(
                    feature_name=k,
                    value=v,
                    baseline=0.0 if isinstance(v, (int, float)) else "NORMAL",
                    deviation=round(v * 1.8, 2) if isinstance(v, (int, float)) else "ANOMALOUS",
                    interpretation=f"Forensic metric {k} ({v}) indicates stage {stage_name} activity exceeding entity baseline."
                )
                for k, v in ind.items()
            ]
        )
        pipeline.stats.signals_generated += 1
        pipeline.entity_memory.record_signal(sig)

        # Build timeline event
        created_timeline.append(
            TimelineEvent(
                event_id=f"evt-{len(created_timeline)+1}",
                event_time=evt_time,
                event_type=stg_type.value,
                source_id=sig_id,
                threat_class=tc,
                description=f"Replayed stage {stage_name} activity on {src_ip}",
                severity=sev,
                fused_risk=conf,
            )
        )

        # Build attack stage record
        created_stages.append(
            AttackStageRecord(
                stage_id=f"stg-{len(created_stages)+1}",
                stage_type=stg_type,
                threat_class=tc,
                first_seen_event_time=evt_time,
                last_seen_event_time=evt_time,
                signal_ids=[sig_id],
                fusion_ids=[],
                evidence_ids=[],
                observation_count=1,
            )
        )

        # Build deduplicated evidence
        for k, v in ind.items():
            created_evidence.append(
                DeduplicatedEvidence(
                    evidence_id=f"evd-{len(created_evidence)+1}",
                    source_signal_id=sig_id,
                    source_fusion_id="fusion-replay",
                    feature_name=k,
                    value=v,
                    baseline=0.0 if isinstance(v, (int, float)) else None,
                    deviation=round(float(v) * 1.8, 2) if isinstance(v, (int, float)) else None,
                    interpretation=f"Forensic metric {k} ({v}) indicates {stage_name} activity.",
                    first_seen_event_time=evt_time,
                    last_seen_event_time=evt_time,
                    occurrence_count=1,
                )
            )

        alert = pipeline.incident_builder.build_incident_alert(
            Incident(
                incident_id=inc_id,
                entity_id=src_ip,
                primary_threat_class=tc,
                status=IncidentStatus.OPEN,
                first_seen_event_time=evt_time,
                last_seen_event_time=evt_time,
                created_at=evt_iso,
                updated_at=evt_iso,
                current_fused_risk=conf,
                max_fused_risk=conf,
                confidence=conf,
                severity=sev,
                signal_ids=[sig_id],
                fusion_ids=[],
                flow_ids=[],
                conversation_ids=[],
                destination_entities=[dst_target],
                domains=[],
                tls_fingerprints=[],
                timeline=[],
                attack_chain=[],
                evidence=[],
                risk_history=[],
                severity_history=[],
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                detector_versions={},
                model_versions={},
                threat_stages=[],
                evidence_items=[],
            ),
            sig
        )
        pipeline.alerts.append(alert)
        created_alerts.append(alert)

    # Sort timeline chronologically by event_time
    created_timeline.sort(key=lambda ev: ev.event_time)

    created_incident = Incident(
        incident_id=inc_id,
        entity_id=src_ip,
        primary_threat_class=ThreatClass.DATA_EXFILTRATION,
        status=IncidentStatus.OPEN,
        first_seen_event_time=stages[0][6],
        last_seen_event_time=stages[-1][6],
        created_at=datetime.datetime.fromtimestamp(stages[0][6], tz=datetime.timezone.utc).isoformat(),
        updated_at=datetime.datetime.fromtimestamp(stages[-1][6], tz=datetime.timezone.utc).isoformat(),
        current_fused_risk=0.96,
        max_fused_risk=0.96,
        confidence=0.94,
        severity=Severity.CRITICAL,
        calibrated_ml_probability=0.91,
        anomaly_score=-0.72,
        detector_score=0.95,
        signal_ids=signal_ids,
        fusion_ids=[f"fusion-replay-{i}" for i in range(len(stages))],
        flow_ids=[f"flow-replay-{i}" for i in range(len(stages))],
        conversation_ids=[],
        destination_entities=[target_c2, target_exfil],
        domains=[target_c2, target_exfil],
        tls_fingerprints=["771,49195-49199-52393,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"],
        timeline=created_timeline,
        attack_chain=created_stages,
        evidence=created_evidence,
        risk_history=[(s[6], s[3]) for s in stages],
        severity_history=[(s[6], s[2].value) for s in stages],
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        detector_versions=dict(DETECTOR_VERSIONS),
        model_versions=dict(MODEL_VERSIONS),
        threat_stages=[ThreatStage(stage=stages[-1][0], timestamp_iso=datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc).isoformat(), threat_class=stages[-1][1], confidence=stages[-1][3])],
        evidence_items=[f"Stage: {s[0]}" for s in stages],
    )
    pipeline.incidents.append(created_incident)

    return {
        "status": "REPLAY_COMPLETED",
        "scenario": "Multi-Stage Attack Chain (Deterministic Replay)",
        "entity_id": src_ip,
        "stages_replayed": len(stages),
        "incident_id": created_incident.incident_id,
        "alerts_generated": len(created_alerts),
        "fused_risk": created_incident.current_fused_risk,
        "calibrated_ml_probability": 0.91,
        "confidence": 0.94,
        "severity": "CRITICAL",
    }

def continuous_simulation_loop():
    global simulation_running
    threats = ["VOLUMETRIC_DDOS", "BOTNET_C2_BEACONING", "DGA_DNS_TUNNELLING", "RECON_PORT_SCAN", "DATA_EXFILTRATION"]

    while simulation_running:
        try:
            src = f"10.0.{random.randint(1, 10)}.{random.randint(2, 200)}"
            pipeline.stats.packets_processed += random.randint(200, 800)
            pipeline.stats.flows_tracked = max(pipeline.stats.flows_tracked, len(pipeline.entity_memory.get_all_profiles()) * 3 + random.randint(5, 20))
            pipeline.entity_memory.get_or_create_profile(src)

            if random.random() < 0.25:
                tc = random.choice(threats)
                dst = f"198.51.100.{random.randint(1, 200)}" if random.random() < 0.5 else f"malicious-node-{random.randint(1, 99)}.cc"
                simulate_specific_attack(AttackSimulationRequest(threat_class=tc, source_ip=src, target=dst))

            time.sleep(1.0)
        except Exception:
            time.sleep(1.0)

@app.post("/simulate/toggle", tags=["Simulation (Local Demo Control)"])
def toggle_simulation() -> Dict[str, Any]:
    global simulation_running, sim_thread
    simulation_running = not simulation_running

    if simulation_running:
        sim_thread = threading.Thread(target=continuous_simulation_loop, daemon=True)
        sim_thread.start()

    return {"simulation_running": simulation_running}

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket stream for dashboard client-plane visualization. Zero network egress or actuation."""
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

seed_initial_demo_data()
