"""FastAPI REST & WebSocket Backend Service (Member 3).

Provides real-time threat intelligence feeds, incident dossiers, entity graphs,
streaming simulation, and PCAP replay endpoints for the SOC dashboard.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import os
import random
import asyncio
import threading
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from schemas import (
    Alert,
    Incident,
    EntityEvent,
    DetectionSignal,
    ThreatClass,
    Severity,
    DetectorType,
    FeatureVector,
    FlowFeatures as PydanticFlowFeatures,
)
from pipeline.integrated_runner import IntegratedThreatPipeline, PipelineStats
from entity.graph import NodeType, EdgeType

app = FastAPI(
    title="Unidirectional Threat Intelligence API (PS 26145)",
    description="Passive streaming cyber threat detection and multi-signal entity correlation layer.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global pipeline instance
pipeline = IntegratedThreatPipeline()

# Continuous simulation state
simulation_running = False
sim_thread: Optional[threading.Thread] = None


class ConnectionManager:
    """Manages real-time WebSocket client connections."""

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

# Mount dashboard static directory
dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")


def seed_initial_demo_data():
    """Seed rich baseline entity graph, signals, alerts and incidents on startup."""
    hosts = ["10.0.4.15", "10.0.4.88", "10.0.12.3", "192.168.10.45", "192.168.10.99"]
    external_targets = ["198.51.100.42", "203.0.113.8", "c2-hidden-master.onion.to", "exfil-drop.darknet.cc"]

    # 1. Establish benign topology
    for h in hosts:
        pipeline.entity_memory.get_or_create_profile(h)
        pipeline.entity_graph.add_node(h, NodeType.HOST_IP, {"role": "Monitored Enclave Host", "status": "ACTIVE"})
        pipeline.stats.packets_processed += random.randint(1200, 5000)
        pipeline.stats.flows_tracked += random.randint(4, 12)

    # 2. Inject seed attacks
    scenarios = [
        (
            "10.0.4.15",
            "198.51.100.42",
            ThreatClass.VOLUMETRIC_DDOS,
            0.96,
            Severity.CRITICAL,
            {"packets_per_sec": 18500.0, "syn_ratio": 0.99, "bytes_per_sec": 1184000.0},
        ),
        (
            "10.0.4.88",
            "c2-hidden-master.onion.to",
            ThreatClass.BOTNET_C2_BEACONING,
            0.92,
            Severity.HIGH,
            {"periodicity_score": 0.94, "jitter_pct": 2.1, "connection_count": 48},
        ),
        (
            "10.0.12.3",
            "exfil-drop.darknet.cc",
            ThreatClass.DATA_EXFILTRATION,
            0.89,
            Severity.HIGH,
            {"bytes_out": 48500000.0, "duration_sec": 12.5, "out_in_byte_ratio": 94.2},
        ),
        (
            "192.168.10.45",
            "10.0.4.0/24",
            ThreatClass.RECON_PORT_SCAN,
            0.85,
            Severity.MEDIUM,
            {"distinct_ports": 1024, "scan_rate_pps": 350.0},
        ),
    ]

    for src, dst, tc, conf, sev, indicators in scenarios:
        sig = DetectionSignal(
            signal_id=f"sig-{random.randint(1000, 9999)}",
            threat_class=tc,
            detector_type=DetectorType.LIGHTWEIGHT_ML if "C2" in tc.value else DetectorType.DETERMINISTIC_BASELINE,
            confidence=conf,
            severity=sev,
            source_entity=src,
            target_entity=dst,
            timestamp_iso=(datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 15))).isoformat(),
            indicators=indicators,
        )
        pipeline.stats.signals_generated += 1
        pipeline.entity_memory.record_signal(sig)
        group, risk, c_sev = pipeline.fusion_engine.process_signal(sig, pipeline.entity_memory, pipeline.entity_graph)
        incident = pipeline.incident_builder.build_incident_from_group(group, pipeline.entity_memory, pipeline.entity_graph)
        pipeline.incidents.append(incident)
        pipeline.stats.incidents_created += 1
        alert = pipeline.incident_builder.build_incident_alert(incident, sig)
        pipeline.alerts.append(alert)
        pipeline.stats.alerts_dispatched += 1


# Populate baseline immediately
seed_initial_demo_data()


@app.get("/", tags=["Dashboard"])
def get_dashboard():
    """Serve the SOC Web Dashboard."""
    index_file = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Unidirectional Threat Intelligence API is Running."}


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Return system operational status and active telemetry stats."""
    return {
        "status": "HEALTHY",
        "timestamp_iso": datetime.now(timezone.utc).isoformat(),
        "threat_classes_monitored": 7,
        "simulation_running": simulation_running,
        "stats": pipeline.stats.to_dict(),
        "active_entities_count": len(pipeline.entity_memory.get_all_profiles()),
        "total_alerts": len(pipeline.alerts),
        "total_incidents": len(pipeline.incidents),
    }


@app.get("/alerts", response_model=List[Alert], tags=["Alerts"])
def get_alerts(limit: int = Query(default=50, ge=1, le=1000)) -> List[Alert]:
    """Retrieve recent standardized security alerts."""
    return pipeline.alerts[-limit:]


@app.get("/alerts/{alert_id}", response_model=Alert, tags=["Alerts"])
def get_alert_by_id(alert_id: str) -> Alert:
    for alert in pipeline.alerts:
        if alert.alert_id == alert_id:
            return alert
    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/incidents", response_model=List[Incident], tags=["Incidents"])
def get_incidents(limit: int = Query(default=50, ge=1, le=1000)) -> List[Incident]:
    return list(pipeline.incident_builder.get_all_incidents().values())[-limit:]


@app.get("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
def get_incident_by_id(incident_id: str) -> Incident:
    incident = pipeline.incident_builder.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


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


@app.get("/graph", tags=["Graph"])
def get_entity_graph() -> Dict[str, Any]:
    return pipeline.entity_graph.export_d3_format()


@app.get("/graph/entity/{entity_id}", tags=["Graph"])
def get_entity_subgraph(entity_id: str, depth: int = Query(default=2, ge=1, le=4)) -> Dict[str, Any]:
    return pipeline.entity_graph.get_entity_subgraph(entity_id=entity_id, max_depth=depth)


class AttackSimulationRequest(BaseModel):
    threat_class: str = "VOLUMETRIC_DDOS"
    source_ip: Optional[str] = None
    target: Optional[str] = None


@app.post("/simulate/attack", tags=["Simulation"])
def simulate_specific_attack(req: AttackSimulationRequest) -> Dict[str, Any]:
    """Inject an instant high-fidelity cyber threat attack scenario into the streaming pipeline."""
    src = req.source_ip or f"10.0.{random.randint(1, 20)}.{random.randint(2, 254)}"
    dst = req.target or f"198.51.100.{random.randint(1, 250)}"

    threat_class_map = {
        "VOLUMETRIC_DDOS": (ThreatClass.VOLUMETRIC_DDOS, Severity.CRITICAL, 0.97, {"packets_per_sec": 24000.0, "syn_ratio": 0.99, "bytes_per_sec": 1536000.0}),
        "BOTNET_C2_BEACONING": (ThreatClass.BOTNET_C2_BEACONING, Severity.HIGH, 0.93, {"periodicity_score": 0.96, "jitter_pct": 1.8, "connection_count": 64}),
        "DGA_DNS_TUNNELLING": (ThreatClass.DGA_DNS_TUNNELLING, Severity.HIGH, 0.91, {"shannon_entropy": 4.62, "query_rate_per_sec": 120.0, "subdomain_length": 34}),
        "ENCRYPTED_MALWARE": (ThreatClass.ENCRYPTED_MALWARE, Severity.HIGH, 0.88, {"ja3_hash": "771,49195-49199-52393,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0", "tls_flow_ratio": 0.92}),
        "RECON_PORT_SCAN": (ThreatClass.RECON_PORT_SCAN, Severity.MEDIUM, 0.86, {"distinct_ports": 2048, "scan_rate_pps": 850.0}),
        "DATA_EXFILTRATION": (ThreatClass.DATA_EXFILTRATION, Severity.CRITICAL, 0.94, {"bytes_out": 128000000.0, "duration_sec": 8.0, "out_in_byte_ratio": 150.0}),
        "UNKNOWN_ANOMALY": (ThreatClass.UNKNOWN_ANOMALY, Severity.HIGH, 0.82, {"isolation_forest_score": -0.68, "anomaly_vector_dim": 14}),
    }

    entry = threat_class_map.get(req.threat_class.upper(), threat_class_map["VOLUMETRIC_DDOS"])
    tc, sev, conf, indicators = entry

    # Update pipeline stats
    pipeline.stats.packets_processed += random.randint(500, 2500)
    pipeline.stats.flows_tracked += random.randint(1, 5)

    sig = DetectionSignal(
        signal_id=f"sig-{random.randint(10000, 99999)}",
        threat_class=tc,
        detector_type=DetectorType.LIGHTWEIGHT_ML if "C2" in tc.value else DetectorType.DETERMINISTIC_BASELINE,
        confidence=conf,
        severity=sev,
        source_entity=src,
        target_entity=dst,
        timestamp_iso=datetime.now(timezone.utc).isoformat(),
        indicators=indicators,
    )

    pipeline.stats.signals_generated += 1
    pipeline.entity_memory.record_signal(sig)
    group, risk, c_sev = pipeline.fusion_engine.process_signal(sig, pipeline.entity_memory, pipeline.entity_graph)
    incident = pipeline.incident_builder.build_incident_from_group(group, pipeline.entity_memory, pipeline.entity_graph)
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


def continuous_simulation_loop():
    """Background continuous traffic & telemetry generation."""
    global simulation_running
    threats = ["VOLUMETRIC_DDOS", "BOTNET_C2_BEACONING", "DGA_DNS_TUNNELLING", "RECON_PORT_SCAN", "DATA_EXFILTRATION"]
    
    while simulation_running:
        try:
            # Generate benign flow
            src = f"10.0.{random.randint(1, 10)}.{random.randint(2, 200)}"
            pipeline.stats.packets_processed += random.randint(200, 800)
            pipeline.stats.flows_tracked = max(pipeline.stats.flows_tracked, len(pipeline.entity_memory.get_all_profiles()) * 3 + random.randint(5, 20))
            pipeline.entity_memory.get_or_create_profile(src)

            # Random attack injection (15% chance per second)
            if random.random() < 0.25:
                tc = random.choice(threats)
                dst = f"198.51.100.{random.randint(1, 200)}" if random.random() < 0.5 else f"malicious-node-{random.randint(1, 99)}.cc"
                simulate_specific_attack(AttackSimulationRequest(threat_class=tc, source_ip=src, target=dst))

            time.sleep(1.0)
        except Exception as e:
            time.sleep(1.0)


@app.post("/simulate/toggle", tags=["Simulation"])
def toggle_simulation() -> Dict[str, Any]:
    """Toggle continuous background live traffic simulation."""
    global simulation_running, sim_thread
    simulation_running = not simulation_running

    if simulation_running:
        sim_thread = threading.Thread(target=continuous_simulation_loop, daemon=True)
        sim_thread.start()

    return {"simulation_running": simulation_running}


@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
