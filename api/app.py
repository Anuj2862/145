"""FastAPI REST & WebSocket Backend Service (Member 3).

Provides real-time threat intelligence feeds, incident dossiers, entity graphs,
and streaming replay endpoints for the SOC dashboard and external SIEM ingestion.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import os
import json
import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from schemas import Alert, Incident, EntityEvent
from pipeline.integrated_runner import IntegratedThreatPipeline, PipelineStats

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


@app.get("/", tags=["Dashboard"])
def get_dashboard():
    """Serve the SOC Web Dashboard."""
    index_file = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Unidirectional Threat Intelligence API is Running. (Dashboard index not found)"}


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Return system operational status and active telemetry stats."""
    return {
        "status": "HEALTHY",
        "timestamp_iso": datetime.now(timezone.utc).isoformat(),
        "threat_classes_monitored": 7,
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
    """Retrieve a specific alert by ID."""
    for alert in pipeline.alerts:
        if alert.alert_id == alert_id:
            return alert
    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/incidents", response_model=List[Incident], tags=["Incidents"])
def get_incidents(limit: int = Query(default=50, ge=1, le=1000)) -> List[Incident]:
    """Retrieve correlated incident dossiers."""
    return list(pipeline.incident_builder.get_all_incidents().values())[-limit:]


@app.get("/incidents/{incident_id}", response_model=Incident, tags=["Incidents"])
def get_incident_by_id(incident_id: str) -> Incident:
    """Retrieve an incident dossier by ID."""
    incident = pipeline.incident_builder.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.get("/entities", tags=["Entities"])
def get_entities() -> Dict[str, Any]:
    """Retrieve summary profiles of all actively monitored entities."""
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
            }
            for p in profiles.values()
        ],
    }


@app.get("/graph", tags=["Graph"])
def get_entity_graph() -> Dict[str, Any]:
    """Export the Entity Behaviour Graph in standard D3 force-directed JSON format."""
    return pipeline.entity_graph.export_d3_format()


@app.get("/graph/entity/{entity_id}", tags=["Graph"])
def get_entity_subgraph(entity_id: str, depth: int = Query(default=2, ge=1, le=4)) -> Dict[str, Any]:
    """Retrieve neighborhood subgraph for an entity."""
    return pipeline.entity_graph.get_entity_subgraph(entity_id=entity_id, max_depth=depth)


class ReplayRequest(BaseModel):
    pcap_path: str


@app.post("/pipeline/replay", tags=["Pipeline"])
def trigger_pcap_replay(req: ReplayRequest) -> Dict[str, Any]:
    """Run an offline PCAP capture through the full threat detection and correlation pipeline."""
    try:
        stats = pipeline.process_pcap(req.pcap_path)
        return {
            "status": "SUCCESS",
            "pcap_path": req.pcap_path,
            "stats": stats.to_dict(),
            "new_alerts_count": len(pipeline.alerts),
            "new_incidents_count": len(pipeline.incidents),
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time streaming WebSocket feed for live SOC dashboard visualization."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keepalive / ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
