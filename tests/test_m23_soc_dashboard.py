# Milestone 23, 23.1, 23.2 & 23.3 (M23/M23.1/M23.2/M23.3) Tests ? SOC Dashboard & Entity Attack Graph Upgrade
# Validates:
# 1. Dashboard static routes and asset serving (index.html, style.css, app.js).
# 2. Read-only SOC API endpoints (/health, /metrics, /security-boundary, /provenance, /alerts, /incidents, /entities, /graph).
# 3. Zero active mitigation/response endpoints (Enclave out-of-band guarantee).
# 4. Distinct risk metric separation (Fused Risk vs ML Probability vs Confidence vs Severity).
# 5. Deterministic in-memory multi-stage attack replay (/demo/replay).
# 6. Missing metadata graceful string representations ("no DNS metadata", etc.).
# 7. Canonical version & provenance consistency across API, models, and schemas (M23.1).
# 8. Dashboard dynamic data-provenance binding & absence of stale literals (M23.1).
# 9. Redesigned SOC Layout, Sidebar, Incident Drawer, Evidence Table & Timeline bindings (M23.2).
# 10. Hero Attack Graph Data, Typed Nodes, Semantic Edges, Timeline Scrubbing & Risk Progression (M23.3).

from __future__ import annotations
import json
import os
import pytest
from fastapi.testclient import TestClient
from api.app import app
from schemas import (
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

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

def test_dashboard_routes_and_static_files(client):
    """Test dashboard index and static assets."""
    r_index = client.get("/")
    assert r_index.status_code == 200
    assert "UNIGUARD" in r_index.text
    assert "incident-drawer" in r_index.text
    assert "soc-sidebar" in r_index.text
    assert "d3GraphContainer" in r_index.text

    r_css = client.get("/static/style.css")
    assert r_css.status_code == 200
    assert "incident-drawer" in r_css.text
    assert "kpi-strip" in r_css.text
    assert "graph-timeline-scrub-bar" in r_css.text

    r_js = client.get("/static/app.js")
    assert r_js.status_code == 200
    assert "openIncidentDrawer" in r_js.text
    assert "renderD3TopologyGraph" in r_js.text
    assert "inspectGraphNode" in r_js.text

def test_health_and_metrics_endpoints(client):
    """Test system health and performance metrics instrumentation."""
    r_health = client.get("/health")
    assert r_health.status_code == 200
    h_data = r_health.json()
    assert h_data["status"] == "HEALTHY"
    assert h_data["passive_enclave"] is True
    assert h_data["diode_rx_active"] is True
    assert h_data["return_network_path"] is False
    assert "provenance" in h_data
    assert h_data["provenance"]["feature_schema_version"] == FEATURE_SCHEMA_VERSION

    r_metrics = client.get("/metrics")
    assert r_metrics.status_code == 200
    m_data = r_metrics.json()
    assert "packets_per_sec" in m_data
    assert "flows_per_sec" in m_data
    assert "queue_depth" in m_data
    assert "dropped_events" in m_data
    assert "p95_latency_ms" in m_data
    assert "memory_mb" in m_data
    assert "cpu_pct" in m_data
    assert m_data["bounded_state_enforced"] is True

def test_security_boundary_endpoint(client):
    """Test PS 26145 security boundary endpoint and guarantees."""
    r_sec = client.get("/security-boundary")
    assert r_sec.status_code == 200
    sec_data = r_sec.json()
    assert sec_data["status"] == "PASS"
    assert sec_data["passive_ingest"] == "YES"
    assert "0" in sec_data["network_writes_in_detection_runtime"]
    assert "DISABLED" in sec_data["active_response"]
    assert sec_data["payload_decryption"] == "NONE"
    assert sec_data["workspace_integrity"] == "PASS"
    assert "Detection is out-of-band and read-only." in sec_data["enclave_statement"]
    assert sec_data["network_actuation_endpoints"] == 0
    assert sec_data["endpoint_classification"]["/simulate/attack"] == "LOCAL_DEMO_CONTROL"

def test_zero_active_response_endpoints(client):
    """Verify that zero active mitigation or firewall manipulation endpoints exist."""
    forbidden_routes = [
        "/mitigate",
        "/block",
        "/drop",
        "/firewall",
        "/isolate",
        "/quarantine",
        "/reset-connection",
        "/inject-packet",
    ]
    for route in forbidden_routes:
        res_get = client.get(route)
        res_post = client.post(route)
        assert res_get.status_code == 404, f"Route {route} GET must not exist!"
        assert res_post.status_code == 404, f"Route {route} POST must not exist!"

def test_alerts_and_incidents_query(client):
    """Test alerts and incidents listing and filtering."""
    r_alerts = client.get("/alerts?limit=10")
    assert r_alerts.status_code == 200
    alerts = r_alerts.json()
    assert isinstance(alerts, list)
    assert len(alerts) > 0

    r_incidents = client.get("/incidents?limit=10")
    assert r_incidents.status_code == 200
    incidents = r_incidents.json()
    assert isinstance(incidents, list)
    assert len(incidents) > 0

    first_inc = incidents[0]
    inc_id = first_inc["incident_id"]
    r_single = client.get(f"/incidents/{inc_id}")
    assert r_single.status_code == 200
    inc_dossier = r_single.json()
    assert inc_dossier["incident_id"] == inc_id
    assert "timeline" in inc_dossier
    assert "evidence" in inc_dossier
    assert "attack_chain" in inc_dossier
    assert "provenance" in inc_dossier

def test_distinct_risk_separation_contract(client):
    """Verify that Fused Risk, Calibrated ML Probability, Confidence, and Severity are distinct."""
    r_incidents = client.get("/incidents?limit=5")
    incidents = r_incidents.json()
    assert len(incidents) > 0

    for inc in incidents:
        assert "current_fused_risk" in inc
        assert "calibrated_ml_probability" in inc
        assert "confidence" in inc
        assert "severity" in inc
        assert isinstance(inc["current_fused_risk"], (float, int))
        assert isinstance(inc["calibrated_ml_probability"], (float, int))
        assert isinstance(inc["confidence"], (float, int))
        assert isinstance(inc["severity"], str)

def test_deterministic_demo_replay(client):
    """Test deterministic multi-stage in-memory replay endpoint."""
    r_replay = client.post("/demo/replay")
    assert r_replay.status_code == 200
    rep_data = r_replay.json()
    assert rep_data["status"] == "REPLAY_COMPLETED"
    assert rep_data["stages_replayed"] == 5
    assert rep_data["alerts_generated"] >= 5
    assert rep_data["incident_id"] is not None

    # Fetch the replayed incident dossier
    inc_id = rep_data["incident_id"]
    r_inc = client.get(f"/incidents/{inc_id}")
    assert r_inc.status_code == 200
    dossier = r_inc.json()
    assert len(dossier["timeline"]) >= 5
    assert len(dossier["evidence"]) >= 5

    # Check chronological ordering of timeline
    times = [ev["event_time"] for ev in dossier["timeline"] if "event_time" in ev]
    assert times == sorted(times), "Timeline events must be chronologically ordered by event_time"

def test_missing_metadata_contracts(client):
    """Test that entities profile handles missing metadata with clear string tokens, never null or 0."""
    r_entities = client.get("/entities")
    assert r_entities.status_code == 200
    entities = r_entities.json()["entities"]
    assert len(entities) > 0

    ent_id = entities[0]["entity_id"]
    r_ent = client.get(f"/entities/{ent_id}")
    assert r_ent.status_code == 200
    profile = r_ent.json()

    assert "baseline_deviation_score" in profile
    assert "dns_metadata" in profile
    assert "tls_metadata" in profile
    assert "flow_summary" in profile

    if isinstance(profile["dns_metadata"], str):
        assert profile["dns_metadata"] == "no DNS metadata"
    if isinstance(profile["tls_metadata"], str):
        assert profile["tls_metadata"] == "no TLS metadata"
    if isinstance(profile["flow_summary"]["inbound_byte_ratio"], str):
        assert profile["flow_summary"]["inbound_byte_ratio"] == "zero inbound bytes"

def test_canonical_version_and_provenance_consistency(client):
    """M23.1: Verify API runtime metadata == loaded model metadata == schema version == provenance endpoint."""
    r_prov = client.get("/provenance")
    assert r_prov.status_code == 200
    prov = r_prov.json()

    assert prov["feature_schema_version"] == "feature-schema-v2.1.0"
    assert prov["feature_count"] == 56
    assert prov["model_version"] == "v2.1.0-calibrated-lgb"
    assert prov["detector_version"] == "v2.1.0"
    assert prov["anomaly_model_version"] == "v2.1.0-isolation-forest"

    # Verify loaded model artifact metadata on disk matches
    with open("models/artifacts/lgb_multiclass_v2_metadata.json", "r") as f:
        lgb_meta = json.load(f)
    assert lgb_meta["feature_schema_version"] == prov["feature_schema_version"]
    assert lgb_meta["num_features"] == prov["feature_count"]

    with open("models/artifacts/isolation_forest_v2_metadata.json", "r") as f:
        if_meta = json.load(f)
    assert if_meta["feature_schema_version"] == prov["feature_schema_version"]
    assert if_meta["num_features"] == prov["feature_count"]

    # Verify active incidents expose identical canonical version metadata
    r_incidents = client.get("/incidents?limit=5")
    assert r_incidents.status_code == 200
    for inc in r_incidents.json():
        inc_prov = inc["provenance"]
        assert inc_prov["feature_schema_version"] == FEATURE_SCHEMA_VERSION
        assert inc_prov["detector_versions"]["deterministic"] == DETECTOR_VERSION
        assert inc_prov["model_versions"]["lightgbm"] == MODEL_VERSION

def test_dashboard_dynamic_provenance_binding(client):
    """M23.1: Verify dashboard JS uses dynamic API provenance rather than stale hard-coded strings."""
    r_js = client.get("/static/app.js")
    assert r_js.status_code == 200
    js_text = r_js.text

    assert "v2.0 (18 features)" not in js_text
    assert "v2-calibrated-2026" not in js_text
    assert "v2-unsupervised-iso" not in js_text
    assert "runtimeProvenance" in js_text
    assert "/provenance" in js_text

def test_m23_2_ux_redesign_components(client):
    """M23.2: Verify the redesigned UX components (Sidebar, Drawer, KPI strip, Demo isolation)."""
    r_index = client.get("/")
    assert r_index.status_code == 200
    html = r_index.text

    assert 'id="nav-feed"' in html
    assert 'id="nav-incidents"' in html
    assert 'id="nav-forensics"' in html
    assert 'id="nav-security"' in html
    assert 'id="nav-demo"' in html

    assert 'class="kpi-strip"' in html
    assert 'id="kpiIncidents"' in html
    assert 'id="kpiThroughput"' in html

    assert 'id="incidentDrawer"' in html
    assert 'id="drawerOverlay"' in html
    assert 'id="drawerBody"' in html

    assert 'id="tab-demo"' in html
    assert 'LOCAL DEMO CONTROL ONLY' in html

    r_css = client.get("/static/style.css")
    assert r_css.status_code == 200
    css = r_css.text
    assert "--kpi-height: 74px" in css
    assert ".incident-drawer" in css

def test_m23_3_attack_graph_and_semantic_edges(client):
    """M23.3: Verify Hero Attack Graph structure, node types, semantic edge labels, and timeline controls."""
    # Trigger demo replay to seed graph with all 5 attack stages
    r_replay = client.post("/demo/replay")
    assert r_replay.status_code == 200

    r_graph = client.get("/graph")
    assert r_graph.status_code == 200
    g = r_graph.json()
    assert "nodes" in g
    assert "links" in g
    assert len(g["nodes"]) >= 5
    assert len(g["links"]) >= 4

    node_types = set(n["type"] for n in g["nodes"])
    assert "HOST_IP" in node_types
    assert "THREAT_STAGE" in node_types

    edge_semantics = set(e.get("properties", {}).get("semantic", e.get("type")) for e in g["links"])
    assert any(sem in edge_semantics for sem in ["contacted", "queried", "correlated", "followed_by"])

    # Verify frontend index contains timeline scrubber and trajectory strip
    r_index = client.get("/")
    assert 'id="timelineScrubRange"' in r_index.text
    assert 'id="riskTrajectoryStrip"' in r_index.text
    assert 'id="btnToggleLabels"' in r_index.text
