// Client-Side Application Logic for Unidirectional Threat Intelligence Dashboard

const API_BASE = window.location.origin;

// State
let alertsData = [];
let incidentsData = [];
let graphData = { nodes: [], links: [] };

// DOM Elements
const kpiPackets = document.getElementById("kpiPackets");
const kpiPps = document.getElementById("kpiPps");
const kpiFlows = document.getElementById("kpiFlows");
const kpiSignals = document.getElementById("kpiSignals");
const kpiIncidents = document.getElementById("kpiIncidents");
const kpiEntities = document.getElementById("kpiEntities");
const alertList = document.getElementById("alertList");
const incidentTableBody = document.getElementById("incidentTableBody");
const filterThreatClass = document.getElementById("filterThreatClass");
const graphCanvas = document.getElementById("graphCanvas");

// Fetch System Health and KPIs
async function fetchHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) return;
    const data = await res.json();
    
    if (data.stats) {
      kpiPackets.innerText = data.stats.packets_processed.toLocaleString();
      kpiPps.innerText = `${data.stats.packets_per_second} pps`;
      kpiFlows.innerText = data.stats.flows_tracked.toLocaleString();
      kpiSignals.innerText = data.stats.signals_generated.toLocaleString();
      kpiIncidents.innerText = data.stats.incidents_created.toLocaleString();
    }
    kpiEntities.innerText = data.active_entities_count || 0;
  } catch (err) {
    console.error("Health check error:", err);
  }
}

// Fetch Alerts
async function fetchAlerts() {
  try {
    const res = await fetch(`${API_BASE}/alerts?limit=50`);
    if (!res.ok) return;
    alertsData = await res.json();
    renderAlerts();
  } catch (err) {
    console.error("Fetch alerts error:", err);
  }
}

// Render Alert List
function renderAlerts() {
  const filter = filterThreatClass.value;
  const filtered = filter === "ALL" 
    ? alertsData 
    : alertsData.filter(a => a.threat_class === filter);

  if (filtered.length === 0) {
    alertList.innerHTML = `<div class="empty-state">No matching alerts observed.</div>`;
    return;
  }

  alertList.innerHTML = filtered.slice().reverse().map(alert => `
    <div class="alert-item ${alert.severity}">
      <div class="alert-item-header">
        <span class="threat-name">${alert.threat_class.replace(/_/g, " ")}</span>
        <span class="badge ${alert.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${alert.severity} (${(alert.confidence * 100).toFixed(0)}%)</span>
      </div>
      <div class="alert-item-summary">${alert.summary}</div>
      <div class="text-muted" style="font-size: 10px; font-family: monospace;">
        Src: ${alert.source_ip} &bull; ${new Date(alert.timestamp_iso).toLocaleTimeString()}
      </div>
    </div>
  `).join("");
}

// Fetch Incidents
async function fetchIncidents() {
  try {
    const res = await fetch(`${API_BASE}/incidents?limit=50`);
    if (!res.ok) return;
    incidentsData = await res.json();
    renderIncidents();
  } catch (err) {
    console.error("Fetch incidents error:", err);
  }
}

// Render Incident Table
function renderIncidents() {
  if (incidentsData.length === 0) {
    incidentTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No correlated incidents created yet.</td></tr>`;
    return;
  }

  incidentTableBody.innerHTML = incidentsData.slice().reverse().map(inc => `
    <tr>
      <td><code>${inc.incident_id}</code></td>
      <td><strong>${inc.primary_entity}</strong></td>
      <td><span class="badge badge-danger">${(inc.risk_score * 100).toFixed(0)}%</span></td>
      <td><span class="badge ${inc.overall_severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${inc.overall_severity}</span></td>
      <td>${inc.threat_stages ? inc.threat_stages.map(s => `<span class="badge" style="margin-right:4px;">${s.stage}</span>`).join("") : "1 Stage"}</td>
      <td>${inc.evidence_items ? inc.evidence_items.slice(0, 2).join("<br>") : "Automated signal"}</td>
      <td><button class="btn btn-primary" onclick="viewIncident('${inc.incident_id}')" style="padding: 4px 8px; font-size: 11px;">Inspect</button></td>
    </tr>
  `).join("");
}

// Fetch Graph Data & Render Canvas
async function fetchGraph() {
  try {
    const res = await fetch(`${API_BASE}/graph`);
    if (!res.ok) return;
    graphData = await res.json();
    drawGraph();
  } catch (err) {
    console.error("Fetch graph error:", err);
  }
}

// Simple Force Simulation Canvas Renderer
function drawGraph() {
  if (!graphCanvas) return;
  const ctx = graphCanvas.getContext("2d");
  const width = graphCanvas.parentElement.clientWidth;
  const height = graphCanvas.parentElement.clientHeight;
  graphCanvas.width = width;
  graphCanvas.height = height;

  ctx.clearRect(0, 0, width, height);

  const nodes = graphData.nodes || [];
  const links = graphData.links || [];

  if (nodes.length === 0) {
    ctx.fillStyle = "#64748b";
    ctx.font = "12px Inter";
    ctx.textAlign = "center";
    ctx.fillText("Entity Behaviour Graph nodes will appear as traffic is correlated.", width / 2, height / 2);
    return;
  }

  // Position nodes radially / grid if unpositioned
  const positions = {};
  const radius = Math.min(width, height) * 0.35;
  nodes.forEach((n, idx) => {
    const angle = (idx / nodes.length) * 2 * Math.PI;
    positions[n.id] = {
      x: width / 2 + radius * Math.cos(angle) + (Math.sin(idx * 3) * 20),
      y: height / 2 + radius * Math.sin(angle) + (Math.cos(idx * 3) * 20),
    };
  });

  // Draw Links
  ctx.strokeStyle = "rgba(255, 255, 255, 0.15)";
  ctx.lineWidth = 1.5;
  links.forEach(link => {
    const src = positions[link.source];
    const tgt = positions[link.target];
    if (src && tgt) {
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();
    }
  });

  // Draw Nodes
  nodes.forEach(n => {
    const pos = positions[n.id];
    if (!pos) return;

    ctx.beginPath();
    ctx.arc(pos.x, pos.y, 8, 0, 2 * Math.PI);
    if (n.type === "HOST_IP") ctx.fillStyle = "#00e5ff";
    else if (n.type === "SIGNAL") ctx.fillStyle = "#f59e0b";
    else if (n.type === "INCIDENT") ctx.fillStyle = "#ef4444";
    else ctx.fillStyle = "#8b5cf6";
    ctx.fill();

    // Node Label
    ctx.fillStyle = "#f0f4f8";
    ctx.font = "10px JetBrains Mono";
    ctx.textAlign = "center";
    ctx.fillText(n.id, pos.x, pos.y + 16);
  });
}

// Modal inspection
window.viewIncident = function(incidentId) {
  const inc = incidentsData.find(i => i.incident_id === incidentId);
  if (!inc) return;

  const modal = document.getElementById("incidentModal");
  const modalTitle = document.getElementById("modalIncidentTitle");
  const modalBody = document.getElementById("modalIncidentBody");

  modalTitle.innerText = `Incident Dossier: ${inc.incident_id}`;
  modalBody.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:12px; font-size:13px;">
      <div><strong>Primary Entity:</strong> <code>${inc.primary_entity}</code></div>
      <div><strong>Risk Score:</strong> ${(inc.risk_score * 100).toFixed(1)}% &bull; <strong>Severity:</strong> ${inc.overall_severity}</div>
      <div><strong>Timeline:</strong> ${inc.first_seen_iso} &rarr; ${inc.last_seen_iso}</div>
      <div><strong>Recommended Action:</strong> <p style="color:#00e5ff; margin-top:4px;">${inc.recommended_action || "Forensic host inspection"}</p></div>
      <div>
        <strong>Supporting Evidence Chain:</strong>
        <ul style="margin-top:6px; padding-left:20px; color:#94a3b8;">
          ${(inc.evidence_items || []).map(e => `<li>${e}</li>`).join("")}
        </ul>
      </div>
    </div>
  `;
  modal.style.display = "flex";
};

document.getElementById("btnModalClose").onclick = () => {
  document.getElementById("incidentModal").style.display = "none";
};

// Event Listeners
filterThreatClass.addEventListener("change", renderAlerts);
window.addEventListener("resize", drawGraph);

// Initial Load & Polling Loop
fetchHealth();
fetchAlerts();
fetchIncidents();
fetchGraph();

setInterval(() => {
  fetchHealth();
  fetchAlerts();
  fetchIncidents();
  fetchGraph();
}, 2000);
