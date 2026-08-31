// ==========================================================================
// UniGuard AI — SOC Command Center Interactive Client Engine
// ==========================================================================

const API_BASE = window.location.origin;

// State
let alerts = [];
let incidents = [];
let graphData = { nodes: [], links: [] };
let audioEnabled = true;
let isStreaming = false;

// Audio Synthesizer for Tactical SOC Chimes
let audioCtx = null;
function playAlertChime(severity) {
  if (!audioEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    const freq = severity === "CRITICAL" ? 880 : severity === "HIGH" ? 660 : 440;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    osc.type = "sine";
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.35);

    osc.start();
    osc.stop(audioCtx.currentTime + 0.35);
  } catch (e) {}
}

function toggleAudio() {
  audioEnabled = !audioEnabled;
  const btn = document.getElementById("btnAudioToggle");
  btn.innerText = audioEnabled ? "🔔 SOUND ON" : "🔕 SOUND OFF";
  btn.style.color = audioEnabled ? "#00f0ff" : "#8493a8";
}

// --------------------------------------------------------------------------
// 1. Attack Simulator Controller
// --------------------------------------------------------------------------
async function injectAttack(threatClass) {
  try {
    const res = await fetch(`${API_BASE}/simulate/attack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ threat_class: threatClass }),
    });
    if (res.ok) {
      const data = await res.json();
      playAlertChime("CRITICAL");
      triggerAttackSpike();
      refreshAll();
    }
  } catch (e) {
    console.error("Attack injection error:", e);
  }
}

async function toggleContinuousStream() {
  try {
    const res = await fetch(`${API_BASE}/simulate/toggle`, { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      isStreaming = data.simulation_running;
      const btn = document.getElementById("btnToggleSim");
      btn.innerText = isStreaming ? "⏹️ PAUSE STREAM" : "▶️ LIVE STREAM";
      btn.style.background = isStreaming ? "linear-gradient(135deg, #ff0055, #9d4edd)" : "linear-gradient(135deg, #00f0ff, #0077b6)";
    }
  } catch (e) {
    console.error("Toggle simulation error:", e);
  }
}

// --------------------------------------------------------------------------
// 2. Telemetry & Health Polling
// --------------------------------------------------------------------------
async function fetchHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) return;
    const data = await res.json();

    if (data.stats) {
      document.getElementById("statPackets").innerText = data.stats.packets_processed.toLocaleString();
      document.getElementById("statPps").innerText = `${data.stats.packets_per_second.toFixed(1)} pps`;
      document.getElementById("statFlows").innerText = data.stats.flows_tracked.toLocaleString();
      document.getElementById("statSignals").innerText = data.stats.signals_generated.toLocaleString();
      document.getElementById("statIncidents").innerText = data.stats.incidents_created.toLocaleString();
    }
    document.getElementById("statEntities").innerText = data.active_entities_count || 0;
  } catch (e) {}
}

// --------------------------------------------------------------------------
// 3. Live Alert Feed
// --------------------------------------------------------------------------
let previousAlertCount = 0;

async function fetchAlerts() {
  try {
    const res = await fetch(`${API_BASE}/alerts?limit=50`);
    if (!res.ok) return;
    alerts = await res.json();
    
    if (alerts.length > previousAlertCount && previousAlertCount > 0) {
      const newest = alerts[alerts.length - 1];
      playAlertChime(newest.severity);
    }
    previousAlertCount = alerts.length;
    renderAlertFeed();
  } catch (e) {}
}

function renderAlertFeed() {
  const container = document.getElementById("feedScroll");
  const filter = document.getElementById("feedFilter").value;

  let filtered = alerts.slice().reverse();
  if (filter === "CRITICAL") filtered = filtered.filter(a => a.severity === "CRITICAL");
  else if (filter === "HIGH") filtered = filtered.filter(a => a.severity === "CRITICAL" || a.severity === "HIGH");
  else if (filter !== "ALL") filtered = filtered.filter(a => a.threat_class === filter);

  if (filtered.length === 0) {
    container.innerHTML = `<div style="padding:40px; text-align:center; color:#4b586e; font-size:12px;">No active alerts matching filter.</div>`;
    return;
  }

  container.innerHTML = filtered.map(a => {
    const badgeClass = a.severity === "CRITICAL" ? "badge-crit" : a.severity === "HIGH" ? "badge-hi" : "badge-med";
    const timeStr = new Date(a.timestamp_iso).toLocaleTimeString();
    return `
      <div class="feed-item ${a.severity}">
        <div class="feed-top">
          <span class="feed-threat">${a.threat_class.replace(/_/g, " ")}</span>
          <span class="feed-badge ${badgeClass}">${a.severity} (${(a.confidence * 100).toFixed(0)}%)</span>
        </div>
        <div class="feed-summary">${a.summary}</div>
        <div class="feed-meta">
          <span>SRC: ${a.source_ip}</span>
          <span>${timeStr}</span>
        </div>
      </div>
    `;
  }).join("");
}

// --------------------------------------------------------------------------
// 4. Incident Dossiers & MITRE Chains
// --------------------------------------------------------------------------
async function fetchIncidents() {
  try {
    const res = await fetch(`${API_BASE}/incidents?limit=50`);
    if (!res.ok) return;
    incidents = await res.json();
    renderIncidentsTable();
  } catch (e) {}
}

function renderIncidentsTable() {
  const tbody = document.getElementById("incidentsBody");
  if (incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#4b586e; padding:30px;">No correlated incidents registered.</td></tr>`;
    return;
  }

  tbody.innerHTML = incidents.slice().reverse().map(inc => {
    const riskPct = (inc.risk_score * 100).toFixed(0);
    const stagesHtml = (inc.threat_stages || []).map(s => `<span class="stage-pill">${s.stage}</span>`).join("") || `<span class="stage-pill">INITIAL_ACCESS</span>`;
    const evidenceHtml = (inc.evidence_items || []).slice(0, 2).map(e => `<div class="evidence-item-tag">${e}</div>`).join("") || "Automated signature match";

    return `
      <tr>
        <td class="id-cell">${inc.incident_id}</td>
        <td class="host-cell">${inc.primary_entity}</td>
        <td><strong style="color:${inc.risk_score >= 0.85 ? '#ff0055' : '#ffb703'};">${riskPct}%</strong></td>
        <td><span class="feed-badge ${inc.overall_severity === 'CRITICAL' ? 'badge-crit' : 'badge-hi'}">${inc.overall_severity}</span></td>
        <td>${stagesHtml}</td>
        <td><div class="evidence-preview">${evidenceHtml}</div></td>
        <td><button class="btn-inspect" onclick="openModal('${inc.incident_id}')">INSPECT</button></td>
      </tr>
    `;
  }).join("");
}

// --------------------------------------------------------------------------
// 5. Forensic Modal
// --------------------------------------------------------------------------
window.openModal = function(incidentId) {
  const inc = incidents.find(i => i.incident_id === incidentId);
  if (!inc) return;

  document.getElementById("mIncidentId").innerText = inc.incident_id;
  document.getElementById("mHost").innerText = inc.primary_entity;
  document.getElementById("mRisk").innerText = `${(inc.risk_score * 100).toFixed(1)}% • ${inc.overall_severity}`;
  document.getElementById("mTimeline").innerText = `${new Date(inc.first_seen_iso).toLocaleTimeString()} → ${new Date(inc.last_seen_iso).toLocaleTimeString()}`;
  document.getElementById("mDirective").innerText = inc.recommended_action || "Isolate host and perform forensic inspection.";

  const evList = document.getElementById("mEvidenceList");
  evList.innerHTML = (inc.evidence_items || []).map(e => `
    <div class="evidence-item-tag">⚡ ${e}</div>
  `).join("") || "<div>Baseline anomaly recorded.</div>";

  document.getElementById("dossierModal").style.display = "flex";
};

window.closeModal = function() {
  document.getElementById("dossierModal").style.display = "none";
};

// --------------------------------------------------------------------------
// 6. Interactive Entity Behaviour Graph (Spring Physics)
// --------------------------------------------------------------------------
let graphNodes = [];
let graphEdges = [];
let draggingNode = null;

async function fetchGraph() {
  try {
    const res = await fetch(`${API_BASE}/graph`);
    if (!res.ok) return;
    const data = await res.json();
    syncGraphData(data);
  } catch (e) {}
}

function syncGraphData(data) {
  const existingPos = {};
  graphNodes.forEach(n => existingPos[n.id] = { x: n.x, y: n.y, vx: n.vx, vy: n.vy });

  const canvas = document.getElementById("graphCanvas");
  if (!canvas) return;
  const w = canvas.parentElement.clientWidth;
  const h = canvas.parentElement.clientHeight;

  graphNodes = (data.nodes || []).map((n, i) => {
    const prev = existingPos[n.id];
    const angle = (i / (data.nodes.length || 1)) * Math.PI * 2;
    const r = Math.min(w, h) * 0.3;
    return {
      id: n.id,
      type: n.type,
      x: prev ? prev.x : w / 2 + r * Math.cos(angle) + (Math.random() - 0.5) * 40,
      y: prev ? prev.y : h / 2 + r * Math.sin(angle) + (Math.random() - 0.5) * 40,
      vx: prev ? prev.vx : 0,
      vy: prev ? prev.vy : 0,
      radius: n.type === "HOST_IP" ? 10 : n.type === "INCIDENT" ? 12 : 7,
    };
  });

  graphEdges = data.links || [];
}

function runGraphPhysics() {
  const canvas = document.getElementById("graphCanvas");
  if (!canvas) return;
  const w = canvas.parentElement.clientWidth;
  const h = canvas.parentElement.clientHeight;

  // Spring physics
  for (let i = 0; i < graphNodes.length; i++) {
    const n1 = graphNodes[i];
    if (n1 === draggingNode) continue;

    // Repulsion
    for (let j = i + 1; j < graphNodes.length; j++) {
      const n2 = graphNodes[j];
      const dx = n2.x - n1.x;
      const dy = n2.y - n1.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      if (dist < 180) {
        const force = (180 - dist) / dist * 0.08;
        n1.vx -= dx * force;
        n1.vy -= dy * force;
        n2.vx += dx * force;
        n2.vy += dy * force;
      }
    }

    // Center gravity
    n1.vx += (w / 2 - n1.x) * 0.003;
    n1.vy += (h / 2 - n1.y) * 0.003;

    // Dampening & update
    n1.vx *= 0.85;
    n1.vy *= 0.85;
    n1.x += n1.vx;
    n1.y += n1.vy;

    // Bounds
    n1.x = Math.max(20, Math.min(w - 20, n1.x));
    n1.y = Math.max(20, Math.min(h - 20, n1.y));
  }
}

let particleOffset = 0;
function renderGraphCanvas() {
  const canvas = document.getElementById("graphCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.parentElement.clientWidth;
  const h = canvas.parentElement.clientHeight;
  canvas.width = w;
  canvas.height = h;

  runGraphPhysics();
  ctx.clearRect(0, 0, w, h);

  const nodeMap = {};
  graphNodes.forEach(n => nodeMap[n.id] = n);

  // Draw Edges with Animated Flow Particles
  particleOffset = (particleOffset + 0.015) % 1;

  graphEdges.forEach(edge => {
    const src = nodeMap[edge.source];
    const tgt = nodeMap[edge.target];
    if (src && tgt) {
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.strokeStyle = "rgba(0, 240, 255, 0.15)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Flowing particle
      const px = src.x + (tgt.x - src.x) * particleOffset;
      const py = src.y + (tgt.y - src.y) * particleOffset;
      ctx.beginPath();
      ctx.arc(px, py, 2, 0, Math.PI * 2);
      ctx.fillStyle = "#00f0ff";
      ctx.fill();
    }
  });

  // Draw Nodes
  graphNodes.forEach(n => {
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);

    if (n.type === "HOST_IP") {
      ctx.fillStyle = "#00f0ff";
      ctx.shadowColor = "#00f0ff";
    } else if (n.type === "INCIDENT") {
      ctx.fillStyle = "#ff0055";
      ctx.shadowColor = "#ff0055";
    } else if (n.type === "SIGNAL") {
      ctx.fillStyle = "#ffb703";
      ctx.shadowColor = "#ffb703";
    } else {
      ctx.fillStyle = "#60a5fa";
      ctx.shadowColor = "#60a5fa";
    }

    ctx.shadowBlur = 12;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Node Label
    ctx.fillStyle = "#f3f6fc";
    ctx.font = "10px JetBrains Mono";
    ctx.textAlign = "center";
    ctx.fillText(n.id, n.x, n.y + n.radius + 12);
  });

  requestAnimationFrame(renderGraphCanvas);
}

// --------------------------------------------------------------------------
// 7. Live Oscilloscope Traffic Velocity Chart
// --------------------------------------------------------------------------
let wavePoints = new Array(60).fill(25);
let spikeIntensity = 0;

function triggerAttackSpike() {
  spikeIntensity = 45;
}

function renderTrafficOscilloscope() {
  const canvas = document.getElementById("trafficCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.parentElement.clientWidth;
  const h = canvas.parentElement.clientHeight;
  canvas.width = w;
  canvas.height = h;

  // Shift wave
  wavePoints.shift();
  const baseNoise = (Math.sin(Date.now() * 0.005) * 8) + (Math.random() * 4);
  const val = Math.max(5, 25 + baseNoise + spikeIntensity);
  spikeIntensity = Math.max(0, spikeIntensity * 0.92);
  wavePoints.push(val);

  ctx.clearRect(0, 0, w, h);

  // Background Grid
  ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 30) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y < h; y += 25) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  // Draw Gradient Wave Area
  const step = w / (wavePoints.length - 1);
  ctx.beginPath();
  ctx.moveTo(0, h);
  wavePoints.forEach((p, idx) => {
    const y = h - (p / 80) * h;
    ctx.lineTo(idx * step, y);
  });
  ctx.lineTo(w, h);
  ctx.closePath();

  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, "rgba(0, 240, 255, 0.3)");
  grad.addColorStop(1, "rgba(0, 240, 255, 0.0)");
  ctx.fillStyle = grad;
  ctx.fill();

  // Wave Stroke
  ctx.beginPath();
  wavePoints.forEach((p, idx) => {
    const y = h - (p / 80) * h;
    if (idx === 0) ctx.moveTo(0, y);
    else ctx.lineTo(idx * step, y);
  });
  ctx.strokeStyle = "#00f0ff";
  ctx.shadowColor = "#00f0ff";
  ctx.shadowBlur = 8;
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Update Ingress bandwidth label
  const curBps = (val * 0.65).toFixed(1);
  document.getElementById("chartBps").innerText = `${curBps} Mbps`;
  document.getElementById("chartMaxZ").innerText = `+${(val / 12).toFixed(1)}σ`;

  requestAnimationFrame(renderTrafficOscilloscope);
}

// --------------------------------------------------------------------------
// 8. Initialization & Refresh Loop
// --------------------------------------------------------------------------
function refreshAll() {
  fetchHealth();
  fetchAlerts();
  fetchIncidents();
  fetchGraph();
}

// Setup Canvas Drag
const graphCanvas = document.getElementById("graphCanvas");
graphCanvas.addEventListener("mousedown", (e) => {
  const rect = graphCanvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;

  for (let n of graphNodes) {
    const dx = n.x - mx;
    const dy = n.y - my;
    if (Math.sqrt(dx * dx + dy * dy) < n.radius + 6) {
      draggingNode = n;
      break;
    }
  }
});

window.addEventListener("mousemove", (e) => {
  if (draggingNode) {
    const rect = graphCanvas.getBoundingClientRect();
    draggingNode.x = e.clientX - rect.left;
    draggingNode.y = e.clientY - rect.top;
  }
});

window.addEventListener("mouseup", () => {
  draggingNode = null;
});

// Start Everything
refreshAll();
renderGraphCanvas();
renderTrafficOscilloscope();
setInterval(refreshAll, 1500);
