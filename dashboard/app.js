// ==========================================================================
// UniGuard AI — SOC Command Center Interactive Client Engine
// Designed for PS 26145 Unidirectional IP Traffic Enclave (NTRO)
// ==========================================================================

const API_BASE = window.location.origin;

// State
let alerts = [];
let incidents = [];
let graphData = { nodes: [], links: [] };
let audioEnabled = true;
let isStreaming = false;
let focusedEntityId = null;
let telemetryMode = "pps"; // pps, bps, risk
let lastAlertTimestamp = Date.now();

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
    gain.gain.setValueAtTime(0.06, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.3);

    osc.start();
    osc.stop(audioCtx.currentTime + 0.3);
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
      playAlertChime("CRITICAL");
      triggerAttackSpike();
      lastAlertTimestamp = Date.now();
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
      btn.style.background = isStreaming
        ? "linear-gradient(135deg, rgba(255, 0, 85, 0.4), rgba(157, 78, 221, 0.4))"
        : "linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(59, 130, 246, 0.2))";
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
      lastAlertTimestamp = Date.now();
    }
    previousAlertCount = alerts.length;
    renderAlertFeed();
    updateFeedTiming();
  } catch (e) {}
}

function updateFeedTiming() {
  const el = document.getElementById("feedLastEvent");
  if (!el) return;
  const elapsed = Math.max(0, Math.floor((Date.now() - lastAlertTimestamp) / 1000));
  el.innerText = elapsed === 0 ? "Last event: just now" : `Last event: ${elapsed}s ago`;
}

function renderAlertFeed() {
  const container = document.getElementById("feedScroll");
  const filter = document.getElementById("feedFilter").value;

  let filtered = alerts.slice().reverse();
  if (filter === "CRITICAL") filtered = filtered.filter(a => a.severity === "CRITICAL");
  else if (filter === "HIGH") filtered = filtered.filter(a => a.severity === "CRITICAL" || a.severity === "HIGH");
  else if (filter !== "ALL") filtered = filtered.filter(a => a.threat_class === filter);

  if (filtered.length === 0) {
    container.innerHTML = `<div style="padding:30px; text-align:center; color:#64748b; font-size:11px;">No active alerts matching filter.</div>`;
    return;
  }

  container.innerHTML = filtered.map(a => {
    const badgeClass = a.severity === "CRITICAL" ? "badge-crit" : a.severity === "HIGH" ? "badge-hi" : "badge-med";
    const timeStr = new Date(a.timestamp_iso).toLocaleTimeString();
    return `
      <div class="feed-item ${a.severity}" onclick="focusEntity('${a.source_ip}')" style="cursor:pointer;" title="Click to focus on ${a.source_ip}">
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
// 4. Correlated Incidents Deck & Cards
// --------------------------------------------------------------------------
async function fetchIncidents() {
  try {
    const res = await fetch(`${API_BASE}/incidents?limit=50`);
    if (!res.ok) return;
    incidents = await res.json();
    renderIncidentsCards();
    updateLifecycleFromIncidents();
  } catch (e) {}
}

function renderIncidentsCards() {
  const container = document.getElementById("incidentsContainer");
  if (!container) return;

  if (incidents.length === 0) {
    container.innerHTML = `<div style="grid-column: 1/-1; text-align:center; color:#64748b; padding:30px; font-size:12px;">No correlated incidents registered.</div>`;
    return;
  }

  container.innerHTML = incidents.slice().reverse().map(inc => {
    const riskPct = (inc.risk_score * 100).toFixed(0);
    const isCrit = inc.risk_score >= 0.85;
    const stagesHtml = (inc.threat_stages || []).map(s => `<span class="stage-pill">${s.stage || s}</span>`).join("") || `<span class="stage-pill">INITIAL_ACCESS</span>`;
    const evidenceSnippet = (inc.evidence_items || [])[0] || "Multi-signal correlated behavioral deviation";
    const timeStr = new Date(inc.created_iso).toLocaleTimeString();

    return `
      <div class="incident-card ${isCrit ? 'critical' : 'high'}" onclick="focusEntity('${inc.primary_entity}')">
        <div class="inc-card-head">
          <span class="inc-id-tag">${inc.incident_id}</span>
          <span class="inc-risk-tag">${riskPct}% ${inc.severity || 'CRITICAL'}</span>
        </div>
        <div class="inc-primary-entity">
          <span>🖥️ HOST:</span> <strong>${inc.primary_entity}</strong>
        </div>
        <div class="inc-stages-row">
          ${stagesHtml}
        </div>
        <div class="inc-evidence-summary">
          ${evidenceSnippet}
        </div>
        <div class="inc-card-footer">
          <span class="inc-time">🕒 ${timeStr}</span>
          <button class="investigate-btn" onclick="event.stopPropagation(); inspectIncident('${inc.incident_id}')">INVESTIGATE DOSSIER &rarr;</button>
        </div>
      </div>
    `;
  }).join("");
}

// --------------------------------------------------------------------------
// 5. Horizontal Attack Lifecycle Progression Engine
// --------------------------------------------------------------------------
function updateLifecycleFromIncidents() {
  if (focusedEntityId) return; // Keep focused entity state if active

  if (incidents.length > 0) {
    const topInc = incidents[incidents.length - 1];
    setLifecycleStages(topInc.threat_stages, topInc.primary_entity, topInc.risk_score);
  }
}

function setLifecycleStages(stages, host, riskScore) {
  const stageNames = (stages || []).map(s => (typeof s === 'string' ? s : s.stage || '').toUpperCase());
  const riskPct = Math.round((riskScore || 0) * 100);

  document.getElementById("focusEntitySubtitle").innerText = host ? `ACTIVE THREAT CORRELATION FOR HOST: ${host}` : "SELECT AN ENTITY BELOW OR INJECT AN ATTACK TO TRACE THE KILL-CHAIN";
  
  const riskBadge = document.getElementById("focusRiskBadge");
  riskBadge.innerText = `COMPOSITE RISK: ${riskPct >= 80 ? 'CRITICAL' : riskPct >= 50 ? 'HIGH' : 'NORMAL'} (${riskPct}%)`;
  if (riskPct >= 80) riskBadge.classList.add("critical");
  else riskBadge.classList.remove("critical");

  const rActive = stageNames.some(s => s.includes("RECON") || s.includes("SCAN"));
  const dActive = stageNames.some(s => s.includes("DNS") || s.includes("DGA"));
  const cActive = stageNames.some(s => s.includes("C2") || s.includes("BEACON"));
  const eActive = stageNames.some(s => s.includes("EXFIL"));

  updateStageNode("stageRecon", "stageReconPill", rActive, "PORT SWEEP DETECTED", "INACTIVE");
  updateStageNode("stageDns", "stageDnsPill", dActive, "DGA DETECTED (H=4.35)", "INACTIVE");
  updateStageNode("stageC2", "stageC2Pill", cActive, "BEACONING (J=3.2%)", "INACTIVE");
  updateStageNode("stageExfil", "stageExfilPill", eActive, "10.5MB OUTBOUND BURST", "INACTIVE", true);

  document.getElementById("connReconDns").className = `timeline-connector ${rActive && dActive ? 'active' : ''}`;
  document.getElementById("connDnsC2").className = `timeline-connector ${dActive && cActive ? 'active' : ''}`;
  document.getElementById("connC2Exfil").className = `timeline-connector ${cActive && eActive ? 'active' : ''}`;
}

function updateStageNode(nodeId, pillId, isActive, activeText, inactiveText, isCrit = false) {
  const node = document.getElementById(nodeId);
  const pill = document.getElementById(pillId);
  if (!node || !pill) return;

  if (isActive) {
    node.className = `stage-node ${isCrit ? 'critical-active' : 'active'}`;
    pill.innerText = activeText;
  } else {
    node.className = "stage-node";
    pill.innerText = inactiveText;
  }
}

// --------------------------------------------------------------------------
// 6. Attack Chain Focus & Interactive Graph
// --------------------------------------------------------------------------
function focusEntity(entityId) {
  focusedEntityId = entityId;
  const matchingInc = incidents.find(i => i.primary_entity === entityId);
  if (matchingInc) {
    setLifecycleStages(matchingInc.threat_stages, entityId, matchingInc.risk_score);
  } else {
    setLifecycleStages(["RECON_PORT_SCAN", "BOTNET_C2_BEACONING"], entityId, 0.88);
  }
}

function resetEntityFocus() {
  focusedEntityId = null;
  updateLifecycleFromIncidents();
}

function focusSampleAttackChain() {
  focusEntity("10.0.15.99");
  setLifecycleStages(
    ["RECON_PORT_SCAN", "DGA_DNS_TUNNELLING", "BOTNET_C2_BEACONING", "DATA_EXFILTRATION"],
    "10.0.15.99",
    0.99
  );
}

// Graph Canvas Physics & Rendering
let graphNodes = [];
let graphEdges = [];
let draggingNode = null;

async function fetchGraph() {
  try {
    const res = await fetch(`${API_BASE}/graph`);
    if (!res.ok) return;
    graphData = await res.json();
    initGraphData(graphData);
  } catch (e) {}
}

function initGraphData(data) {
  const canvas = document.getElementById("graphCanvas");
  if (!canvas) return;
  const w = canvas.parentElement.clientWidth || 500;
  const h = canvas.parentElement.clientHeight || 400;

  const existingPos = {};
  graphNodes.forEach(n => existingPos[n.id] = { x: n.x, y: n.y, vx: n.vx, vy: n.vy });

  graphNodes = (data.nodes || []).map((n, i) => {
    const prev = existingPos[n.id];
    const angle = (i / (data.nodes.length || 1)) * Math.PI * 2;
    const r = Math.min(w, h) * 0.32;
    return {
      id: n.id,
      type: n.type,
      x: prev ? prev.x : w / 2 + r * Math.cos(angle) + (Math.random() - 0.5) * 30,
      y: prev ? prev.y : h / 2 + r * Math.sin(angle) + (Math.random() - 0.5) * 30,
      vx: prev ? prev.vx : 0,
      vy: prev ? prev.vy : 0,
      radius: n.type === "HOST_IP" ? 11 : n.type === "INCIDENT" ? 13 : 7,
    };
  });

  graphEdges = data.links || [];
}

function runGraphPhysics() {
  const canvas = document.getElementById("graphCanvas");
  if (!canvas) return;
  const w = canvas.parentElement.clientWidth;
  const h = canvas.parentElement.clientHeight;

  for (let i = 0; i < graphNodes.length; i++) {
    const n1 = graphNodes[i];
    if (n1 === draggingNode) continue;

    // Repulsion
    for (let j = i + 1; j < graphNodes.length; j++) {
      const n2 = graphNodes[j];
      const dx = n2.x - n1.x;
      const dy = n2.y - n1.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      if (dist < 220) {
        const force = (220 - dist) / dist * 0.06;
        n1.vx -= dx * force;
        n1.vy -= dy * force;
        n2.vx += dx * force;
        n2.vy += dy * force;
      }
    }

    // Center Gravity
    n1.vx += (w / 2 - n1.x) * 0.0025;
    n1.vy += (h / 2 - n1.y) * 0.0025;

    // Dampening
    n1.vx *= 0.86;
    n1.vy *= 0.86;
    n1.x += n1.vx;
    n1.y += n1.vy;

    // Boundary constraints
    n1.x = Math.max(25, Math.min(w - 25, n1.x));
    n1.y = Math.max(25, Math.min(h - 25, n1.y));
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

  // Determine focused connected set
  const connectedNodeIds = new Set();
  if (focusedEntityId) {
    connectedNodeIds.add(focusedEntityId);
    graphEdges.forEach(e => {
      if (e.source === focusedEntityId) connectedNodeIds.add(e.target);
      if (e.target === focusedEntityId) connectedNodeIds.add(e.source);
    });
  }

  particleOffset = (particleOffset + 0.012) % 1;

  // Draw Edges
  graphEdges.forEach(edge => {
    const src = nodeMap[edge.source];
    const tgt = nodeMap[edge.target];
    if (src && tgt) {
      const isFocused = !focusedEntityId || (connectedNodeIds.has(src.id) && connectedNodeIds.has(tgt.id));
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.strokeStyle = isFocused ? "rgba(0, 240, 255, 0.35)" : "rgba(255, 255, 255, 0.04)";
      ctx.lineWidth = isFocused ? 2 : 1;
      ctx.stroke();

      if (isFocused) {
        const px = src.x + (tgt.x - src.x) * particleOffset;
        const py = src.y + (tgt.y - src.y) * particleOffset;
        ctx.beginPath();
        ctx.arc(px, py, 2, 0, Math.PI * 2);
        ctx.fillStyle = "#00f0ff";
        ctx.fill();
      }
    }
  });

  // Draw Nodes
  graphNodes.forEach(n => {
    const isFocused = !focusedEntityId || connectedNodeIds.has(n.id);
    const alpha = isFocused ? 1.0 : 0.15;

    ctx.save();
    ctx.globalAlpha = alpha;
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
      ctx.fillStyle = "#a78bfa";
      ctx.shadowColor = "#a78bfa";
    }

    if (isFocused) ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Draw label only for important nodes or if focused to avoid hairball clutter
    const showLabel = isFocused && (n.type === "HOST_IP" || n.type === "INCIDENT" || n.id.includes("darknet") || n.id.includes("onion") || n.id.includes("apt"));
    if (showLabel) {
      ctx.fillStyle = "#f3f6fc";
      ctx.font = "10px JetBrains Mono";
      ctx.textAlign = "center";
      ctx.fillText(n.id, n.x, n.y + n.radius + 12);
    }
    ctx.restore();
  });

  requestAnimationFrame(renderGraphCanvas);
}

// --------------------------------------------------------------------------
// 7. Telemetry Oscilloscope Switcher & Wave
// --------------------------------------------------------------------------
let wavePoints = new Array(60).fill(25);
let spikeIntensity = 0;

function switchTelemetryTab(mode) {
  telemetryMode = mode;
  document.querySelectorAll(".ttab").forEach(b => b.classList.remove("active"));
  const tabEl = document.getElementById(`tab${mode.charAt(0).toUpperCase() + mode.slice(1)}`);
  if (tabEl) tabEl.classList.add("active");
}

function triggerAttackSpike() {
  spikeIntensity = 45;
}

function renderTelemetryCanvas() {
  const canvas = document.getElementById("trafficCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.parentElement.clientWidth;
  const h = canvas.parentElement.clientHeight;
  canvas.width = w;
  canvas.height = h;

  let baseVal = 20;
  if (telemetryMode === "bps") baseVal = 35;
  if (telemetryMode === "risk") baseVal = 15;

  const nextVal = baseVal + (Math.random() - 0.5) * 12 + spikeIntensity;
  spikeIntensity *= 0.92;
  wavePoints.push(nextVal);
  if (wavePoints.length > 60) wavePoints.shift();

  ctx.clearRect(0, 0, w, h);

  // Background Grid
  ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 30) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }
  for (let y = 0; y < h; y += 30) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  // Waveform
  ctx.beginPath();
  const step = w / (wavePoints.length - 1);
  wavePoints.forEach((val, idx) => {
    const x = idx * step;
    const y = h - (val / 100) * (h - 20) - 10;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  const grad = ctx.createLinearGradient(0, 0, w, 0);
  if (telemetryMode === "risk") {
    grad.addColorStop(0, "#ffb703");
    grad.addColorStop(1, "#ff0055");
  } else {
    grad.addColorStop(0, "#00f0ff");
    grad.addColorStop(1, "#3b82f6");
  }

  ctx.strokeStyle = grad;
  ctx.lineWidth = 2.5;
  ctx.stroke();

  // Gradient Fill
  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  const fillGrad = ctx.createLinearGradient(0, 0, 0, h);
  fillGrad.addColorStop(0, telemetryMode === "risk" ? "rgba(255, 0, 85, 0.15)" : "rgba(0, 240, 255, 0.12)");
  fillGrad.addColorStop(1, "rgba(0, 0, 0, 0)");
  ctx.fillStyle = fillGrad;
  ctx.fill();

  requestAnimationFrame(renderTelemetryCanvas);
}

// --------------------------------------------------------------------------
// 8. Forensic Dossier Modal Controller
// --------------------------------------------------------------------------
function inspectIncident(incidentId) {
  const inc = incidents.find(i => i.incident_id === incidentId);
  if (!inc) return;

  document.getElementById("mIncidentId").innerText = inc.incident_id;
  document.getElementById("mHost").innerText = inc.primary_entity;
  document.getElementById("mRisk").innerText = `${(inc.risk_score * 100).toFixed(0)}% • ${inc.severity || 'CRITICAL'}`;
  document.getElementById("mTimeline").innerText = `${new Date(inc.created_iso).toLocaleString()} → ACTIVE`;

  let directive = "Maintain continuous zero-return-path passive observation and isolate affected network enclave.";
  if (inc.risk_score >= 0.85) {
    directive = `EMERGENCY DIRECTIVE: Deploy immediate upstream BGP blackhole filter for external destinations targeted by ${inc.primary_entity} and isolate host.`;
  }
  document.getElementById("mDirective").innerText = directive;

  const evList = document.getElementById("mEvidenceList");
  evList.innerHTML = (inc.evidence_items || []).map(ev => {
    return `<div class="evidence-entry">${ev}</div>`;
  }).join("") || `<div class="evidence-entry">Deterministic Multi-Signal Correlation & Baseline Anomaly</div>`;

  document.getElementById("dossierModal").style.display = "flex";
}

function closeModal() {
  document.getElementById("dossierModal").style.display = "none";
}

// --------------------------------------------------------------------------
// 9. Initializer & Polling Loops
// --------------------------------------------------------------------------
async function refreshAll() {
  await Promise.all([
    fetchHealth(),
    fetchAlerts(),
    fetchIncidents(),
    fetchGraph(),
  ]);
}

window.addEventListener("DOMContentLoaded", () => {
  refreshAll();
  renderGraphCanvas();
  renderTelemetryCanvas();

  // Polling loops
  setInterval(fetchHealth, 2000);
  setInterval(fetchAlerts, 2500);
  setInterval(fetchIncidents, 3000);
  setInterval(fetchGraph, 5000);
  setInterval(updateFeedTiming, 1000);
});
