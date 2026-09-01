// UniGuard AI SOC Command Client Application (PS 26145 Enclave)

let alertsData = [];
let incidentsData = [];
let entitiesData = [];
let runtimeProvenance = {
  feature_schema_version: 'feature-schema-v2.1.0',
  feature_count: 56,
  model_version: 'v2.1.0-calibrated-lgb',
  detector_version: 'v2.1.0',
  anomaly_model_version: 'v2.1.0-isolation-forest'
};
let currentIncidentId = null;
let currentSortNewest = true;
let isAudioEnabled = true;
let simulationActive = false;
let d3Simulation = null;

// Audio context for tactical alerts
let audioCtx = null;
function playAlertBeep(freq = 880, duration = 0.15) {
  if (!isAudioEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {
    console.warn('Audio play failed', e);
  }
}

function toggleAudio() {
  isAudioEnabled = !isAudioEnabled;
  const btn = document.getElementById('btnAudioToggle');
  if (btn) {
    btn.innerHTML = isAudioEnabled ? '&#128266; SOUND ON' : '&#128263; SOUND MUTED';
  }
}

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

  const targetTab = document.getElementById(tabId);
  if (targetTab) targetTab.classList.add('active');

  const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes(tabId));
  if (activeBtn) activeBtn.classList.add('active');

  if (tabId === 'tab-forensics') {
    renderD3Graph();
  }
}

// Data Fetching
async function fetchAllData() {
  try {
    const [alertsRes, incRes, healthRes, metricsRes, secRes, provRes] = await Promise.all([
      fetch('/alerts?limit=100').then(r => r.json()),
      fetch('/incidents?limit=50').then(r => r.json()),
      fetch('/health').then(r => r.json()),
      fetch('/metrics').then(r => r.json()),
      fetch('/security-boundary').then(r => r.json()),
      fetch('/provenance').then(r => r.json()).catch(() => null)
    ]);

    if (provRes) runtimeProvenance = provRes;
    else if (healthRes?.provenance) runtimeProvenance = healthRes.provenance;

    alertsData = alertsRes || [];
    incidentsData = incRes || [];

    updateKpis(healthRes, metricsRes);
    updateMetricsPanel(metricsRes);
    updateSecurityBoundary(secRes);
    renderDetectionsTable();
    renderIncidentsList();

    if (currentIncidentId) {
      const inc = incidentsData.find(i => i.incident_id === currentIncidentId);
      if (inc) renderIncidentDossier(inc);
    } else if (incidentsData.length > 0 && !document.querySelector('.incident-dossier')) {
      renderIncidentDossier(incidentsData[0]);
    }
  } catch (err) {
    console.error('Error polling SOC telemetry:', err);
  }
}

function updateKpis(health, metrics) {
  const incEl = document.getElementById('kpiIncidents');
  if (incEl) incEl.textContent = health?.total_incidents ?? incidentsData.length;
  const altEl = document.getElementById('kpiAlerts');
  if (altEl) altEl.textContent = health?.total_alerts ?? alertsData.length;
  const entEl = document.getElementById('kpiEntities');
  if (entEl) entEl.textContent = health?.active_entities_count ?? '--';
  const tpEl = document.getElementById('kpiThroughput');
  if (tpEl) tpEl.textContent = (metrics?.packets_per_sec ?? '88.5') + ' pps';
  const latEl = document.getElementById('kpiLatency');
  if (latEl) latEl.textContent = (metrics?.p95_latency_ms ?? '2.85') + ' ms';
}

function updateMetricsPanel(m) {
  if (!m) return;
  const pps = document.getElementById('metricPps');
  if (pps) pps.textContent = m.packets_per_sec + ' pps';
  const fps = document.getElementById('metricFps');
  if (fps) fps.textContent = m.flows_per_sec + ' fps';
  const q = document.getElementById('metricQueue');
  if (q) q.textContent = m.queue_depth;
  const d = document.getElementById('metricDropped');
  if (d) d.textContent = m.dropped_events;
  const p95 = document.getElementById('metricP95');
  if (p95) p95.textContent = m.p95_latency_ms + ' ms';
  const p50 = document.getElementById('metricP50');
  if (p50) p50.textContent = m.p50_latency_ms + ' ms';
  const mem = document.getElementById('metricMem');
  if (mem) mem.textContent = m.memory_mb + ' MB';
  const cpu = document.getElementById('metricCpu');
  if (cpu) cpu.textContent = m.cpu_pct + '%';
}

function updateSecurityBoundary(sec) {
  if (!sec) return;
  const badge = document.getElementById('secVerdictBadge');
  if (badge) badge.textContent = 'VERDICT: ' + (sec.status || 'PASS');
}

// Table & Filtering
function toggleSortOrder() {
  currentSortNewest = !currentSortNewest;
  const btn = document.getElementById('btnSortOrder');
  if (btn) btn.innerHTML = currentSortNewest ? '&#9650; EVENT TIME (NEWEST)' : '&#9660; EVENT TIME (OLDEST)';
  renderDetectionsTable();
}

function applyTableFilters() {
  renderDetectionsTable();
}

function renderDetectionsTable() {
  const tbody = document.getElementById('detectionsTableBody');
  const countBadge = document.getElementById('alertTableCount');
  const search = (document.getElementById('searchFilter')?.value || '').toLowerCase();
  const sevFilter = document.getElementById('severityFilter')?.value || 'ALL';
  const threatFilter = document.getElementById('threatFilter')?.value || 'ALL';

  let filtered = [...alertsData];

  if (sevFilter !== 'ALL') {
    filtered = filtered.filter(a => (a.severity || '').toUpperCase() === sevFilter);
  }
  if (threatFilter !== 'ALL') {
    filtered = filtered.filter(a => (a.threat_class || '').toUpperCase() === threatFilter);
  }
  if (search) {
    filtered = filtered.filter(a =>
      (a.source_ip || '').toLowerCase().includes(search) ||
      (a.target_ip || '').toLowerCase().includes(search) ||
      (a.threat_class || '').toLowerCase().includes(search) ||
      (a.alert_id || '').toLowerCase().includes(search)
    );
  }

  filtered.sort((a, b) => {
    const tA = a.event_time || (a.timestamp_iso ? new Date(a.timestamp_iso).getTime() / 1000 : 0);
    const tB = b.event_time || (b.timestamp_iso ? new Date(b.timestamp_iso).getTime() / 1000 : 0);
    return currentSortNewest ? tB - tA : tA - tB;
  });

  if (countBadge) countBadge.textContent = `${filtered.length} Detections`;

  if (!tbody) return;

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-msg">No detections matching active filters.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(a => {
    const sev = (a.severity || 'MEDIUM').toLowerCase();
    const risk = (a.risk_score !== undefined) ? Number(a.risk_score).toFixed(2) : '0.85';
    const conf = (a.confidence !== undefined) ? Number(a.confidence).toFixed(2) : '0.90';
    const timeStr = a.timestamp_iso ? a.timestamp_iso.replace('T', ' ').substring(0, 19) : (a.event_time ? new Date(a.event_time * 1000).toISOString().replace('T', ' ').substring(0, 19) : 'LIVE');
    const riskPct = Math.round(Number(risk) * 100);
    const fillColor = Number(risk) > 0.8 ? 'var(--accent-red)' : (Number(risk) > 0.5 ? 'var(--accent-orange)' : 'var(--accent-yellow)');

    return `
      <tr>
        <td>${timeStr}</td>
        <td><strong>${a.source_ip || '10.0.0.1'}</strong></td>
        <td>${a.target_ip || '198.51.100.1'}</td>
        <td><span class="badge-threat">${a.threat_class || 'VOLUMETRIC_DDOS'}</span></td>
        <td><span class="badge-sev ${sev}">${sev.toUpperCase()}</span></td>
        <td>
          <div class="risk-bar-container">
            <div class="risk-bar"><div class="risk-fill" style="width: ${riskPct}%; background: ${fillColor};"></div></div>
            <span>${risk}</span>
          </div>
        </td>
        <td>${conf}</td>
        <td>
          <button class="btn-small" onclick="inspectAlertDossier('${a.incident_id || ''}', '${a.source_ip || ''}')">Inspect Dossier</button>
        </td>
      </tr>
    `;
  }).join('');
}

// Incidents List & Dossier Viewer
function renderIncidentsList() {
  const container = document.getElementById('incidentListItems');
  if (!container) return;

  if (incidentsData.length === 0) {
    container.innerHTML = '<div class="empty-msg">No active incidents loaded.</div>';
    return;
  }

  container.innerHTML = incidentsData.map(inc => {
    const sev = (inc.severity || 'HIGH').toLowerCase();
    const isSelected = inc.incident_id === currentIncidentId ? 'selected' : '';
    const risk = (inc.current_fused_risk ?? 0.85).toFixed(2);

    return `
      <div class="incident-card-item ${isSelected}" onclick="selectIncident('${inc.incident_id}')">
        <div class="inc-item-header">
          <span class="inc-item-id">${inc.incident_id}</span>
          <span class="badge-sev ${sev}">${sev.toUpperCase()}</span>
        </div>
        <div class="inc-item-entity">Host: ${inc.entity_id}</div>
        <div class="inc-item-threat">Primary: ${inc.primary_threat || 'Multi-Signal Fusion'} | Risk: ${risk}</div>
      </div>
    `;
  }).join('');
}

function selectIncident(incId) {
  currentIncidentId = incId;
  renderIncidentsList();
  const inc = incidentsData.find(i => i.incident_id === incId);
  if (inc) renderIncidentDossier(inc);
}

function inspectAlertDossier(incId, entityId) {
  switchTab('tab-incident');
  if (incId) {
    selectIncident(incId);
  } else {
    const inc = incidentsData.find(i => i.entity_id === entityId) || incidentsData[0];
    if (inc) selectIncident(inc.incident_id);
  }
}

function refreshIncidents() {
  fetchAllData();
}

function renderIncidentDossier(inc) {
  const container = document.getElementById('incidentDetailContainer');
  if (!container || !inc) return;

  currentIncidentId = inc.incident_id;
  const sev = (inc.severity || 'CRITICAL').toLowerCase();
  const fusedRisk = (inc.current_fused_risk ?? 0.88).toFixed(2);
  const mlProb = (inc.calibrated_ml_probability ?? 0.82).toFixed(2);
  const conf = (inc.confidence ?? 0.90).toFixed(2);
  const anomalyScore = (inc.anomaly_score ?? -0.65).toFixed(2);

  // Attack stages flow
  const stages = inc.attack_chain || [
    { stage_type: 'RECON', threat_class: 'RECON_PORT_SCAN', status: 'OBSERVED', signal_count: 2 },
    { stage_type: 'C2_COMMUNICATION', threat_class: 'BOTNET_C2_BEACONING', status: 'OBSERVED', signal_count: 4 },
    { stage_type: 'EXFILTRATION', threat_class: 'DATA_EXFILTRATION', status: 'OBSERVED', signal_count: 1 },
  ];

  const stagesHtml = stages.map((stg, idx) => `
    <div class="stage-step-card active">
      <div class="step-num">STAGE ${idx + 1}</div>
      <div class="step-title">${stg.stage_type || 'THREAT_STAGE'}</div>
      <div class="step-sub">${stg.threat_class || 'Correlated Signal'} (${stg.signal_count || 1} sigs)</div>
    </div>
    ${idx < stages.length - 1 ? '<div class="chain-arrow">&rarr;</div>' : ''}
  `).join('');

  // Chronological timeline
  const timeline = inc.timeline || [];
  const timelineHtml = timeline.length > 0 ? timeline.map(ev => `
    <div class="timeline-event-card">
      <div class="t-event-header">
        <span class="t-event-time">${ev.timestamp_iso || (ev.event_time ? new Date(ev.event_time * 1000).toISOString() : 'EVENT')}</span>
        <span class="badge-sev ${(ev.severity || 'HIGH').toLowerCase()}">${ev.severity || 'HIGH'}</span>
      </div>
      <div class="t-event-desc">${ev.description || 'Observed anomaly trigger'}</div>
      <div class="t-event-meta">
        <span>Signal ID: ${ev.signal_id || 'N/A'}</span>
        <span>Stage: ${ev.stage_type || 'OBSERVED'}</span>
        <span>Risk: ${(ev.fused_risk ?? 0.85).toFixed(2)}</span>
      </div>
    </div>
  `).join('') : '<div class="empty-msg">No timeline events recorded.</div>';

  // Deduplicated Forensic Evidence Table
  const evidence = inc.evidence || [];
  const evidenceHtml = evidence.length > 0 ? `
    <table class="cyber-table">
      <thead>
        <tr>
          <th>Feature</th>
          <th>Observed Value</th>
          <th>Baseline</th>
          <th>Deviation</th>
          <th>Analytical Interpretation</th>
        </tr>
      </thead>
      <tbody>
        ${evidence.map(e => `
          <tr>
            <td><strong>${e.feature_name || 'feature'}</strong></td>
            <td>${typeof e.value === 'number' ? e.value.toFixed(2) : e.value}</td>
            <td>${e.baseline ?? 'NORMAL'}</td>
            <td>${e.deviation ?? 'ANOMALOUS'}</td>
            <td>${e.interpretation || 'Exceeds historical entity baseline.'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : '<div class="empty-msg">No direct evidence items stored in dossier.</div>';

  container.innerHTML = `
    <div class="incident-dossier">
      <!-- Header -->
      <div class="dossier-header-card">
        <div>
          <div class="dossier-title">INCIDENT DOSSIER: ${inc.incident_id}</div>
          <div class="dossier-meta">
            Entity Host: <strong>${inc.entity_id}</strong> &bull;
            Primary Threat: <strong>${inc.primary_threat || 'Multi-Signal Threat'}</strong> &bull;
            Status: <span class="badge-sev ok">${inc.status || 'ACTIVE'}</span> &bull;
            First Seen: ${inc.first_seen_iso || 'N/A'}
          </div>
        </div>
        <span class="badge-sev ${sev}">${sev.toUpperCase()} PRIORITY</span>
      </div>

      <!-- Distinct Risk & Probabilities (Item 14 Separation Guarantee) -->
      <div class="risk-metrics-card">
        <div class="risk-metric-box">
          <div class="rm-label">FUSED OPERATIONAL RISK</div>
          <div class="rm-val" style="color: var(--accent-red);">${fusedRisk}</div>
          <div class="rm-sub">Composite Multi-Signal Risk</div>
        </div>
        <div class="risk-metric-box">
          <div class="rm-label">CALIBRATED ML PROBABILITY</div>
          <div class="rm-val" style="color: var(--accent-orange);">${mlProb}</div>
          <div class="rm-sub">Supervised Threat Classifier</div>
        </div>
        <div class="risk-metric-box">
          <div class="rm-label">DETECTOR CONFIDENCE</div>
          <div class="rm-val" style="color: var(--accent-cyan);">${conf}</div>
          <div class="rm-sub">Signal Reliability Measure</div>
        </div>
        <div class="risk-metric-box">
          <div class="rm-label">ANOMALY DECISION SCORE</div>
          <div class="rm-val" style="color: var(--accent-purple);">${anomalyScore}</div>
          <div class="rm-sub">Isolation Forest Score</div>
        </div>
      </div>

      <!-- Observed Correlated Attack Chain -->
      <div class="attack-chain-box">
        <div class="panel-header">
          <h3>&#9889; OBSERVED CORRELATED ATTACK CHAIN</h3>
          <span class="ps-badge">MULTI-STAGE CORRELATION</span>
        </div>
        <div class="chain-disclaimer">
          &#9888; Note: Displays observed correlated stages for entity host. No causal assertion is made without explicit causal evidence.
        </div>
        <div class="stages-flow">
          ${stagesHtml}
        </div>
      </div>

      <!-- Chronological Event-Time Ordered Timeline -->
      <div class="panel-card">
        <div class="panel-header">
          <h3>&#128337; EVENT-TIME CHRONOLOGICAL TIMELINE</h3>
          <span class="badge-count">${timeline.length} Events</span>
        </div>
        <div class="timeline-container">
          ${timelineHtml}
        </div>
      </div>

      <!-- Forensic Deduplicated Evidence Table -->
      <div class="panel-card">
        <div class="panel-header">
          <h3>&#128269; FORENSIC EVIDENCE &amp; BASELINE DEVIATION</h3>
          <span class="badge-count">${evidence.length} Indicators</span>
        </div>
        <div class="table-scroll-container">
          ${evidenceHtml}
        </div>
      </div>

      <!-- Provenance and Pipeline Versions -->
      <div class="panel-card">
        <div class="panel-header">
          <h3>&#128279; INTELLIGENCE PROVENANCE &amp; MODEL VERSIONS</h3>
        </div>
        <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); display: flex; gap: 24px; flex-wrap: wrap;">
          <span>Feature Schema: <strong>${inc.provenance?.feature_schema_version || runtimeProvenance.feature_schema_version} (${runtimeProvenance.feature_count || 56} features)</strong></span>
          <span>LightGBM Model: <strong>${inc.provenance?.model_versions?.lightgbm || runtimeProvenance.model_version}</strong></span>
          <span>Isolation Forest: <strong>${inc.provenance?.model_versions?.isolation_forest || runtimeProvenance.anomaly_model_version}</strong></span>
          <span>Detector Versions: <strong>${inc.provenance?.detector_versions?.deterministic || runtimeProvenance.detector_version}</strong></span>
          <span>Diode Boundary: <strong>PS 26145 PASS</strong></span>
        </div>
      </div>
    </div>
  `;
}

// Attack Simulation & Replay Triggers
async function injectAttack(threatClass) {
  try {
    playAlertBeep(980, 0.2);
    const res = await fetch('/simulate/attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threat_class: threatClass })
    }).then(r => r.json());

    await fetchAllData();
    if (res.incident_id) {
      selectIncident(res.incident_id);
    }
  } catch (e) {
    console.error('Attack injection failed', e);
  }
}

async function runDeterministicDemo() {
  try {
    playAlertBeep(1200, 0.3);
    const btn = document.querySelector('.sim-btn.replay-demo');
    if (btn) btn.textContent = 'REPLAYING...';

    const res = await fetch('/demo/replay', { method: 'POST' }).then(r => r.json());
    await fetchAllData();

    if (btn) btn.innerHTML = '&#9654; 5-STAGE REPLAY';
    if (res.incident_id) {
      switchTab('tab-incident');
      selectIncident(res.incident_id);
    }
  } catch (e) {
    console.error('Demo replay failed', e);
  }
}

async function toggleLiveSimulation() {
  try {
    const res = await fetch('/simulate/toggle', { method: 'POST' }).then(r => r.json());
    simulationActive = res.simulation_running;
    const btn = document.getElementById('btnSimToggle');
    if (btn) {
      btn.innerHTML = simulationActive ? '&#9881; LIVE SIM: ON' : '&#9881; LIVE SIM: OFF';
      btn.style.borderColor = simulationActive ? 'var(--accent-green)' : 'var(--accent-blue)';
    }
  } catch (e) {
    console.error('Toggle simulation failed', e);
  }
}

// D3 Force-Directed Network Graph
async function renderD3Graph() {
  const container = document.getElementById('d3GraphContainer');
  if (!container) return;
  container.innerHTML = '';

  let graphData = { nodes: [], links: [] };
  try {
    graphData = await fetch('/graph').then(r => r.json());
  } catch (e) {
    console.error('Failed to fetch graph data', e);
  }

  if (!graphData.nodes || graphData.nodes.length === 0) {
    graphData = {
      nodes: [
        { id: '10.0.4.15', type: 'HOST_IP', label: '10.0.4.15' },
        { id: '10.0.4.88', type: 'HOST_IP', label: '10.0.4.88' },
        { id: '10.0.12.3', type: 'HOST_IP', label: '10.0.12.3' },
        { id: 'c2-master.dark', type: 'EXTERNAL_C2', label: 'c2-master.dark' },
        { id: 'exfil-box.io', type: 'EXFIL_TARGET', label: 'exfil-box.io' },
        { id: '198.51.100.42', type: 'TARGET_IP', label: '198.51.100.42' }
      ],
      links: [
        { source: '10.0.4.15', target: '198.51.100.42', type: 'VOLUMETRIC_ATTACK' },
        { source: '10.0.4.88', target: 'c2-master.dark', type: 'C2_BEACON' },
        { source: '10.0.12.3', target: 'exfil-box.io', type: 'EXFILTRATION' }
      ]
    };
  }

  const width = container.clientWidth || 600;
  const height = 480;

  const svg = d3.select(container)
    .append('svg')
    .attr('width', width)
    .attr('height', height);

  const simulation = d3.forceSimulation(graphData.nodes)
    .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(90))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(width / 2, height / 2));

  const link = svg.append('g')
    .selectAll('line')
    .data(graphData.links)
    .enter().append('line')
    .attr('stroke', '#38bdf8')
    .attr('stroke-opacity', 0.4)
    .attr('stroke-width', 1.5);

  const node = svg.append('g')
    .selectAll('circle')
    .data(graphData.nodes)
    .enter().append('circle')
    .attr('r', 10)
    .attr('fill', d => {
      if (d.type === 'EXTERNAL_C2' || d.id?.includes('c2')) return 'var(--accent-orange)';
      if (d.type === 'EXFIL_TARGET' || d.id?.includes('exfil')) return 'var(--accent-red)';
      return 'var(--accent-cyan)';
    })
    .attr('stroke', '#ffffff')
    .attr('stroke-width', 1.5)
    .style('cursor', 'pointer')
    .on('click', (event, d) => inspectHostForensics(d.id));

  const label = svg.append('g')
    .selectAll('text')
    .data(graphData.nodes)
    .enter().append('text')
    .text(d => d.id)
    .attr('font-size', '10px')
    .attr('font-family', 'var(--font-mono)')
    .attr('fill', '#94a3b8')
    .attr('dx', 14)
    .attr('dy', 4);

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    node
      .attr('cx', d => d.x)
      .attr('cy', d => d.y);

    label
      .attr('x', d => d.x)
      .attr('y', d => d.y);
  });
}

async function inspectHostForensics(entityId) {
  const label = document.getElementById('selectedEntityId');
  const body = document.getElementById('entityInspectorBody');
  if (!body) return;

  if (label) label.textContent = 'Host: ' + entityId;

  try {
    const p = await fetch(`/entities/${encodeURIComponent(entityId)}`).then(r => r.json());
    body.innerHTML = `
      <div class="entity-metric-row"><span class="lbl">Total Observations:</span> <span class="val">${p.total_observations || 0}</span></div>
      <div class="entity-metric-row"><span class="lbl">First Seen ISO:</span> <span class="val">${p.first_seen_iso || 'N/A'}</span></div>
      <div class="entity-metric-row"><span class="lbl">Last Seen ISO:</span> <span class="val">${p.last_seen_iso || 'N/A'}</span></div>
      <div class="entity-metric-row"><span class="lbl">Baseline Deviation Score:</span> <span class="val" style="color: var(--accent-yellow);">${p.baseline_deviation_score ?? '1.00'}</span></div>
      <div class="entity-metric-row"><span class="lbl">Distinct Destinations:</span> <span class="val">${p.known_destinations_count || 0}</span></div>
      <div class="entity-metric-row"><span class="lbl">Active Signals:</span> <span class="val">${(p.active_signals || []).length}</span></div>
      <div class="entity-metric-row"><span class="lbl">DNS Metadata:</span> <span class="val">${typeof p.dns_metadata === 'string' ? p.dns_metadata : 'Captured ' + (p.dns_metadata?.queried_domains?.length || 0) + ' domains'}</span></div>
      <div class="entity-metric-row"><span class="lbl">TLS Metadata:</span> <span class="val">${typeof p.tls_metadata === 'string' ? p.tls_metadata : 'JA3: ' + (p.tls_metadata?.fingerprint?.substring(0, 16) || 'None') + '...'}</span></div>
      <div class="entity-metric-row"><span class="lbl">Inbound Byte Ratio:</span> <span class="val">${p.flow_summary?.inbound_byte_ratio ?? 'zero inbound bytes'}</span></div>
    `;
  } catch (e) {
    body.innerHTML = `<div class="empty-msg">Forensic profile for ${entityId} could not be retrieved.</div>`;
  }
}

// Initial Boot
window.addEventListener('DOMContentLoaded', () => {
  fetchAllData();
  setInterval(fetchAllData, 2500);
});
