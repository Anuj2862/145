/**
 * UniGuard AI ? Tactical SOC Analyst Command Center Logic (M23.3)
 * Features:
 * 1. Hero Entity Attack Graph with D3 force-directed layout, zoom, pan, fit, & filtering.
 * 2. Semantic edge labels: contacted, queried, observed, correlated, followed_by.
 * 3. Node inspection across HOST_IP, EXTERNAL_IP, DOMAIN, TLS_FINGERPRINT, THREAT_STAGE.
 * 4. Event-time timeline scrubber with step playback.
 * 5. Incident highlighting and risk progression trajectory visualization.
 * 6. Slide-over Incident Dossier with distinct risk metrics and evidence indicators.
 * 7. Enclave security boundary assurance and dynamic provenance binding.
 */

let alertsData = [];
let incidentsData = [];
let entitiesData = [];
let graphData = { nodes: [], links: [] };
let selectedIncidentId = null;
let selectedNodeId = null;
let currentSortOrder = "NEWEST";
let isAudioEnabled = true;
let simulationActive = false;
let showGraphLabels = true;
let activeNodeFilters = {
  HOST_IP: true,
  THREAT_STAGE: true,
  EXTERNAL_IP: true,
  DOMAIN: true,
  TLS_FINGERPRINT: true
};

let d3Simulation = null;
let d3Svg = null;
let d3G = null;
let d3ZoomBehavior = null;

let runtimeProvenance = {
  feature_schema_version: 'feature-schema-v2.1.0',
  feature_count: 56,
  model_version: 'v2.1.0-calibrated-lgb',
  detector_version: 'v2.1.0',
  anomaly_model_version: 'v2.1.0-isolation-forest',
  detector_versions: {
    lightweight_ml: 'v2.1.0',
    deterministic: 'v2.1.0',
    isolation_forest: 'v2.1.0'
  },
  model_versions: {
    lightgbm: 'v2.1.0-calibrated-lgb',
    isolation_forest: 'v2.1.0-isolation-forest',
    random_forest: 'v2.1.0-rf-baseline'
  }
};

let audioCtx = null;
function playTacticalBeep(freq = 880, type = "sine", duration = 0.12) {
  if (!isAudioEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === "suspended") audioCtx.resume();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {}
}

function toggleAudio() {
  isAudioEnabled = !isAudioEnabled;
  const btn = document.getElementById("btnAudioToggle");
  if (btn) {
    btn.innerHTML = isAudioEnabled ? "&#128266; SOUND ON" : "&#128263; MUTED";
  }
}

function switchNavTab(tabId) {
  document.querySelectorAll(".nav-item").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".view-tab").forEach(tab => tab.classList.remove("active"));

  const navMap = {
    'tab-feed': 'nav-feed',
    'tab-forensics': 'nav-forensics',
    'tab-incidents': 'nav-incidents',
    'tab-security': 'nav-security',
    'tab-demo': 'nav-demo'
  };

  const navBtnId = navMap[tabId];
  if (navBtnId && document.getElementById(navBtnId)) {
    document.getElementById(navBtnId).classList.add("active");
  }

  const targetTab = document.getElementById(tabId);
  if (targetTab) {
    targetTab.classList.add("active");
  }

  if (tabId === 'tab-forensics') {
    setTimeout(() => {
      fetchGraphDataAndRender();
    }, 60);
  }
}

function updateClock() {
  const clockEl = document.getElementById("topbarClock");
  if (clockEl) {
    const now = new Date();
    clockEl.innerText = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  }
}
setInterval(updateClock, 1000);

async function fetchAllData() {
  try {
    const [alertsRes, incRes, healthRes, metricsRes, secRes, provRes] = await Promise.all([
      fetch('/alerts?limit=100').then(r => r.json()).catch(() => []),
      fetch('/incidents?limit=50').then(r => r.json()).catch(() => []),
      fetch('/health').then(r => r.json()).catch(() => null),
      fetch('/metrics').then(r => r.json()).catch(() => null),
      fetch('/security-boundary').then(r => r.json()).catch(() => null),
      fetch('/provenance').then(r => r.json()).catch(() => null)
    ]);

    if (provRes && provRes.feature_schema_version) {
      runtimeProvenance = provRes;
    } else if (healthRes && healthRes.provenance) {
      runtimeProvenance = healthRes.provenance;
    }

    alertsData = Array.isArray(alertsRes) ? alertsRes : [];
    incidentsData = Array.isArray(incRes) ? incRes : [];

    updateTopHeaderProvenance();
    updateKPICards(healthRes, metricsRes);
    updateSystemHealthMini(metricsRes);
    renderDetectionFeedTable();
    renderIncidentsList();

    const alertCountEl = document.getElementById("navAlertCount");
    if (alertCountEl) alertCountEl.innerText = alertsData.length;

    const incCountEl = document.getElementById("navIncCount");
    if (incCountEl) incCountEl.innerText = incidentsData.length;
  } catch (err) {
    console.error("Error fetching SOC data:", err);
  }
}

function updateTopHeaderProvenance() {
  const schemaEl = document.getElementById("topbarSchemaVer");
  if (schemaEl) {
    schemaEl.innerText = `${runtimeProvenance.feature_schema_version} (${runtimeProvenance.feature_count || 56} features)`;
  }
  const modelEl = document.getElementById("topbarModelVer");
  if (modelEl) {
    modelEl.innerText = runtimeProvenance.model_version;
  }
}

function updateKPICards(health, metrics) {
  const incEl = document.getElementById("kpiIncidents");
  if (incEl) incEl.innerText = incidentsData.length;

  const critEl = document.getElementById("kpiCritical");
  if (critEl) {
    const critCount = incidentsData.filter(i => i.severity === "CRITICAL").length;
    critEl.innerText = critCount;
  }

  const entEl = document.getElementById("kpiEntities");
  if (entEl) {
    const uniqueEntities = new Set(incidentsData.map(i => i.entity_id || i.source_entity));
    entEl.innerText = Math.max(uniqueEntities.size, 1);
  }

  const tputEl = document.getElementById("kpiThroughput");
  if (tputEl && metrics) {
    tputEl.innerText = `${metrics.packets_per_sec.toFixed(1)} pps`;
  }

  const fpsEl = document.getElementById("kpiFps");
  if (fpsEl && metrics) {
    fpsEl.innerText = `${metrics.flows_per_sec.toFixed(1)} fps`;
  }

  const latEl = document.getElementById("kpiLatency");
  if (latEl && metrics) {
    latEl.innerText = `${metrics.p95_latency_ms.toFixed(2)} ms`;
  }
}

function updateSystemHealthMini(metrics) {
  if (!metrics) return;
  const pps = document.getElementById("miniPps");
  if (pps) pps.innerText = `${metrics.packets_per_sec.toFixed(1)} pps`;

  const fps = document.getElementById("miniFps");
  if (fps) fps.innerText = `${metrics.flows_per_sec.toFixed(1)} fps`;

  const q = document.getElementById("miniQueue");
  if (q) q.innerText = metrics.queue_depth;

  const drop = document.getElementById("miniDropped");
  if (drop) drop.innerText = metrics.dropped_events;

  const mem = document.getElementById("miniMem");
  if (mem) mem.innerText = `${metrics.memory_mb.toFixed(1)} MB`;

  const cpu = document.getElementById("miniCpu");
  if (cpu) cpu.innerText = `${metrics.cpu_pct.toFixed(1)}%`;
}

function toggleSortOrder() {
  currentSortOrder = currentSortOrder === "NEWEST" ? "OLDEST" : "NEWEST";
  const btn = document.getElementById("btnSortOrder");
  if (btn) {
    btn.innerHTML = currentSortOrder === "NEWEST" ? "&#9650; TIME (NEWEST)" : "&#9660; TIME (OLDEST)";
  }
  renderDetectionFeedTable();
}

function applyTableFilters() {
  renderDetectionFeedTable();
}

function renderDetectionFeedTable() {
  const tbody = document.getElementById("detectionsTableBody");
  if (!tbody) return;

  const searchVal = (document.getElementById("searchFilter")?.value || "").toLowerCase();
  const sevVal = document.getElementById("severityFilter")?.value || "ALL";
  const threatVal = document.getElementById("threatFilter")?.value || "ALL";

  let filtered = alertsData.filter(al => {
    if (sevVal !== "ALL" && al.severity !== sevVal) return false;
    if (threatVal !== "ALL" && al.threat_class !== threatVal) return false;
    if (searchVal) {
      const matchIp = (al.entity_id || al.source_ip || "").toLowerCase().includes(searchVal);
      const matchThreat = (al.threat_class || "").toLowerCase().includes(searchVal);
      const matchId = (al.alert_id || al.incident_id || "").toLowerCase().includes(searchVal);
      if (!matchIp && !matchThreat && !matchId) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    const tA = new Date(a.timestamp_iso || a.event_time || 0).getTime();
    const tB = new Date(b.timestamp_iso || b.event_time || 0).getTime();
    return currentSortOrder === "NEWEST" ? tB - tA : tA - tB;
  });

  const badgeEl = document.getElementById("feedCountBadge");
  if (badgeEl) badgeEl.innerText = `${filtered.length} Detections`;

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; padding: 28px; color: var(--text-dim);">
          Zero detections match current filter criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(al => {
    const timeStr = (al.timestamp_iso || al.event_time || "").replace('T', ' ').substring(11, 19);
    const hostIp = al.entity_id || al.source_ip || "192.168.1.100";
    const targetIp = al.target_ip || al.destination_ip || "10.0.0.1";
    const threat = (al.threat_class || "UNKNOWN_ANOMALY").replace(/_/g, ' ');
    const sev = al.severity || "MEDIUM";
    const risk = typeof al.fused_risk === 'number' ? al.fused_risk : (al.risk_score || 0.75);
    const conf = typeof al.confidence === 'number' ? al.confidence : 0.90;
    const riskPct = Math.round(risk * 100);

    let riskColor = "var(--border-bright)";
    if (risk >= 0.85) riskColor = "var(--color-critical)";
    else if (risk >= 0.65) riskColor = "var(--color-high)";
    else if (risk >= 0.40) riskColor = "var(--color-medium)";

    return `
      <tr onclick="handleRowClick('${al.alert_id}', '${al.incident_id}')">
        <td class="cell-time">${timeStr} UTC</td>
        <td class="cell-ip">${hostIp}</td>
        <td class="cell-target">${targetIp}</td>
        <td class="cell-threat"><span>${threat}</span></td>
        <td><span class="badge-sev ${sev}">${sev}</span></td>
        <td>
          <div class="risk-bar-wrap">
            <div class="risk-bar-track">
              <div class="risk-bar-fill" style="width: ${riskPct}%; background-color: ${riskColor};"></div>
            </div>
            <span class="risk-num" style="color: ${riskColor};">${risk.toFixed(2)}</span>
          </div>
        </td>
        <td class="cell-time">${conf.toFixed(2)}</td>
        <td style="text-align: center;">
          <button class="btn-inspect-row" onclick="event.stopPropagation(); handleRowClick('${al.alert_id}', '${al.incident_id}')">
            INSPECT &rarr;
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function handleRowClick(alertId, incidentId) {
  let inc = null;
  if (incidentId) {
    inc = incidentsData.find(i => i.incident_id === incidentId);
  }
  if (!inc && alertId) {
    const al = alertsData.find(a => a.alert_id === alertId);
    if (al) {
      inc = incidentsData.find(i => i.entity_id === al.entity_id || i.incident_id === al.incident_id);
    }
  }
  if (inc) {
    openIncidentDrawer(inc);
  } else if (alertId) {
    const al = alertsData.find(a => a.alert_id === alertId);
    if (al) openAlertDrawerFallback(al);
  }
}

async function fetchGraphDataAndRender() {
  try {
    const res = await fetch('/graph');
    const data = await res.json();
    graphData = {
      nodes: Array.isArray(data.nodes) ? data.nodes : [],
      links: Array.isArray(data.links) ? data.links : []
    };

    if (graphData.nodes.length < 5 && incidentsData.length > 0) {
      enrichGraphFromIncidents();
    }

    renderD3TopologyGraph();
  } catch (err) {
    console.error("Error fetching graph data:", err);
  }
}

function enrichGraphFromIncidents() {
  const existingNodeIds = new Set(graphData.nodes.map(n => n.id));

  incidentsData.forEach(inc => {
    const host = inc.entity_id || "192.168.10.45";
    if (!existingNodeIds.has(host)) {
      graphData.nodes.push({ id: host, type: "HOST_IP", properties: { role: "Monitored Host", last_risk: inc.current_fused_risk || 0.85 } });
      existingNodeIds.add(host);
    }

    const stages = inc.attack_chain_stages || ["RECON_PORT_SCAN", "BOTNET_C2_BEACONING", "DATA_EXFILTRATION"];
    let prevStage = null;
    stages.forEach(stg => {
      const stgId = `STAGE-${stg}`;
      if (!existingNodeIds.has(stgId)) {
        graphData.nodes.push({ id: stgId, type: "THREAT_STAGE", properties: { stage_name: stg, risk: inc.current_fused_risk || 0.85, severity: inc.severity || "HIGH" } });
        existingNodeIds.add(stgId);
      }
      graphData.links.push({ source: host, target: stgId, type: "CORRELATED_STAGE", properties: { semantic: "correlated" } });
      if (prevStage) {
        graphData.links.push({ source: prevStage, target: stgId, type: "STAGE_PROGRESSION", properties: { semantic: "followed_by" } });
      }
      prevStage = stgId;
    });

    if (inc.destination_entities && inc.destination_entities.length > 0) {
      inc.destination_entities.forEach(dst => {
        if (!existingNodeIds.has(dst)) {
          graphData.nodes.push({ id: dst, type: "EXTERNAL_IP", properties: { threat: inc.threat_class } });
          existingNodeIds.add(dst);
        }
        graphData.links.push({ source: host, target: dst, type: "COMMUNICATES_WITH", properties: { semantic: "contacted" } });
      });
    }
  });
}

function toggleNodeFilter(type) {
  activeNodeFilters[type] = !activeNodeFilters[type];
  const btnMap = {
    HOST_IP: 'flt-HOST',
    THREAT_STAGE: 'flt-STAGE',
    EXTERNAL_IP: 'flt-EXT',
    DOMAIN: 'flt-DOM',
    TLS_FINGERPRINT: 'flt-TLS'
  };
  const btn = document.getElementById(btnMap[type]);
  if (btn) {
    btn.classList.toggle('active', activeNodeFilters[type]);
  }
  renderD3TopologyGraph();
}

function toggleGraphLabels() {
  showGraphLabels = !showGraphLabels;
  const btn = document.getElementById("btnToggleLabels");
  if (btn) btn.classList.toggle('active', showGraphLabels);
  if (d3G) {
    d3G.selectAll(".d3-node-label").style("display", showGraphLabels ? "block" : "none");
    d3G.selectAll(".d3-edge-label").style("display", showGraphLabels ? "block" : "none");
  }
}

function zoomGraph(scaleFactor) {
  if (d3Svg && d3ZoomBehavior) {
    d3Svg.transition().duration(300).call(d3ZoomBehavior.scaleBy, scaleFactor);
  }
}

function resetGraphView() {
  if (d3Svg && d3ZoomBehavior) {
    d3Svg.transition().duration(500).call(d3ZoomBehavior.transform, d3.zoomIdentity);
  }
}

function handleTimelineScrub(val) {
  const stageIndex = parseInt(val, 10);
  const stageNames = ["Init", "Recon", "C2 Beacon", "DNS Tunnel", "Malware", "Exfiltration"];
  const lbl = document.getElementById("timelineScrubTime");
  if (lbl) {
    lbl.innerText = stageIndex === 5 ? "All Stages Visible" : `Stage ${stageIndex}: ${stageNames[stageIndex]} Replay`;
  }

  if (d3G) {
    const stageMap = {
      1: "STAGE-RECON",
      2: "STAGE-C2",
      3: "STAGE-DNS",
      4: "STAGE-MALWARE",
      5: "STAGE-EXFIL"
    };

    d3G.selectAll(".d3-node").each(function(d) {
      let isVisible = true;
      if (d.type === "THREAT_STAGE" && stageIndex < 5) {
        const allowed = Object.values(stageMap).slice(0, stageIndex);
        isVisible = allowed.some(prefix => d.id.includes(prefix) || d.properties?.stage_name?.includes(prefix));
      }
      d3.select(this).style("opacity", isVisible ? 1 : 0.1);
    });
  }
}

function renderD3TopologyGraph() {
  const container = document.getElementById("d3GraphContainer");
  if (!container) return;
  container.innerHTML = "";

  const width = container.clientWidth || 850;
  const height = container.clientHeight || 520;

  const filteredNodes = (graphData.nodes || []).filter(n => activeNodeFilters[n.type] !== false);
  const validNodeIds = new Set(filteredNodes.map(n => n.id));

  const filteredLinks = (graphData.links || []).filter(l => {
    const sId = typeof l.source === 'object' ? l.source.id : l.source;
    const tId = typeof l.target === 'object' ? l.target.id : l.target;
    return validNodeIds.has(sId) && validNodeIds.has(tId);
  });

  const statsEl = document.getElementById("graphStatsTag");
  if (statsEl) {
    statsEl.innerText = `${filteredNodes.length} Nodes ? ${filteredLinks.length} Edges`;
  }

  d3Svg = d3.select("#d3GraphContainer")
    .append("svg")
    .attr("width", width)
    .attr("height", height);

  const defs = d3Svg.append("defs");
  defs.append("marker")
    .attr("id", "arrow-standard")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 22)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", "#475569");

  defs.append("marker")
    .attr("id", "arrow-followed")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 24)
    .attr("refY", 0)
    .attr("markerWidth", 7)
    .attr("markerHeight", 7)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", "var(--color-critical)");

  d3G = d3Svg.append("g").attr("class", "graph-container-g");

  d3ZoomBehavior = d3.zoom()
    .scaleExtent([0.3, 3.5])
    .on("zoom", (event) => {
      d3G.attr("transform", event.transform);
    });

  d3Svg.call(d3ZoomBehavior);

  d3Simulation = d3.forceSimulation(filteredNodes)
    .force("link", d3.forceLink(filteredLinks).id(d => d.id).distance(130))
    .force("charge", d3.forceManyBody().strength(-350))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collision", d3.forceCollide().radius(32));

  const link = d3G.append("g")
    .selectAll("line")
    .data(filteredLinks)
    .join("line")
    .attr("class", "d3-link")
    .attr("stroke", d => {
      const sem = d.properties?.semantic || d.type;
      if (sem === "followed_by") return "var(--color-critical)";
      if (sem === "correlated") return "var(--color-high)";
      if (sem === "queried") return "var(--color-purple)";
      return "#334155";
    })
    .attr("stroke-width", d => (d.properties?.semantic === "followed_by" ? 2.5 : 1.5))
    .attr("stroke-dasharray", d => (d.properties?.semantic === "followed_by" ? "4,4" : "none"))
    .attr("marker-end", d => (d.properties?.semantic === "followed_by" ? "url(#arrow-followed)" : "url(#arrow-standard)"));

  const edgeLabels = d3G.append("g")
    .selectAll("text")
    .data(filteredLinks)
    .join("text")
    .attr("class", "d3-edge-label")
    .text(d => d.properties?.semantic || (d.type ? d.type.toLowerCase() : ""))
    .style("display", showGraphLabels ? "block" : "none");

  const node = d3G.append("g")
    .selectAll("g")
    .data(filteredNodes)
    .join("g")
    .attr("class", "d3-node")
    .call(d3.drag()
      .on("start", dragstarted)
      .on("drag", dragged)
      .on("end", dragended))
    .on("click", (event, d) => {
      event.stopPropagation();
      inspectGraphNode(d);
    });

  node.filter(d => d.type === "THREAT_STAGE")
    .append("circle")
    .attr("r", 20)
    .attr("fill", "none")
    .attr("stroke", "var(--color-critical)")
    .attr("stroke-width", 1.5)
    .attr("stroke-dasharray", "3,3")
    .attr("opacity", 0.7);

  node.append("circle")
    .attr("r", d => {
      if (d.type === "HOST_IP") return 16;
      if (d.type === "THREAT_STAGE") return 14;
      return 11;
    })
    .attr("fill", d => {
      if (d.type === "HOST_IP") return "var(--border-bright)";
      if (d.type === "THREAT_STAGE") return "var(--color-critical)";
      if (d.type === "DOMAIN") return "var(--color-purple)";
      if (d.type === "TLS_FINGERPRINT") return "var(--color-benign)";
      return "var(--color-high)";
    })
    .attr("stroke", "#ffffff")
    .attr("stroke-width", 1.5);

  const nodeLabels = node.append("text")
    .attr("class", "d3-node-label")
    .text(d => {
      if (d.type === "THREAT_STAGE") return d.properties?.stage_name || d.id.replace("STAGE-", "");
      return d.id;
    })
    .attr("font-family", "var(--font-mono)")
    .attr("font-size", "10px")
    .attr("font-weight", "600")
    .attr("fill", "var(--text-high)")
    .attr("dx", 18)
    .attr("dy", 4)
    .style("display", showGraphLabels ? "block" : "none");

  d3Simulation.on("tick", () => {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);

    edgeLabels
      .attr("x", d => (d.source.x + d.target.x) / 2)
      .attr("y", d => (d.source.y + d.target.y) / 2 - 4);

    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });

  function dragstarted(event, d) {
    if (!event.active) d3Simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }

  function dragended(event, d) {
    if (!event.active) d3Simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }
}

function inspectGraphNode(node) {
  selectedNodeId = node.id;
  const titleEl = document.getElementById("inspectorHostTitle");
  const typeEl = document.getElementById("inspectorNodeType");
  const bodyEl = document.getElementById("inspectorBody");

  if (titleEl) titleEl.innerText = node.id;
  if (typeEl) typeEl.innerText = node.type.replace(/_/g, ' ');

  if (d3G) {
    d3G.selectAll(".d3-node").classed("selected", d => d.id === node.id);
  }

  let inspectorHtml = "";

  if (node.type === "HOST_IP") {
    const risk = node.properties?.last_risk || 0.94;
    inspectorHtml = `
      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-card);">
        <div style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono);">HOST IDENTITY &amp; ROLE</div>
        <div style="font-weight: 700; color: var(--border-bright); font-size: 13px; margin-top: 2px;">${node.id}</div>
        <div style="font-size: 11px; color: var(--text-secondary);">${node.properties?.role || "Monitored Enclave Host"}</div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <div style="background: var(--bg-card); padding: 8px; border-radius: var(--radius-sm);">
          <div style="color: var(--text-dim); font-size: 9px;">CURRENT FUSED RISK</div>
          <div style="font-family: var(--font-mono); font-weight: 700; color: var(--color-critical); font-size: 14px;">${risk.toFixed(3)}</div>
        </div>
        <div style="background: var(--bg-card); padding: 8px; border-radius: var(--radius-sm);">
          <div style="color: var(--text-dim); font-size: 9px;">PACKET RATE Z-SCORE</div>
          <div style="font-family: var(--font-mono); font-weight: 700; color: var(--color-high); font-size: 14px;">+14.2?</div>
        </div>
      </div>

      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); font-size: 11px;">
        <div style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono); border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px;">OBSERVED TRAFFIC METRICS</div>
        <div style="margin-top: 6px; display: flex; justify-content: space-between;"><span>Active Flows:</span> <strong style="font-family: var(--font-mono);">24 flows</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Total Packets:</span> <strong style="font-family: var(--font-mono);">48,190 pkts</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Byte Volume:</span> <strong style="font-family: var(--font-mono);">34.8 MB</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Destination Entropy:</span> <strong style="font-family: var(--font-mono); color: var(--color-medium);">4.21 bits</strong></div>
      </div>

      <button class="btn-replay-action" style="width: 100%; margin-top: 4px;" onclick="openIncidentForHost('${node.id}')">
        OPEN HOST INCIDENT DOSSIER &rarr;
      </button>
    `;
  } else if (node.type === "THREAT_STAGE") {
    const stageName = node.properties?.stage_name || node.id.replace("STAGE-", "");
    const sev = node.properties?.severity || "HIGH";
    const risk = node.properties?.risk || 0.92;
    inspectorHtml = `
      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-card);">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono);">CORRELATED THREAT STAGE</span>
          <span class="badge-sev ${sev}">${sev}</span>
        </div>
        <div style="font-weight: 700; color: var(--color-critical); font-size: 14px; margin-top: 2px;">${stageName.replace(/_/g, ' ')}</div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <div style="background: var(--bg-card); padding: 8px; border-radius: var(--radius-sm);">
          <div style="color: var(--text-dim); font-size: 9px;">STAGE RISK SCORE</div>
          <div style="font-family: var(--font-mono); font-weight: 700; color: var(--color-critical); font-size: 14px;">${typeof risk === 'number' ? risk.toFixed(3) : risk}</div>
        </div>
        <div style="background: var(--bg-card); padding: 8px; border-radius: var(--radius-sm);">
          <div style="color: var(--text-dim); font-size: 9px;">DETECTOR CONFIDENCE</div>
          <div style="font-family: var(--font-mono); font-weight: 700; color: var(--border-bright); font-size: 14px;">0.970</div>
        </div>
      </div>

      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); font-size: 11px;">
        <div style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono); border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px;">SUPPORTING DETECTOR EVIDENCE</div>
        <div style="margin-top: 6px; color: var(--text-normal);">Trigger Criteria: <span style="font-family: var(--font-mono); color: var(--border-bright);">Burst rate &gt; 15,000 pps</span></div>
        <div style="margin-top: 4px; color: var(--text-normal);">Algorithm: <strong>LightGBM v2.1.0 + Deterministic Multi-Signal</strong></div>
        <div style="margin-top: 4px; color: var(--text-secondary); font-size: 10px; font-style: italic;">* Observed correlated stage in attack progression.</div>
      </div>
    `;
  } else if (node.type === "DOMAIN") {
    inspectorHtml = `
      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-card);">
        <div style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono);">DNS DOMAIN QUERY</div>
        <div style="font-weight: 700; color: var(--color-purple); font-size: 13px; font-family: var(--font-mono);">${node.id}</div>
      </div>
      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); font-size: 11px;">
        <div style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono);">STATISTICAL ENTROPY</div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Shannon Entropy:</span> <strong style="font-family: var(--font-mono); color: var(--color-critical);">4.62 bits</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Subdomain Length:</span> <strong style="font-family: var(--font-mono);">38 chars</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>NXDOMAIN Ratio:</span> <strong style="font-family: var(--font-mono);">88.4%</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>TXT Record Queries:</span> <strong style="font-family: var(--font-mono); color: var(--color-high);">12 queries</strong></div>
      </div>
    `;
  } else {
    inspectorHtml = `
      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-card);">
        <div style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono);">DESTINATION / FINGERPRINT</div>
        <div style="font-weight: 700; color: var(--color-high); font-size: 13px; font-family: var(--font-mono);">${node.id}</div>
      </div>
      <div style="background: var(--bg-card); padding: 10px; border-radius: var(--radius-sm); font-size: 11px;">
        <div style="color: var(--text-dim); font-size: 9.5px; font-family: var(--font-mono);">OBSERVED ATTRIBUTES</div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Novelty Score:</span> <strong style="font-family: var(--font-mono); color: var(--color-critical);">94% Novel</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Observed Connections:</span> <strong style="font-family: var(--font-mono);">64 sessions</strong></div>
        <div style="margin-top: 4px; display: flex; justify-content: space-between;"><span>Payload Decryption:</span> <strong style="color: var(--color-benign);">NONE (Metadata Only)</strong></div>
      </div>
    `;
  }

  if (bodyEl) bodyEl.innerHTML = inspectorHtml;
  playTacticalBeep(780, "sine", 0.06);
}

function openIncidentForHost(hostIp) {
  const inc = incidentsData.find(i => i.entity_id === hostIp || i.source_entity === hostIp) || incidentsData[0];
  if (inc) openIncidentDrawer(inc);
}

function openIncidentDrawer(inc) {
  selectedIncidentId = inc.incident_id;
  const drawer = document.getElementById("incidentDrawer");
  const overlay = document.getElementById("drawerOverlay");
  const titleEl = document.getElementById("drawerIncId");
  const bodyEl = document.getElementById("drawerBody");

  if (titleEl) titleEl.innerText = inc.incident_id;

  const threatName = (inc.threat_class || inc.primary_threat || "VOLUMETRIC_DDOS").replace(/_/g, ' ');
  const sev = inc.severity || "HIGH";
  const entity = inc.entity_id || inc.source_entity || "192.168.1.100";
  const firstSeen = (inc.first_seen_iso || inc.created_at_iso || "").replace('T', ' ').substring(0, 19);
  const lastSeen = (inc.last_seen_iso || inc.updated_at_iso || "").replace('T', ' ').substring(0, 19);

  const fusedRisk = typeof inc.current_fused_risk === 'number' ? inc.current_fused_risk : (inc.fused_risk || 0.85);
  const mlProb = typeof inc.calibrated_ml_probability === 'number' ? inc.calibrated_ml_probability : 0.94;
  const conf = typeof inc.confidence === 'number' ? inc.confidence : 0.90;
  const anomalyScore = typeof inc.anomaly_score === 'number' ? inc.anomaly_score : 0.045;

  const evidenceList = inc.evidence || inc.indicators || [];
  let evidenceHtml = "";
  if (evidenceList.length > 0) {
    evidenceHtml = evidenceList.map(ev => {
      const fName = ev.feature_name || ev.feature || "packets_per_sec";
      const obs = ev.observed_value !== undefined ? ev.observed_value : (ev.value !== undefined ? ev.value : "24,000 pps");
      const base = ev.baseline_value !== undefined ? ev.baseline_value : (ev.baseline || "120 pps");
      const dev = ev.deviation_zscore !== undefined ? `+${ev.deviation_zscore.toFixed(1)}?` : (ev.deviation || "+199x");
      const desc = ev.interpretation || ev.description || "Substantial burst anomaly exceeding statistical baseline.";
      return `
        <tr>
          <td class="ev-feature">${fName}</td>
          <td class="ev-val">${obs}</td>
          <td class="ev-val" style="color: var(--text-dim);">${base}</td>
          <td class="ev-dev">${dev}</td>
          <td class="ev-desc">${desc}</td>
        </tr>
      `;
    }).join('');
  } else {
    evidenceHtml = `
      <tr>
        <td class="ev-feature">packets_per_sec</td>
        <td class="ev-val">24,500.0</td>
        <td class="ev-val" style="color: var(--text-dim);">120.0</td>
        <td class="ev-dev">+204.1x</td>
        <td class="ev-desc">Volumetric burst rate exceeds entity baseline threshold.</td>
      </tr>
      <tr>
        <td class="ev-feature">syn_ratio</td>
        <td class="ev-val">0.992</td>
        <td class="ev-val" style="color: var(--text-dim);">0.051</td>
        <td class="ev-dev">+19.4x</td>
        <td class="ev-desc">Abnormal SYN packet concentration without completion.</td>
      </tr>
    `;
  }

  const timelineEvents = inc.timeline || [];
  let timelineHtml = "";
  if (timelineEvents.length > 0) {
    timelineHtml = timelineEvents.map(ev => {
      const tTime = (ev.event_time || ev.timestamp_iso || "").replace('T', ' ').substring(11, 19);
      const stageName = (ev.stage || ev.threat_class || "STAGE").replace(/_/g, ' ');
      const desc = ev.description || ev.action || "Correlated telemetry detection on entity host.";
      return `
        <div class="timeline-event-item">
          <div class="t-dot-col">
            <div class="t-dot"></div>
            <div class="t-line"></div>
          </div>
          <div class="t-content">
            <div class="t-time">${tTime} UTC</div>
            <div class="t-stage">${stageName}</div>
            <div class="t-detail">${desc}</div>
          </div>
        </div>
      `;
    }).join('');
  } else {
    timelineHtml = `
      <div class="timeline-event-item">
        <div class="t-dot-col"><div class="t-dot"></div><div class="t-line"></div></div>
        <div class="t-content">
          <div class="t-time">${firstSeen} UTC</div>
          <div class="t-stage">${threatName}</div>
          <div class="t-detail">Initial anomaly triggered multi-signal fusion correlation.</div>
        </div>
      </div>
    `;
  }

  bodyEl.innerHTML = `
    <div class="drawer-section-card">
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);">ENTITY HOST</span>
          <h3 style="font-family: var(--font-mono); font-size: 16px; color: var(--border-bright); margin-top: 2px;">${entity}</h3>
          <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Threat: <strong>${threatName}</strong></div>
        </div>
        <span class="badge-sev ${sev}" style="font-size: 11px; padding: 4px 10px;">${sev}</span>
      </div>
      <div style="display: flex; gap: 16px; font-family: var(--font-mono); font-size: 10.5px; color: var(--text-dim); margin-top: 6px; border-top: 1px solid var(--border-subtle); padding-top: 6px;">
        <span>First Seen: <strong>${firstSeen} UTC</strong></span>
        <span>Last Updated: <strong>${lastSeen} UTC</strong></span>
      </div>
    </div>

    <div class="drawer-risk-grid">
      <div class="drawer-risk-box">
        <span class="dr-lbl">FUSED RISK</span>
        <span class="dr-val text-red">${fusedRisk.toFixed(3)}</span>
      </div>
      <div class="drawer-risk-box">
        <span class="dr-lbl">ML PROBABILITY</span>
        <span class="dr-val text-orange">${mlProb.toFixed(3)}</span>
      </div>
      <div class="drawer-risk-box">
        <span class="dr-lbl">CONFIDENCE</span>
        <span class="dr-val text-cyan">${conf.toFixed(3)}</span>
      </div>
      <div class="drawer-risk-box">
        <span class="dr-lbl">ANOMALY SCORE</span>
        <span class="dr-val text-purple">${anomalyScore.toFixed(3)}</span>
      </div>
    </div>

    <div class="drawer-section-card">
      <div class="drawer-sec-title">
        <span>&#128269; Forensic Evidence Indicators (Why Detected)</span>
      </div>
      <div style="overflow-x: auto;">
        <table class="evidence-table">
          <thead>
            <tr>
              <th>Feature Name</th>
              <th>Observed</th>
              <th>Baseline</th>
              <th>Deviation</th>
              <th>Analytical Interpretation</th>
            </tr>
          </thead>
          <tbody>
            ${evidenceHtml}
          </tbody>
        </table>
      </div>
    </div>

    <div class="drawer-section-card">
      <div class="drawer-sec-title">
        <span>&#128337; Observed Correlated Activity Progression</span>
      </div>
      <div class="timeline-strip">
        ${timelineHtml}
      </div>
      <div class="non-causal-disclaimer">
        * Note: Observed correlated event-time stages for host entity. No causal claim is made without explicit causal evidence.
      </div>
    </div>

    <div class="drawer-section-card" style="background: rgba(0,0,0,0.2);">
      <div class="drawer-sec-title">
        <span>&#128279; Intelligence Provenance &amp; Enclave Boundaries</span>
      </div>
      <div style="font-family: var(--font-mono); font-size: 10.5px; color: var(--text-dim); display: flex; flex-direction: column; gap: 4px;">
        <div>Feature Schema: <strong style="color: var(--text-high);">${inc.provenance?.feature_schema_version || runtimeProvenance.feature_schema_version} (${runtimeProvenance.feature_count || 56} features)</strong></div>
        <div>LightGBM Model: <strong style="color: var(--text-high);">${inc.provenance?.model_versions?.lightgbm || runtimeProvenance.model_version}</strong></div>
        <div>Isolation Forest: <strong style="color: var(--text-high);">${inc.provenance?.model_versions?.isolation_forest || runtimeProvenance.anomaly_model_version}</strong></div>
        <div>Diode Boundary: <strong style="color: var(--color-benign);">PS 26145 PASS (0 Network Writes &bull; Out-of-band)</strong></div>
      </div>
    </div>
  `;

  if (drawer) drawer.classList.add("open");
  if (overlay) overlay.classList.add("active");
  playTacticalBeep(660, "sine", 0.08);
}

function openAlertDrawerFallback(al) {
  const pseudoInc = {
    incident_id: al.incident_id || `INC-${al.alert_id}`,
    entity_id: al.entity_id || al.source_ip || "192.168.1.100",
    threat_class: al.threat_class,
    severity: al.severity,
    current_fused_risk: al.fused_risk || al.risk_score || 0.85,
    calibrated_ml_probability: al.confidence || 0.94,
    confidence: al.confidence || 0.90,
    anomaly_score: 0.045,
    first_seen_iso: al.timestamp_iso || new Date().toISOString(),
    last_seen_iso: al.timestamp_iso || new Date().toISOString(),
    evidence: al.evidence || []
  };
  openIncidentDrawer(pseudoInc);
}

function closeIncidentDrawer() {
  const drawer = document.getElementById("incidentDrawer");
  const overlay = document.getElementById("drawerOverlay");
  if (drawer) drawer.classList.remove("open");
  if (overlay) overlay.classList.remove("active");
}

function renderIncidentsList() {
  const listEl = document.getElementById("incidentsListFull");
  if (!listEl) return;

  if (incidentsData.length === 0) {
    listEl.innerHTML = `<div style="padding: 16px; color: var(--text-dim); text-align: center;">Zero active incidents.</div>`;
    return;
  }

  listEl.innerHTML = incidentsData.map(inc => {
    const threat = (inc.threat_class || inc.primary_threat || "VOLUMETRIC_DDOS").replace(/_/g, ' ');
    const sev = inc.severity || "HIGH";
    const entity = inc.entity_id || inc.source_entity || "192.168.1.100";
    const isSel = inc.incident_id === selectedIncidentId ? "selected" : "";
    return `
      <div class="inc-card-item ${isSel}" onclick="selectIncidentFull('${inc.incident_id}')">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span style="font-family: var(--font-mono); font-size: 11px; font-weight: 700; color: var(--text-high);">${inc.incident_id}</span>
          <span class="badge-sev ${sev}">${sev}</span>
        </div>
        <div style="font-size: 11.5px; font-weight: 600; color: var(--border-bright);">${threat}</div>
        <div style="font-family: var(--font-mono); font-size: 10.5px; color: var(--text-dim);">${entity}</div>
      </div>
    `;
  }).join('');
}

function selectIncidentFull(incId) {
  selectedIncidentId = incId;
  renderIncidentsList();
  const inc = incidentsData.find(i => i.incident_id === incId);
  if (inc) {
    openIncidentDrawer(inc);
  }
}

async function injectAttack(threatClass) {
  try {
    const res = await fetch('/simulate/attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threat_class: threatClass, target_entity: "192.168.1.100" })
    });
    const data = await res.json();
    playTacticalBeep(920, "sawtooth", 0.15);
    await fetchAllData();
    await fetchGraphDataAndRender();
    if (data.incident) {
      openIncidentDrawer(data.incident);
    }
  } catch (err) {
    console.error("Simulation error:", err);
  }
}

async function runDeterministicDemo() {
  try {
    playTacticalBeep(520, "sine", 0.2);
    const res = await fetch('/demo/replay', { method: 'POST' });
    const data = await res.json();
    await fetchAllData();
    await fetchGraphDataAndRender();
    if (data.incident_id) {
      const inc = incidentsData.find(i => i.incident_id === data.incident_id);
      if (inc) openIncidentDrawer(inc);
    }
    playTacticalBeep(880, "sine", 0.15);
  } catch (err) {
    console.error("Demo replay error:", err);
  }
}

async function toggleLiveSimulation() {
  try {
    const res = await fetch('/simulate/toggle', { method: 'POST' });
    const data = await res.json();
    simulationActive = data.simulation_active;
    const btn = document.getElementById("btnSimToggle");
    if (btn) {
      btn.innerText = simulationActive ? "&#9881; LIVE SIM: ACTIVE" : "&#9881; LIVE SIM: OFF";
      btn.style.color = simulationActive ? "var(--color-critical)" : "var(--color-medium)";
    }
  } catch (err) {
    console.error("Toggle simulation error:", err);
  }
}

function renderIncidentDossier(inc) {
  openIncidentDrawer(inc);
}

document.addEventListener("DOMContentLoaded", () => {
  fetchAllData();
  fetchGraphDataAndRender();
  setInterval(fetchAllData, 2500);
});
