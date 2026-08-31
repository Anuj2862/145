# UniGuard AI &bull; Unidirectional Cyber Threat Intelligence System

> **National Technical Research Organisation (NTRO) — Smart India Hackathon**  
> **Problem Statement ID:** 26145  
> **Theme:** Blockchain & Cybersecurity | **Category:** Software  
> **Repository:** [https://github.com/Anuj2862/145](https://github.com/Anuj2862/145)  
> **Status:** 🟢 **WORKING PROTOTYPE VERIFIED (308/308 Tests Passing)**

---

## 📌 Executive Summary

**UniGuard AI** is a passive, streaming cyber threat detection, entity behavioral profiling, and incident reconstruction system built specifically for **unidirectional IP traffic** in high-security, air-gapped critical infrastructure and diode-isolated security enclaves.

```text
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                           PASSIVE UNIDIRECTIONAL IP INGESTION                             │
│                  (Hardware Data Diode / Optical TAP / SPAN Port Mirror)                   │
└─────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                              │ ⚡ Strictly Rx-Only (Zero Return Path)
                                              ▼
┌───────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────┐
│         MEMBER 1          │    │         MEMBER 2          │    │         MEMBER 3          │
│ Ingestion & Flow Engine   │    │ Features & Detection ML   │    │ Entity Intel & Dashboard  │
├───────────────────────────┤    ├───────────────────────────┤    ├───────────────────────────┤
│ • Zero-dep PCAP Parser    │    │ • 5 Feature Families      │    │ • Rolling Entity Memory   │
│ • 5-Tuple Flow State      │    │ • 6 Heuristic Detectors   │    │ • Behaviour Graph Engine  │
│ • Sliding Windows (5s)    │───►│ • LightGBM Multi-class    │───►│ • Multi-Signal Fusion     │
│ • PCAP Replay Controller  │    │ • Isolation Forest Anomaly│    │ • Evidence & Incident Doc │
│ • Flow Key & Manager      │    │ • Signal Adapters         │    │ • FastAPI & SOC Dashboard │
└───────────────────────────┘    └───────────────────────────┘    └───────────────────────────┘
                                              │
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                 INTERACTIVE SOC COMMAND DASHBOARD & REST / WEBSOCKET API                  │
│       (Live Waveform Oscilloscope • 2D Physics Graph • Attack Injector • Evidence Modal)   │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Core Invariants & Engineering Constraints (PS 26145)

1. **Strictly Passive / One-Way Monitoring:** Monitored traffic is ingested across an optical data diode or TAP. The system has **no transmitter (Tx)**, sends zero active probes, completes no TCP handshakes, injects no TCP resets, and performs no inline blocking.
2. **Zero Payload Decryption:** Observes TLS 1.3, HTTPS, and QUIC traffic purely through observable protocol metadata (JA3/JA4 fingerprints, SNI, ALPN, packet size sequences, directional byte ratios, and inter-arrival timing).
3. **Dual Detection Engine:** Combines deterministic rule-based baselines (for instant, explainable detection of known attacks) with machine learning models (LightGBM multi-class classifier and Isolation Forest unsupervised anomaly detector).
4. **Entity-Centric Multi-Signal Correlation:** Rather than spamming raw alerts, weak independent signals from the same host are correlated over temporal sliding windows into unified, scored **Incident Dossiers** complete with attack lifecycle stages and human-readable evidence chains.

---

## ✨ Working Prototype Features

- 🖥️ **Cyber SOC Command Dashboard (`/`):** Full dark-mode tactical interface featuring real-time telemetry KPI counters, live alert stream, interactive entity graph, and incident dossier inspector.
- ⚡ **Interactive Attack Injector Quick-Bar:** One-click simulation triggers for:
  - **`[⚡ DDoS Flood]`**: High-volume TCP SYN bursts ($\approx 24{,}000\text{ pps}$) triggering volume heuristics and $+5.2\sigma$ Z-score anomaly spikes.
  - **`[📡 C2 Beacon]`**: Periodic low-jitter botnet heartbeat callbacks to command nodes.
  - **`[🧬 DGA / DNS]`**: High Shannon entropy algorithmic domain queries and tunneling.
  - **`[🔐 Exfil]`**: Multi-megabyte outbound data exfiltration bursts over unidirectional channels.
  - **`[🔍 Recon]`**: High-cardinality port scanning sweeps.
  - **`[▶️ LIVE STREAM]`**: Continuous background traffic generation and threat simulation.
- 📈 **Passive Ingress Oscilloscope:** Real-time animated canvas waveform visualizing ingress velocity, bandwidth (Mbps), and instantaneous Z-score bursts.
- 🕸️ **2D Spring-Physics Entity Behaviour Graph:** Canvas-rendered force-directed network graph with glowing node halos, particle animations along communication links, and draggable entity nodes.
- 📋 **Explainable Incident Dossiers:** Standardized incident dossiers linking MITRE/Cyber Kill Chain stages (`RECONNAISSANCE` $\rightarrow$ `C2_ESTABLISHMENT` $\rightarrow$ `EXFILTRATION`) with forensic evidence chains and SOC mitigation directives.
- 🚀 **FastAPI Backend & WebSockets (`/docs`):** Production REST API and real-time WebSocket feeds for SIEM integration.

---

## ⚡ Quickstart Guide

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.13)
- macOS / Linux / Windows

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/Anuj2862/145.git
cd 145

# Install dependencies
pip install -r requirements.txt
```

### 3. Launch the SOC Command Dashboard & API Server
```bash
PYTHONPATH=. uvicorn api.app:app --host 0.0.0.0 --port 8080 --reload
```
- Open your browser at: **[http://localhost:8080/](http://localhost:8080/)**
- Explore interactive API documentation at: **[http://localhost:8080/docs](http://localhost:8080/docs)**
- Query system telemetry health at: **[http://localhost:8080/health](http://localhost:8080/health)**

### 4. Run the Full Test Suite
```bash
PYTHONPATH=. pytest tests/
```

### 5. Run Standalone Terminal Verification
```bash
PYTHONPATH=. python3 incidents/verifier.py
```

### 6. Process an Offline PCAP Capture
```python
from pipeline.integrated_runner import IntegratedThreatPipeline

pipeline = IntegratedThreatPipeline()
stats = pipeline.process_pcap("path/to/capture.pcap")
print(stats.to_dict())
```

---

## 📊 Benchmark & Accuracy Results

| Metric | Result | Description |
| :--- | :--- | :--- |
| **Unit & Integration Tests** | **308 / 308 (100%)** | Full test coverage across Members 1, 2, and 3 |
| **LightGBM Multi-Class Accuracy** | **99.89%** | Evaluated across 7 threat classes on validation set |
| **LightGBM Macro F1-Score** | **0.9985** | Balanced performance across imbalanced traffic splits |
| **Isolation Forest Anomaly Throughput** | **374,976 samples/sec** | Ultra-low latency unsupervised anomaly detection |
| **Streaming Ingestion Latency** | **< 1.0 second** | Sub-second sliding window feature evaluation |

---

## 📁 Repository Directory Structure

```text
/
├── README.md                       # Main working prototype overview & quickstart
├── requirements.txt                # Production and test dependencies
│
├── api/                            # [Member 3] FastAPI REST and WebSocket service
│   ├── app.py                      # REST endpoints, simulation engine & static UI mount
│   └── __init__.py
│
├── dashboard/                      # [Member 3] Cyber SOC Web Dashboard
│   ├── index.html                  # Tactical command center UI layout
│   ├── style.css                   # Cyberpunk glassmorphism design system
│   └── app.js                      # Canvas oscilloscope, physics graph & state engine
│
├── ingest/                         # [Member 1] Packet capture & PCAP parsing
│   ├── pcap_reader.py              # Zero-dependency binary PCAP reader
│   └── __init__.py
│
├── flow/                           # [Member 1] 5-tuple flow & window management
│   ├── flow_key.py                 # 5-tuple immutable flow hashing
│   ├── flow_state.py               # Active flow accumulators & statistics
│   ├── flow_manager.py             # Capacity-bounded active flow registry
│   ├── windows.py                  # Dual sliding burst & timing window manager
│   └── __init__.py
│
├── features/                       # [Member 2] Multi-family feature extractors
│   ├── flow_features.py            # Flow velocity & flag ratios
│   ├── dns_features.py             # DNS entropy, query length & NXDomain ratios
│   ├── tls_features.py             # JA3/JA4 fingerprinting & handshake metadata
│   ├── temporal_features.py        # Periodic beaconing & inter-arrival statistics
│   ├── recon_features.py           # Port sweep cardinality & scan rates
│   ├── exfil_features.py           # Volume ratios, burstiness & transfer durations
│   └── __init__.py
│
├── detectors/                      # [Member 2] 6 Deterministic baseline threat detectors
│   ├── engine.py                   # Member-2 un-fused detector orchestration
│   ├── unified_detector.py         # Unified baseline + ML evaluation layer
│   ├── ddos_detector.py            # Volumetric DDoS SYN flood detector
│   ├── c2_detector.py              # C2 periodic beaconing detector
│   ├── dns_detector.py             # DGA & DNS tunneling detector
│   ├── encrypted_detector.py       # Encrypted malware & JA3 detector
│   ├── recon_detector.py           # Horizontal/vertical port scan detector
│   ├── exfil_detector.py           # Outbound data exfiltration detector
│   └── __init__.py
│
├── models/                         # [Member 2] Machine learning models & inference
│   ├── artifacts/                  # Serialized LightGBM & Isolation Forest models
│   ├── training/                   # Model training scripts & pipelines
│   └── inference/                  # Low-latency inference adapters
│
├── entity/                         # [Member 3] Entity memory & behavioral graph
│   ├── memory.py                   # Rolling host baselines & Z-score calculations
│   ├── graph.py                    # Directed temporal entity graph (D3 export)
│   └── __init__.py
│
├── fusion/                         # [Member 3] Multi-signal temporal correlation
│   ├── engine.py                   # Active correlation groups & fused risk scoring
│   └── __init__.py
│
├── evidence/                       # [Member 3] Explainable threat reasoning
│   ├── engine.py                   # MITRE attack stage mapping & evidence chains
│   └── __init__.py
│
├── incidents/                      # [Member 3] Incident reconstruction & alerts
│   ├── incident_builder.py         # Incident dossier construction
│   ├── alert_builder.py            # Standardized alert generation
│   ├── formatter.py                # JSON serialization & CLI formatting
│   ├── verifier.py                 # Standalone M1 verification runner
│   └── __init__.py
│
├── pipeline/                       # End-to-end integration & replay
│   ├── integrated_runner.py        # Unified streaming detection pipeline
│   ├── replay.py                   # Replay pipeline with rate throttling
│   └── __init__.py
│
├── schemas/                        # Shared Pydantic v2 data contracts
│   ├── flow_event.py
│   ├── feature_vector.py
│   ├── detection_signal.py
│   ├── entity_event.py
│   ├── incident.py
│   ├── alert.py
│   └── __init__.py
│
├── docs/                           # Architecture, problem statement & team docs
├── dataset/                        # Benchmark dataset generation & splits
└── tests/                          # 308 automated unit and integration tests
```

---

## 👥 Team Work Division

| Member | Focus Area | Core Modules |
| :--- | :--- | :--- |
| **Member 1** (Saurabh Gangurde) | Ingestion & Flow Engine | `ingest/`, `flow/`, `pipeline/replay.py` |
| **Member 2** | Features, Detectors & ML Inference | `features/`, `detectors/`, `models/`, `dataset/` |
| **Member 3** | Entity Intel, Graph, Fusion, API & Dashboard | `entity/`, `fusion/`, `evidence/`, `incidents/`, `api/`, `dashboard/`, `pipeline/integrated_runner.py` |

---

## 📜 License
Developed for the **Smart India Hackathon (NTRO Problem Statement 26145)**.
All rights reserved.
