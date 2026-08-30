# Unidirectional IP Threat Detection System (PS 26145)

> **National Technical Research Organisation (NTRO) — Smart India Hackathon**  
> **Problem Statement ID:** 26145  
> **Theme:** Blockchain & Cybersecurity | **Category:** Software  
> **Repository:** [https://github.com/Anuj2862/145](https://github.com/Anuj2862/145)

---

## 📌 Project Overview
This project is an **AI-based cyber threat detection, classification, scoring, and incident reconstruction system** designed specifically for **strictly unidirectional IP traffic** in high-security, air-gapped, or diode-isolated critical infrastructure.

### The Operational Reality
- **Read-Only / Air-Gapped Monitoring:** Traffic is observed passively across a hardware data diode or optical TAP / SPAN mirror.
- **No Return Path:** The monitoring system cannot send probes, complete TCP handshakes, inject resets, or interact with monitored endpoints.
- **No Payload Decryption:** The system analyzes TLS 1.3 / QUIC traffic using metadata, handshake fingerprints (JA3/JA4, SNI, ALPN), packet size sequences, directions, and timings.
- **Entity-Centric Multi-Signal Correlation:** Correlates multiple weak behavioral indicators across time and protocols into structured, explainable incidents with concrete evidence.

---

## 📁 Repository Structure

```text
/
├── README.md                       # Main repository overview & onboarding guide
│
├── docs/                           # Comprehensive engineering & research documentation
│   ├── problem-statement.md        # Official Problem Statement 26145 text & requirements
│   ├── project-context.md          # Environmental constraints & threat classes
│   ├── architecture.md             # High-level pipeline, Fast Path vs. Slow Path design
│   ├── implementation-plan.md      # Tiered roadmap & definition of done per milestone
│   ├── team.md                     # 3-member responsibility matrix & shared ownership
│   ├── dataset.md                  # Dataset strategy, lab traffic generation & ground truth
│   ├── evaluation-plan.md          # Evaluation metrics, benchmarking & ablation study
│   ├── threat-model.md             # Security boundaries, attacker profiles & safeguards
│   ├── design-decisions.md         # Architectural rationale & frozen decisions
│   ├── git-workflow.md             # Git branching, PR rules, commit conventions & merge policy
│   └── research/
│       ├── 00-project-map.md       # Conceptual hierarchy from PS to evaluation
│       └── sans-research.md        # Industry research context (SANS & C2 analysis)
│
├── schemas/                        # Shared data contracts (FlowEvent, FeatureVector, etc.)
│   └── contracts.md
│
├── ingest/                         # [Member 1] Packet capture, PCAP parsing & replay
├── flow/                           # [Member 1] 5-tuple flow state & tiered sliding windows
├── features/                       # [Member 2] Feature extraction (Flow, DNS, TLS, Temporal)
├── detectors/                      # [Member 2] Deterministic baselines, ML & anomaly models
├── entity/                         # [Member 3] Entity memory, baseline profiling & graph
├── fusion/                         # [Member 3] Multi-signal correlation & risk scoring
├── evidence/                       # [Member 3] Explainable reasoning & indicator generator
├── incidents/                      # [Member 3] Incident timeline reconstruction & lifecycle
├── api/                            # [Member 3] FastAPI backend service
├── dashboard/                      # [Member 3] Frontend visualization & UI
│
├── dataset/                        # Benchmark PCAPs & ground-truth JSON manifests
├── evaluation/                     # Automated benchmarking, metrics & ablation test scripts
├── tests/                          # Unit, integration & schema validation test suites
└── docker/                         # Containerization & environment definitions
```

---

## 👥 Team Work Division & Branching Model

```text
                      main (Stable / Demo-Ready)
                       │
                       ▼
                 integration (Integration & Testing)
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
      member-1/     member-2/     member-3/
   ingestion-flow  detection-ml  entity-dashboard
```

| Member | Primary Focus | Core Directories | Branch |
| :--- | :--- | :--- | :--- |
| **Member 1** | Ingestion, PCAP replay, 5-tuple flow state, sliding windows | `ingest/`, `flow/`, `schemas/`, `tests/` | `member-1/ingestion-flow` |
| **Member 2** | Feature extractors, deterministic baselines, ML models, ablation | `features/`, `detectors/`, `evaluation/`, `schemas/`, `tests/` | `member-2/detection-ml` |
| **Member 3** | Entity memory, behaviour graph, multi-signal fusion, API & dashboard | `entity/`, `fusion/`, `evidence/`, `incidents/`, `api/`, `dashboard/` | `member-3/entity-dashboard` |

---

## 🚀 Development Workflow Summary
1. All developers branch off `integration`.
2. Work is bounded by the shared schema contracts in [`schemas/contracts.md`](file:///Users/anuj/Desktop/145/schemas/contracts.md).
3. Changes merge into `integration` via Pull Requests with mandatory review and test verification.
4. `integration` is promoted to `main` only after milestone verification.

For full guidelines, read [`docs/git-workflow.md`](file:///Users/anuj/Desktop/145/docs/git-workflow.md).
