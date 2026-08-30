# Team Structure & Ownership Matrix

## 1. Core Team Breakdown

```text
┌─────────────────────────────────────────────────────────────┐
│                       3-Person Team                         │
├───────────────────┬─────────────────────┬───────────────────┤
│     Member 1      │      Member 2       │     Member 3      │
│ Ingestion & Flow  │ Features, Detectors │ Entity Intel,     │
│   & Streaming     │       & ML          │ Fusion, Dashboard │
└───────────────────┴─────────────────────┴───────────────────┘
```

### Member 1: Ingestion, Flow & Streaming Infrastructure
- **Core Modules:** `ingest/`, `flow/`
- **Supporting:** `schemas/`, `tests/`
- **Branch:** `member-1/ingestion-flow`
- **Responsibilities:**
  - Raw packet ingestion and PCAP parsing.
  - PCAP replay engine with rate control ($1\times, 5\times, 10\times$).
  - 5-tuple unidirectional flow state tracking (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`).
  - Tiered sliding window management (5s, 30s, 5m).
  - Ingestion throughput benchmarking and memory boundedness.

### Member 2: Feature Extraction, Threat Detectors & ML
- **Core Modules:** `features/`, `detectors/`, `evaluation/`
- **Supporting:** `schemas/`, `tests/`
- **Branch:** `member-2/detection-ml`
- **Responsibilities:**
  - Feature extraction across 5 families (Flow, DNS, TLS/QUIC, Temporal, Entity-relative).
  - Deterministic baseline detectors for all 6 required threat classes + novel anomalies.
  - Supervised & unsupervised ML model training (LightGBM, Random Forest, Isolation Forest).
  - Baseline vs. ML comparative evaluation.
  - Feature ablation benchmark implementation.

### Member 3: Entity Intelligence, Incident Fusion & Dashboard
- **Core Modules:** `entity/`, `fusion/`, `evidence/`, `incidents/`, `api/`, `dashboard/`
- **Supporting:** `schemas/`, `tests/`
- **Branch:** `member-3/entity-dashboard`
- **Responsibilities:**
  - Rolling entity memory and historical baseline profiling.
  - Temporal Entity Behaviour Graph construction and querying.
  - Multi-signal fusion engine and risk scoring.
  - Evidence engine generating explainable reasoning chains.
  - Incident builder and timeline reconstruction.
  - FastAPI backend and interactive frontend dashboard.

---

## 2. Shared Ownership
All three team members jointly own:
- Architecture integrity and system-level design decisions.
- Cross-module schema contracts (`schemas/contracts.md`).
- Integration testing and CI verification on the `integration` branch.
- Dataset curation, lab attack scenario generation, and ground-truth labeling.
- Final benchmarking, technical documentation, and presentation.
