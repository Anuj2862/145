# Master Gap List & Change-Control Roadmap

> **PS 26145:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
> **Status:** 🔒 **FROZEN CHANGE-CONTROL DOCUMENT**

---

## 1. Original Final Aim vs. Current Implementation

The core innovation of **UniGuard AI** is:
> *"Correlate multiple weak behavioural signals at the entity level in a strictly passive, metadata-only environment, and turn those signals into explainable attack stories."*

### Architectural Status Comparison

| Planned Component | Implementation Status | Phase 2 Validation Requirement |
| :--- | :---: | :--- |
| **Passive PCAP Ingestion** | 🟢 Implemented | Measure packet parser throughput & zero packet drop |
| **Directional 5-Tuple Flows** | 🟢 Implemented | Verify directional flow state with asymmetric traffic |
| **Sliding Windows (5s / 30s)** | 🟢 Implemented | Verify memory bounding under high PPS |
| **Metadata Feature Engine** | 🟢 Implemented | Trace exact feature calculations from raw packets |
| **6 Threat Baseline Detectors** | 🟢 Implemented | Benchmark Precision/Recall/F1 per threat class |
| **ML & Anomaly Models** | 🟢 Implemented | Evaluate LightGBM vs. RF vs. Isolation Forest |
| **Entity Memory ($Z$-Scores)** | 🟢 Implemented | Validate baseline convergence and deviation accuracy |
| **Entity Behaviour Graph** | 🟢 Implemented | Verify temporal multi-stage attack chaining |
| **Multi-Signal Fusion Engine** | 🟢 Implemented | Prove empirical superiority over single-method baselines |
| **Explainable Evidence Chains** | 🟢 Implemented | Ensure every alert includes concrete observable metrics |
| **Standardized Incident Dossiers**| 🟢 Implemented | Verify MITRE stage mapping and lifecycle updates |
| **FastAPI Backend & SOC Dashboard**| 🟢 Implemented | Verify live alert/incident streaming without UI bloat |
| **Automated Software Tests** | 🟢 317 / 317 Passing | Maintain 100% test pass rate across all builds |
| **Empirical Benchmark on Ground Truth**| 🟡 **Phase 2B (Next)** | Run frozen pipeline on registered PCAP captures |
| **Ablation Studies** | 🟡 **Phase 2D** | Compare Mode A, B, C vs. Mode D (Hybrid Fusion) |
| **Adversarial Robustness Testing** | 🔴 **Phase 2E** | Test degradation under jitter, low-and-slow rates |

---

## 2. Master Modification Roadmap (12 Frozen Work Items)

This is the definitive list of permitted modifications for Phase 2:

```text
[1] Dataset & Ground Truth Infrastructure (Phase 2A - Done)
    └── Schema-enforced manifest + PCAP category storage

[2] End-to-End Replay Validation (Phase 2B)
    └── PCAP → Flow → Detection → Entity → Fusion → Alert using real captures

[3] Six Threat Class Empirical Validation (Phase 2B)
    ├── Volumetric DDoS (SYN & UDP flood patterns)
    ├── Botnet C2 Beaconing (Periodicity & low jitter callbacks)
    ├── DGA & DNS Tunnelling (Entropy & lexical anomalies)
    ├── Encrypted Threats (JA3/JA4 & TLS handshake metadata without decryption)
    ├── Reconnaissance (Horizontal & vertical port scanning)
    └── Data Exfiltration (Asymmetric outbound volume bursts)

[4] Entity Behaviour Graph Multi-Stage Validation (Phase 2C)
    └── Temporal attack chain correlation: Recon → C2 → Anomaly → Exfil

[5] Detection Provenance & Explainability (Phase 2C)
    └── Concrete audit trail: Detector ID + Observable Features + Baseline Deviation + Evidence

[6] Confidence & Risk Scoring Semantics Audit (Phase 2C)
    └── Formal mathematical distinction: Heuristic Score vs. ML Probability vs. Fused Risk

[7] Baseline vs. ML Comparative Benchmark (Phase 2D)
    └── Empirical comparison: Heuristic vs. LightGBM vs. Isolation Forest vs. Hybrid

[8] Comprehensive Metric Suite (Phase 2B & 2D)
    └── Precision, Recall, Macro F1, False Positive Rate (FPR), Latency (ms), Throughput (pps)

[9] Adversarial Robustness & Degradation Boundary Analysis (Phase 2E)
    ├── C2 Jitter Variation (5% → 20% → 50%)
    ├── Scanning Rate Variation (Fast → Medium → Slow)
    ├── Exfiltration Rate Variation (Bulk burst → Low-and-slow)
    └── Background Composition (Pure attack vs. Benign-mixed background)

[10] Dashboard Evidence Drill-Down (Phase 2C)
     └── Alert → Why? → Observable Metrics → Baseline Comparison → Timeline

[11] Evaluation Reproducibility Framework (Phase 2B)
     └── Automated experiment tracking: commit + config + dataset + metrics JSON export

[12] Final Constraint & Security Audit (Phase 2F)
     └── Verification checklist: zero return path, no active probes, zero payload decryption
```

---

## 3. Negative Constraint List (What Will NOT Be Modified)

To maintain architectural stability and avoid scope creep, the following are strictly prohibited:

- ❌ **NO Core Architecture Redesign:** The 3-tier pipeline (Ingestion $\rightarrow$ Detection $\rightarrow$ Entity/Fusion) is frozen.
- ❌ **NO New Message Brokers or Distributed Queues:** Keep the pipeline lightweight, deterministic, and self-contained.
- ❌ **NO Unnecessary AI / LLM Additions:** No chat-bots or un-evaluated models.
- ❌ **NO Blockchain Additions:** The focus is pure cybersecurity and network traffic intelligence.
- ❌ **NO Payload Decryption:** Strictly preserve TLS 1.3 / QUIC metadata-only analysis.
- ❌ **NO Active Probing or Return-Path Transmissions:** Zero packets transmitted back to monitored enclave.
- ❌ **NO Dashboard Bloat:** No unnecessary widgets; focus strictly on explainable evidence and incident timelines.
- ❌ **NO Fabricated Metrics:** Every metric must trace back to a registered PCAP and ground-truth interval.

---

## 4. Phase 2 Execution Sequence

```text
               STAGE 2: WORKING PROTOTYPE (COMPLETED)
                                 │
                                 ▼
             ┌───────────────────────────────────────┐
             │ [Phase 2A] Ground-Truth Infrastructure│ ✅ COMPLETED
             │  • Schema-enforced manifest           │
             │  • PCAP directory hierarchy           │
             │  • Traceability & leakage rules       │
             └───────────────────┬───────────────────┘
                                 ▼
             ┌───────────────────────────────────────┐
             │ [Phase 2B] Baseline Benchmarking      │ 🟡 IMMEDIATE NEXT
             │  • Replay registered PCAPs            │
             │  • Un-tuned Precision, Recall, F1, FPR│
             │  • Measured latency & throughput      │
             └───────────────────┬───────────────────┘
                                 ▼
             ┌───────────────────────────────────────┐
             │ [Phase 2C] Detection Provenance       │
             │  • Observable feature audit trail     │
             │  • Baseline $Z$-score verification    │
             │  • Scoring semantics audit            │
             └───────────────────┬───────────────────┘
                                 ▼
             ┌───────────────────────────────────────┐
             │ [Phase 2D] Ablation Studies           │
             │  • Heuristics vs. ML vs. Hybrid Fusion│
             └───────────────────┬───────────────────┘
                                 ▼
             ┌───────────────────────────────────────┐
             │ [Phase 2E] Adversarial Robustness     │
             │  • Jitter, rate, & background sweeps  │
             └───────────────────┬───────────────────┘
                                 ▼
               STAGE 4: COMPETITION-GRADE SUBMISSION
```
