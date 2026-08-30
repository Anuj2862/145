# Project Map: Logical Pipeline & Conceptual Hierarchy

```text
OFFICIAL REQUIREMENT
        │
        ▼
PS 26145 (NTRO)
        │
        ▼
REAL-WORLD PROBLEM (Isolated Critical Infrastructure / Data Diode / One-Way Tap)
        │
        ▼
INDUSTRY LANDSCAPE (Zeek, Suricata, NetFlow, SIEM - Established passive tools)
        │
        ▼
RESEARCH MOTIVATION (Modern C2 & threats blending into legitimate encrypted traffic; weak individual signals)
        │
        ▼
OUR GAP (Passive, streaming, entity-centric multi-signal behavioural correlation & explainable incidents)
        │
        ▼
ARCHITECTURE (Ingest → Flow → Features → Detectors → Entity Memory → Behaviour Graph → Multi-Signal Fusion → Evidence & Incidents → Dashboard)
        │
        ▼
IMPLEMENTATION (Tiered phases: Baseline heuristic vertical slice → Streaming → Fast/Slow paths → ML comparison → Entity graph & fusion)
        │
        ▼
EVALUATION (Controlled benign/attack lab PCAPs with ground truth labels; metrics: precision, recall, F1, FPR, latency, throughput, ablation)
        │
        ▼
PROOF OF VALUE (Ablation study proving multi-signal entity correlation outperforms isolated alerts)
```
