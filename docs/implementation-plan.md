# Implementation Plan & Milestone Roadmap

## Development Philosophy
1. **Vertical Slice First:** Establish an end-to-end working pipeline (PCAP $\rightarrow$ Flow $\rightarrow$ Window $\rightarrow$ Heuristic Detector $\rightarrow$ Standardized Alert) before adding breadth.
2. **Deterministic Baseline Before ML:** Always implement and measure an interpretable heuristic baseline before training machine learning models.
3. **Strict Interface Contracts:** Modules communicate exclusively through validated schemas (`schemas/`).

---

## Phase Progression

### Milestone 0: Foundation & Contracts (CURRENT PHASE)
- Establish repository documentation and shared architectural contracts.
- Define core schemas: `FlowEvent`, `FeatureVector`, `DetectionSignal`, `EntityEvent`, `Incident`, `Alert`.
- Setup Git workflow rules, team responsibility breakdown, and test frameworks.

### Milestone 1: Minimal Working Vertical Slice
- Ingest offline PCAP file via lightweight packet parser.
- Group packets into 5-tuple unidirectional flow state (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`).
- Compute 5-second sliding window metrics (packet rate, SYN flag ratio, byte velocity).
- Implement deterministic Volumetric DDoS heuristic detector.
- Output standardized JSON alert to file/stdout.
- Verify end-to-end pipeline with test PCAP.

### Milestone 2: Streaming Ingestion & Replay Engine
- Implement streaming replay controller with configurable speed multiplier ($1\times, 5\times, 10\times$).
- Connect packet parser to in-memory streaming queue / message bus.
- Measure baseline packet throughput and latency.

### Milestone 3: Fast-Path Detectors
- Add HyperLogLog and Count-Min Sketch structures.
- Implement Reconnaissance / Port Scan detector (horizontal and vertical scan detection via cardinality tracking).
- Refine Volumetric DDoS detection (SYN flood, UDP reflection).

### Milestone 4: Slow-Path Feature Extractors & Threat Engines
- Extract DNS metadata features (entropy, query length, NXDOMAIN counts).
- Extract TLS metadata features (JA3/JA4 hash extraction, SNI, ALPN, packet size sequences).
- Extract Temporal features (inter-arrival time distribution, jitter, periodicity).
- Implement DGA & DNS Tunnelling detector, C2 Beaconing detector, Encrypted Malware detector, Data Exfiltration detector.

### Milestone 5: Machine Learning Baseline Comparison
- Train lightweight models (LightGBM, Random Forest, Isolation Forest) on extracted feature sets.
- Execute comparative benchmark: Deterministic Baseline vs. ML Classifier.
- Evaluate Precision, Recall, F1, and inference latency.

### Milestone 6: Entity Memory & Baseline Profiler
- Implement stateful rolling entity memory for active hosts/IPs.
- Calculate entity baseline deviation scores ($Z$-score / quantile comparison against historical distributions).

### Milestone 7: Entity Behaviour Graph & Incident Construction
- Build temporal graph connecting Entities, Events, and Detection Signals.
- Implement graph traversal to correlate multi-stage attacks across time.

### Milestone 8: Multi-Signal Fusion & Evidence Engine
- Fuse individual detection signals with entity deviation into consolidated incident risk scores.
- Generate explainable evidence records (e.g., bulleted signal contributions, metric deltas).

### Milestone 9: REST API & Interactive Dashboard
- Build FastAPI endpoints for live/replayed alerts, incident timelines, entity profiles, and graph visualization.
- Build React/TypeScript dashboard with modern visualization of flows, incidents, and threat breakdown.

### Milestone 10: Rigorous Evaluation & Ablation Study
- Run full evaluation suite on benchmark datasets (Benign + Controlled Attacks).
- Measure throughput (packets/sec, flows/sec, Mbps), detection latency, memory usage, and resource footprint.
- Conduct feature ablation experiments (Flow vs. Flow+DNS vs. Flow+DNS+TLS vs. Fusion).
