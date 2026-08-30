# Architectural & Design Decisions

## 1. Unidirectional Traffic Model
- **Decision:** All flows are strictly identified by unidirectional 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`).
- **Rationale:** Because traffic crosses a hardware diode or one-way TAP, return packets (SYN-ACK, ACK from destination) may not be observable on the same physical link. Flow tracking cannot depend on pairing forward and reverse flows into a single bidirectional session.

## 2. Fast Path vs. Slow Path Split
- **Decision:** Ingestion traffic is dispatched into a high-speed fast path (5s windows, bounded probabilistic counters) and a context-rich slow path (30s/5m windows, metadata extraction, sequence analysis).
- **Rationale:** Volumetric bursts (DDoS, sweeps) must be detected with minimal latency and constant memory bounds, while deep behavioral analysis (C2 beaconing, DGA, encrypted malware) requires multi-packet state and temporal distributions.

## 3. Deterministic Baselines Before ML
- **Decision:** Every threat class must first have an interpretable, rule/threshold-based deterministic detector before implementing machine learning models.
- **Rationale:** To establish an empirical baseline. We must rigorously test and verify whether ML models provide measurable improvements in F1/FPR over transparent heuristics under one-way monitoring constraints.

## 4. No Payload Decryption
- **Decision:** System operates exclusively on cleartext headers, protocol metadata (DNS queries/responses), and cryptographic handshake metadata (TLS SNI, ALPN, JA3/JA4, packet length sequences).
- **Rationale:** Passive one-way taps in isolated enclaves cannot perform active TLS interception or MITM, and must preserve compliance with security boundaries.

## 5. Explainable Evidence & Incident Reconstruction
- **Decision:** Alerts are not isolated score outputs. They are grouped into Incidents via an Entity Behaviour Graph, supported by human-readable evidence items.
- **Rationale:** Security analysts require context (what happened across time, which hosts were involved, why the system flagged it) rather than an uninterpretable probability float.
