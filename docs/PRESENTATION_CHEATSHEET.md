# UniGuard AI: Presentation & Defense Technical Cheatsheet

**Problem Statement:** PS 26145 — *"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic"*

---

### 1. What is the core problem?
High-security critical infrastructure (power grids, defense networks, SCADA) uses unidirectional data diodes to isolate networks. Traditional IDSs fail because they expect bidirectional TCP handshake tracking, active probing, or TLS decryption.

### 2. Why unidirectional traffic?
Physical data diodes enforce single-direction packet transmission at the optical fiber layer. No return packets (ACKs, SYN-ACKs, RSTs, ICMPs) can flow back across the diode.

### 3. Why can't we use standard bidirectional inspection?
Standard tools (Zeek, Suricata, Snort) rely on bidirectional TCP state machines to reconstruct connections. In unidirectional traffic, return-path packets are physically absent, causing state machines to drop or misclassify flows.

### 4. How is the architecture strictly passive?
All ingestion occurs in read-only mode (`open(path, "rb")`) from network taps. No active sockets, packet injection, or network transmission interfaces exist in runtime detection code.

### 5. How do we detect encrypted traffic without decrypting it?
By extracting observable cleartext metadata from initial TLS ClientHello/ServerHello handshakes (JA3/JA4 fingerprints, SNI, ALPN, TLS version) and statistical packet dynamics (byte sizes, inter-arrival time distributions).

### 6. Why 5-tuple flows in unidirectional traffic?
Even with unidirectional observation, `(src_ip, dst_ip, src_port, dst_port, protocol)` uniquely partitions incoming packets into coherent communication channels, allowing statistical accounting of bytes, packets, and timing.

### 7. Why multi-timescale sliding windows?
Different cyber threats operate on vastly different timescales:
- **5s Window:** Captures micro-bursts and high-velocity volumetric DDoS ($> 10,000\text{ pps}$).
- **30s Window:** Computes statistical periodicity, inter-arrival time jitter, and DNS entropy.
- **300s Window:** Tracks host fanout cardinality, connection attempt rates, and asymmetric exfiltration trends.

### 8. Why combine deterministic heuristics, supervised ML, and unsupervised anomaly detection?
- **Deterministic Heuristics:** Provide fast, zero-delay, explainable baselines for high-velocity known threats (DDoS, port scans).
- **Supervised ML (LightGBM):** Classifies complex multi-feature tabular patterns across 52 dimensions in $< 0.2\text{ ms}$.
- **Unsupervised Anomaly Detection (Isolation Forest):** Identifies novel, out-of-distribution zero-day threats with a low $15.19\%$ false alarm rate on benign traffic.

### 9. Why an Entity Behaviour Graph?
Cyberattacks involve multiple steps across entities (e.g., Recon $\to$ C2 $\to$ Exfiltration). The directed bipartite graph connects hosts, external IPs, domain names, and detection signals to visualize the full threat topology.

### 10. Why Multi-Signal Fusion?
Single-signal detections produce noise. The `MultiSignalFusionEngine` correlates signals occurring within a 300-second window on the same entity, computing composite risk with diversity and agreement bonuses.

### 11. How is false-positive reduction handled?
Through host baseline memory (`EntityMemory`), which tracks rolling 1-hour Welford profiles per entity. Isolated signals with normal host Z-scores are suppressed as uncorroborated noise.

### 12. How is forensic provenance provided?
Every `DetectionSignal` and `Alert` attaches an immutable `SignalProvenance` record specifying detector ID, semantic version, exact decision reason tags, un-fabricated observable feature values, and timestamps.

### 13. What are the measured empirical results?
- **Mode A (Heuristics):** Macro F1 = 0.3777, DDoS F1 = 0.7143, p50 latency = 0.05 ms.
- **Mode C (Anomaly Only):** Isolation Forest achieves 15.19% Benign False Alarm Rate and 0.1496 Anomaly F1.
- **Mode D (Fused Hybrid):** Macro F1 = 0.3305, DDoS F1 = 0.6154, p50 latency = 3.47 ms, throughput = 1,090.9 pps.

### 14. What are the known weaknesses?
Un-tuned fusion weights in Mode D currently prioritize strict multi-signal corroboration over raw sensitivity, requiring operational tuning on specific customer deployment networks.

### 15. What happens under adversarial C2 jitter?
- Jitter $\le 20\%$: Maintained 100% detection.
- Jitter $\ge 50\%$: Periodicity degrades below the $0.70$ threshold, successfully evading isolated timing rules and requiring unsupervised anomaly detection.

### 16. What happens under low-and-slow port scanning?
- Scans $\ge 0.5\text{ pps}$: Detected across sliding windows.
- Ultra-slow sweeps ($0.1\text{ pps}$ / 1 packet every 10s): Evade short 5s windows, requiring long-term Entity Memory correlation.

### 17. What happens under reduced DDoS rates?
- Floods $\ge 3,000\text{ pps}$: Trigger critical velocity alerts immediately.
- Bursts $< 1,000\text{ pps}$: Stay below rate thresholds, transitioning toward application-layer Slowloris attack profiles.

### 18. How is the zero-return-path constraint guaranteed?
Audited and certified in `docs/FINAL_SECURITY_AUDIT.md`: Zero outbound sockets (`socket.SOCK_RAW`), zero packet injection calls (`scapy.send`), and zero return-traffic handlers exist in the production codebase.

### 19. How does UniGuard AI differ from Zeek and Suricata?
1. Does not assume bidirectional TCP state reassembly.
2. Integrates multi-scale streaming windows with host Z-score baseline memory.
3. Incorporates multi-signal cross-layer fusion and automated forensic provenance natively.

### 20. What is genuinely novel in this system?
The unified synthesis of **unidirectional streaming flow reassembly**, **52-feature multi-timescale metadata extraction**, **hybrid deterministic/ML/anomaly inference**, and **entity-centric behavioural graph fusion** with complete mathematical provenance.
