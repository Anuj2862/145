# Problem Statement 26145: Complete Requirements

## Metadata
- **Problem Statement ID:** 26145
- **Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- **Organization:** National Technical Research Organisation (NTRO)
- **Department:** National Technical Research Organisation
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity

---

## Official Context & Environment
In critical infrastructure installations (defense networks, nuclear facilities, national intelligence enclaves), network boundaries are isolated by physical or optical hardware data diodes and unidirectional SPAN/TAP mirrors. Network traffic crossing this boundary flows in **one direction only**. 

The analytics system operates in an isolated environment with **no physical or logical return path** to the monitored network.

---

## Core Operational Constraints
1. **Strictly Passive / Read-Only Ingest:** The analytics system must not send packets, query monitored infrastructure, initiate connections, or attempt TCP handshakes.
2. **No Inline Mitigation:** The system is a passive detection and intelligence engine, not an active inline blocking firewall.
3. **No Payload Decryption:** TLS 1.3 / QUIC encrypted payloads cannot be decrypted. Threat detection must rely exclusively on packet metadata, handshake characteristics (JA3/JA4, SNI, ALPN), packet timing, packet sizes, and flow metrics.
4. **Streaming & Bounded Latency:** Real-time stream processing with sliding windows and bounded resource utilization.
5. **Standardized & Explainable Alerts:** Structured output containing timestamps, entity identifiers, threat classes, confidence scores, severity ratings, and supporting evidence.
6. **Empirical Evaluation:** Measured benchmarks on controlled lab datasets with ground-truth manifests.

---

## Required Threat Classes
1. **Volumetric / Protocol DDoS:** SYN floods, UDP amplification, spoofed-source floods.
2. **Botnet C2 Beaconing:** Periodic/jittered communication toward persistent endpoints.
3. **DGA Domains & DNS Tunnelling:** Non-standard record types, character entropy anomalies, NXDOMAIN bursts, length distribution anomalies.
4. **Malware in Encrypted Sessions:** Malicious TLS/QUIC fingerprints, abnormal initial packet sequence profiles.
5. **Reconnaissance / Port Scanning:** Horizontal network sweeps, vertical port scans, ephemeral connection bursts.
6. **Data Exfiltration:** High outbound transfer volumes, abnormal byte ratios, prolonged anomalous sessions.
7. **Unknown / Novel Anomalies:** Unsupervised deviation from entity historical baselines.
