# Project Context: Unidirectional Threat Intelligence

## 1. Problem Statement Overview
- **Problem ID:** 26145
- **Organization:** National Technical Research Organisation (NTRO)
- **Domain:** Cybersecurity in Unidirectional / Isolated Network Environments

## 2. Core Operational Constraints
1. **Unidirectional / Read-Only Monitoring:** Traffic is received across a hardware data diode or passive optical TAP / SPAN mirror.
2. **Strictly Isolated (No Return Path):** The analytics environment cannot transmit packets, inject TCP resets, send probes, or execute active queries back into the production/monitored network.
3. **No Payload Decryption:** Operating under modern TLS 1.3 / QUIC encryption without access to private keys or MITM capabilities. Threat detection must rely exclusively on packet metadata, timing, sizes, directions, and protocol handshakes (JA3/JA4, SNI, ALPN).
4. **Streaming & Bounded State:** The system must process traffic continuously in sliding time windows (e.g., 5s, 30s, 5m) with bounded memory structures (e.g., Count-Min Sketch, HyperLogLog, bounded circular ring buffers).
5. **Explainability & Ground Truth:** Every alert must contain concrete evidence and attribution, evaluated against reproducible lab-generated ground truth datasets.

## 3. Seven Required Threat Classes
1. **Volumetric / Protocol DDoS:** SYN floods, UDP reflection, spoofed floods, connection bursts.
2. **Botnet C2 Beaconing:** Low-frequency periodic/jittered outbound sessions to persistent endpoints.
3. **DGA Domains & DNS Tunnelling:** Non-standard record types, high character entropy, TXT record exfiltration, NXDOMAIN storms.
4. **Malware in Encrypted Sessions:** Malicious TLS/QUIC fingerprints, abnormal initial packet size sequences, suspicious ALPN/SNI.
5. **Reconnaissance / Port Scanning:** Horizontal network sweeps, vertical port scans, ephemeral connection attempts.
6. **Data Exfiltration:** High-volume outbound transfers, abnormal transfer durations, inverted byte ratios.
7. **Unknown / Novel Anomalies:** Unsupervised deviation from entity historical baselines.
