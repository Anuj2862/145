# Project Context: Unidirectional Threat Intelligence

## 1. Problem Statement Overview
- **Problem ID:** 26145
- **Organization:** National Technical Research Organisation (NTRO)
- **Domain:** Cybersecurity in Unidirectional / Isolated Network Environments

## 2. Core Operational Constraints
1. **Unidirectional / Read-Only Monitoring:** Traffic is observed passively across a hardware data diode or optical TAP / SPAN mirror.
2. **Strictly Isolated (No Return Path):** The analytics environment cannot transmit packets, inject TCP resets, send probes, or execute active queries back into the production/monitored network.
3. **No Payload Decryption:** The system analyzes TLS 1.3 / QUIC traffic using **whatever metadata is observable from passive traffic, without decrypting payloads** (e.g. handshake fingerprints such as JA3/JA4, SNI, ALPN where present, packet size sequences, directions, and timings).
4. **Streaming & Bounded State:** The system processes traffic continuously in sliding time windows (e.g. 5s Fast Path, 30s session Slow Path, 5m baseline) with bounded memory structures (e.g. Count-Min Sketch, HyperLogLog, circular buffers).
5. **Explainability & Ground Truth:** Every alert contains concrete evidence and attribution, evaluated against reproducible lab-generated ground truth datasets.

## 3. Seven Required Threat Classes
1. **Volumetric / Protocol DDoS:** SYN floods, UDP reflection, spoofed floods, connection bursts.
2. **Botnet C2 Beaconing:** Low-frequency periodic/jittered outbound sessions to persistent endpoints.
3. **DGA Domains & DNS Tunnelling:** Non-standard record types, high character entropy, TXT record exfiltration, NXDOMAIN storms.
4. **Malware in Encrypted Sessions:** Malicious TLS/QUIC fingerprints, abnormal early packet size sequence profiles.
5. **Reconnaissance / Port Scanning:** Horizontal network sweeps, vertical port scans, ephemeral connection attempts.
6. **Data Exfiltration:** High-volume outbound transfers, abnormal transfer durations, inverted byte ratios.
7. **Unknown / Novel Anomalies:** Unsupervised deviation from entity historical baselines.
