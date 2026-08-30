# Industry Research & SANS Motivation Context

> [!NOTE]
> This document captures research and industry context. It is **NOT** an official PS requirement, nor did SANS propose our architecture. It serves as industry motivation, validation of our research direction, and guidance for evaluation philosophy.

---

## 1. The Operational Reality of Modern Network Defense
Traditional perimeter defenses and signature-based Network Intrusion Detection Systems (NIDS) were designed around assumptions that are increasingly challenged:
- Cleartext inspection of payloads
- Bidirectional TCP/IP handshakes to verify host liveness
- Distinct, noisy malicious signatures easily separated from benign user traffic

In modern threat landscapes, Command and Control (C2) frameworks (e.g., Cobalt Strike, Mythic, Sliver, Havoc) and advanced threat actors actively evade signature detection by:
- Operating over legitimate TLS 1.3 / QUIC encrypted channels
- Blending into standard HTTP/2 and cloud provider traffic (domain fronting, CDN endpoints)
- Introducing configurable jitter, sleep intervals, and payload padding to mimic benign user browsing
- Using weak, subtle signals that avoid triggering isolated threshold-based alerts

## 2. Role of Established Industry Tools (Zeek & Suricata)
- **Zeek (Bro):** Exceptional network security monitoring engine that translates raw packets into structured, protocol-specific semantic event streams (`conn.log`, `dns.log`, `ssl.log`, `http.log`).
- **Suricata:** High-performance multi-threaded signature and behavioral IDS/IPS engine with protocol parsing and EVE JSON logging.

### Key Takeaway
We do **NOT** claim Zeek and Suricata are obsolete or that we are replacing them. Instead:
- Existing tools are highly proficient at raw protocol parsing, connection summarization, and signature matching.
- However, isolated events (e.g., an individual DNS query to a slightly unusual domain, or a single TLS session with an unclassified JA3 hash) produce either high false-alarm rates or go unnoticed because each individual event is a **weak signal**.

## 3. The Research Gap: Multi-Signal Entity Correlation
SANS and modern network security research emphasize that detection efficacy increases dramatically when an analytics layer performs:
1. **Temporal Sequence Analysis:** Correlating inter-arrival time distributions and jitter across session boundaries.
2. **Multi-Protocol Metadata Synthesis:** Combining DNS anomalies + TLS client fingerprints + Flow timing + Byte ratios for a single host.
3. **Entity Baseline Tracking:** Comparing observed behavior against historical norms for that specific host/IP rather than generic global thresholds.
4. **Explainable Graph-Based Incident Construction:** Grouping individual weak signals into a coherent multi-stage attack lifecycle (Recon → DNS Anomaly → C2 Beaconing → Encrypted Transfer → Exfiltration).
