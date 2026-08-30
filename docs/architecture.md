# System Architecture: Unidirectional Threat Intelligence Pipeline

## 1. High-Level Pipeline

```text
[ One-Way IP Traffic: PCAP / Stream / Tap / Diode ]
                        │ (Passive Ingestion)
                        ▼
            [ Packet & Header Parser ]
                        │
                        ▼
         [ 5-Tuple Flow Normalizer & State ]
          (src_ip, dst_ip, src_port, dst_port, proto)
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
   [ Fast Path ]                 [ Slow Path ]
 (High-velocity, streaming      (Stateful, multi-protocol
  counters, CMS, HLL, 5s)        timing, DNS/TLS, 30s-5m)
         │                             │
         └──────────────┬──────────────┘
                        ▼
             [ Feature Extractors ]
        (Flow, DNS, TLS, Temporal, Entity)
                        │
                        ▼
            [ Dual Detection Layer ]
     ┌──────────────────┴──────────────────┐
     ▼                                     ▼
 [ Deterministic Baselines ]        [ Lightweight ML / Anomaly ]
 (Rule/threshold-based detectors)   (LightGBM / Isolation Forest)
     │                                     │
     └──────────────────┬──────────────────┘
                        ▼
            [ Raw Detection Signals ]
                        │
                        ▼
          [ Entity Memory & Graph Engine ]
     (Host baselines, historical profiles,
      multi-entity relationship graph)
                        │
                        ▼
            [ Multi-Signal Fusion ]
     (Evidence correlation, risk aggregation,
      multi-stage attack grouping)
                        │
                        ▼
     [ Evidence Engine & Incident Builder ]
     (Produces structured, explainable Incidents)
                        │
                        ▼
             [ Standardized Alert ]
                        │
                        ▼
      [ FastAPI Backend & Live Dashboard ]
```

## 2. Fast Path vs. Slow Path Architecture

### Fast Path (High-Velocity / Low-Latency)
- **Target Threats:** Volumetric DDoS (SYN floods, UDP storms), rapid port scans, source spoofing.
- **Window:** 5-second sliding windows.
- **Data Structures:** Fixed-memory streaming algorithms (Count-Min Sketch for frequency estimation, HyperLogLog for cardinality/fan-out estimation, circular sliding buffers).
- **Latency Target:** Sub-second (near immediate signal output).

### Slow Path (Deep Contextual & Stateful Analysis)
- **Target Threats:** Botnet C2 beaconing, DGA / DNS tunnelling, Encrypted session malware, slow data exfiltration.
- **Window:** 30 seconds (session level) and 5 minutes (baseline context).
- **Processing:** Bounded flow buffer (retaining first $K$ packets for sequence and inter-arrival timing calculations), DNS payload metadata parsing, TLS ClientHello/ServerHello fingerprinting (JA3/JA4/SNI/ALPN).

## 3. Entity Intelligence & Fusion Layer
- **Entity Memory:** Maintains rolling statistical baselines per active IP/Host (e.g., normal packet/sec distribution, habitual destination ports, known TLS fingerprints, typical DNS query volume).
- **Entity Behaviour Graph:** Directed temporal graph linking Hosts $\rightarrow$ IP/Domains $\rightarrow$ Protocol Events $\rightarrow$ Detection Signals.
- **Fusion Engine:** Evaluates multi-signal co-occurrence. Computes consolidated incident risk and outputs structured, explainable incidents with human-readable evidence chains.
