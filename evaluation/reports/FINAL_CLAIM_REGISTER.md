# FINAL CLAIM REGISTER & EVIDENCE VERIFICATION

**Audit Milestone:** `M23.5`
**Purpose:** Presentation and Demonstration Claim Assurance
**Standard:** Strict Empirical Evidence Verification (Zero Inflated Claims)

---

## 1. Executive Instructions for Presentations
Every numerical result and technical claim made in documentation, presentations, and technical demonstrations must be grounded strictly in measured code and report artifacts. The table below provides the **exact measured value**, **provenance source**, **scientific classification**, **safe wording**, and **mandatory caveats** for all claims.

---

## 2. Master Claim Register

| Metric / Claim Area | Measured Value | Provenance Artifact | Classification | Recommended Safe Presentation Wording | Mandatory Operational Caveat |
| :--- | :---: | :--- | :---: | :--- | :--- |
| **Supervised Macro F1** | `0.9693` (E1) / `0.9696` (E2) / `0.9620` (E4) | `evaluation/reports/EVAL_M19_REPORT.json` | **MEASURED** | *"LightGBM multi-class threat classifier achieves >0.96 Macro F1 across entity (E2) and temporal (E4) holdout splits."* | Evaluated on standard 18,000-sample balanced benchmark split. Real-world class imbalance will vary operational precision. |
| **Supervised Accuracy** | `97.18%` (E1, E2) / `96.63%` (E4) | `evaluation/reports/EVAL_M19_REPORT.json` | **MEASURED** | *"Classifier demonstrates ~97% overall classification accuracy across evaluated benchmark traffic."* | Multi-class accuracy across 7 threat classes on curated benchmark corpus. |
| **Volumetric DDoS Detection** | `P=0.9994`, `R=1.0000`, `F1=0.9997` | `evaluation/reports/EVAL_M19_REPORT.json` | **MEASURED** | *"Volumetric and SYN flood attacks are detected with near-perfect separation (>0.99 F1)."* | Verified on high-rate burst traffic (>1,000 pps); low-rate stealth DDoS (<50 pps) requires aggregate window correlation. |
| **C2 Beaconing Detection** | `P=0.9655`, `R=0.9974`, `F1=0.9812` | `evaluation/reports/EVAL_M19_REPORT.json` | **MEASURED** | *"Periodic and beaconing C2 activity is detected with >0.98 F1 on entity holdouts."* | Evaluated on periodic intervals with 5% to 50% timing jitter. Non-periodic event-driven C2 requires graph anomaly fusion. |
| **C2 Jitter Resilience** | Jitter resilience verified across 5% & 50% jitter | `evaluation/reports/EVAL_M19_REPORT.json`, `evaluation/reports/M20_ROBUSTNESS_REPORT.json` | **MEASURED** | *"Periodicity detection engine discriminates periodic beaconing from benign traffic under up to 50% timing jitter."* | Jitter exceeding 75% degrades standalone FFT/autocorrelation periodicity metrics. |
| **DGA & DNS Tunnelling** | `P=0.9986`, `R=1.0000`, `F1=0.9993` | `evaluation/reports/EVAL_M19_REPORT.json` | **MEASURED** | *"Algorithmic DGA domains and DNS tunnelling queries detected with >0.99 F1 using character entropy and n-gram scoring."* | Requires DNS packet metadata capture; dictionary-based concatenated DGAs exhibit lower entropy. |
| **Data Exfiltration** | `P=0.9978`, `R=0.9868`, `F1=0.9923` | `evaluation/reports/EVAL_M19_REPORT.json` | **MEASURED** | *"Bulk outbound exfiltration detected with >0.99 F1 via upload/download asymmetry and burst accounting."* | Slow covert exfiltration (<10 KB/hour) requires multi-day baseline windows. |
| **Encrypted Malware (Metadata Only)** | `P=0.8085`, `R=0.8221`, `F1=0.8152` | `evaluation/reports/EVAL_M19_REPORT.json` | **MEASURED** | *"Encrypted malware sessions identified at ~81.5% F1 using strictly unencrypted handshake metadata and flow timing without decryption."* | Operates 100% without TLS decryption; malware using benign standard browser JA3 fingerprints exhibits lower separation. |
| **Pipeline Throughput** | `75.89 pps` sustained (`0.314 Mbps`) | `evaluation/reports/M21_PERFORMANCE_REPORT.json` | **MEASURED** | *"The pure Python end-to-end multimodal pipeline sustains a maximum verified throughput of 75.89 packets/sec (0.314 Mbps)."* | **CRITICAL:** 75.89 pps is the measured sustained processing capacity of the pure Python pipeline, NOT a 10 Gbps hardware TAP claim. |
| **Processing Latency** | `P50 = 1.12 ms`, `P95 = 2.85 ms` | `evaluation/reports/M21_PERFORMANCE_REPORT.json` | **MEASURED** | *"Real-time streaming pipeline operates with a P50 latency of 1.12 ms and a P95 latency of 2.85 ms per packet event."* | Measured under sustained load sweep; transient GC pauses can produce occasional P99.9 spikes up to 12 ms. |
| **CPU Utilization** | `4.2%` (single-worker baseline) | `evaluation/reports/M21_PERFORMANCE_REPORT.json` | **MEASURED** | *"Low computational footprint consuming ~4.2% CPU during sustained ingestion."* | Measured on standard development test bench (Intel/AMD x86_64 single core). |
| **Memory Consumption (RAM)** | `186.4 MB RSS` (Bounded Plateau) | `evaluation/reports/M21_PERFORMANCE_REPORT.json` | **MEASURED** | *"Memory consumption stabilizes in a bounded plateau at ~186.4 MB with zero persistent leak over extended operation."* | Memory is bounded by strict LRU cache (max 10,000 entities) and fixed-capacity sliding window ring buffers. |
| **Packet Loss Robustness** | F1 remains `>0.95` up to 10% packet loss | `evaluation/reports/M20_ROBUSTNESS_REPORT.json` | **MEASURED** | *"Detection performance remains robust (>0.95 F1) under up to 10% simulated packet loss and reordering."* | Packet loss exceeding 30% significantly distorts TCP flag ratio statistics. |
| **Probability Calibration** | Brier Score = `0.0198`, ECE = `0.0004` | `evaluation/reports/M20_ROBUSTNESS_REPORT.json` | **MEASURED** | *"Model outputs well-calibrated threat probabilities with an Expected Calibration Error of 0.0004 using Sigmoid scaling."* | Calibration parameters fitted on validation split; requires monitoring under severe operational distribution shifts. |
| **Concept Drift Monitoring** | PSI & Wasserstein tracking operational | `evaluation/reports/M20_ROBUSTNESS_REPORT.json` | **MEASURED** | *"Automated distribution drift monitoring tracks Population Stability Index (PSI) to detect statistical feature shifts."* | Generates diagnostic warnings in telemetry; does NOT perform automated online retraining (by design). |
| **Security Boundary Status** | `PASS` (13/13 security assertions) | `evaluation/reports/M22_SECURITY_BOUNDARY_REPORT.json` | **MEASURED** | *"Complies with NTRO PS 26145 out-of-band enclave boundaries: 0 network writes, disabled active response, zero payload decryption."* | Verified by AST inspection and runtime test client probing. |
| **Network Actuation Endpoints** | `0` (Zero actuation endpoints) | `evaluation/reports/M22_SECURITY_BOUNDARY_REPORT.json`, `api/app.py` | **MEASURED** | *"Zero network actuation, packet transmission, or firewall modification endpoints exist in the API plane."* | All mitigation routes (/mitigate, /block, /drop) return 404 Not Found. |
| **Canonical Feature Count** | `56 features` | `features/model_features_v2.py`, `schemas/provenance.py` | **MEASURED** | *"Canonical Phase 2 feature schema (`feature-schema-v2.1.0`) extracts 56 multimodal features across flow, timing, DNS, and TLS."* | 56 features are aligned across all v2 ML models, preprocessors, schemas, and reports. |
| **Scenario Generalization (E3)** | `NOT_AVAILABLE` | `evaluation/reports/EVAL_M19_REPORT.json` | **LIMITATION** | *"Scenario holdout generalization is explicitly documented as NOT_AVAILABLE due to single-scenario benchmark dataset scope."* | Do NOT claim multi-scenario generalization without a multi-environment dataset corpus. |
| **Real PCAP Target Validation** | Validated on DDoS & C2; single-flow captures for others map to C2 | `evaluation/reports/EVAL_M19_REPORT.json` | **LIMITATION** | *"Real PCAP replay validates end-to-end detection; short snippet captures without temporal warm-up exhibit feature overlap."* | Do NOT claim universal 100% precision on un-warmed short PCAP snippets. |

---

## 3. Mandatory Defense Guidelines for Demonstrations
1. **Never claim 10 Gbps line-rate throughput:** Always state the measured single-core software throughput of **75.89 pps (0.314 Mbps)** for the Python prototype and explain that production scale-out relies on C/Rust DPDK/eBPF acceleration.
2. **Never claim active mitigation:** Always emphasize that UniGuard is strictly an **out-of-band passive intelligence enclave** (PS 26145 compliant) with **zero network writes**.
3. **Never claim payload decryption:** Always highlight that all encrypted threat detection operates strictly on **unencrypted metadata (JA3/JA4/SNI/ALPN) and packet timing statistics**.
4. **Never claim E3 scenario generalization:** Clearly document that cross-scenario holdout is an identified research gap due to benchmark corpus scope.
