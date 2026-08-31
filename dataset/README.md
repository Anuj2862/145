# Dataset & Ground-Truth Infrastructure (PS 26145)

This directory houses the dataset artifacts, raw PCAP capture hierarchy, ground-truth manifests, and validation schemas for **UniGuard AI** under Problem Statement 26145 (*AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*).

---

## 📁 Directory Layout

```text
dataset/
├── README.md                       # This comprehensive dataset guide & protocols
├── manifest_schema.py              # Pydantic v2 data models for ground-truth manifests
├── manifest_manager.py             # Manifest query, loading, and integrity validation engine
│
├── manifests/                      # Labeled ground-truth manifests
│   └── ground_truth.json           # Schema-enforced master evaluation manifest
│
├── pcaps/                          # Raw packet capture storage (by traffic category)
│   ├── benign/                     # Controlled benign baseline enterprise captures
│   ├── ddos/                       # Volumetric DDoS & flood captures
│   ├── c2/                         # Botnet C2 periodic beaconing & heartbeat traces
│   ├── dns/                        # DGA queries and DNS tunneling captures
│   ├── encrypted/                  # Encrypted malware, TLS metadata & JA3/JA4 traces
│   ├── recon/                      # Horizontal/vertical port scanning sweeps
│   └── exfiltration/               # Outbound data transfer & exfiltration bursts
│
└── processed/                      # Preprocessed feature splits for ML evaluation
    ├── train.csv                   # 83,918 rows (Training partition)
    ├── val.csv                     # 18,018 rows (Validation partition)
    ├── test.csv                    # 18,064 rows (Test partition)
    └── dataset_manifest.json       # Feature column specifications and label encodings
```

---

## 🏷️ Ground-Truth Label Taxonomy

Every capture and internal event is categorized into the standardized taxonomy aligned with PS 26145:

| Evaluation Class | Category | Ground-Truth Definition & Ingress Characteristics |
| :--- | :---: | :--- |
| **`BENIGN`** | Baseline | Normal corporate/enclave traffic (HTTP/2, HTTPS, DNS lookups, NTP, TLS 1.3 handshakes) adhering to normal packet rates and low baseline $Z$-scores. |
| **`VOLUMETRIC_DDOS`** | Attack | High packet-rate flooding (e.g., TCP SYN floods, UDP reflection) with extreme packet velocities ($\text{pps} \gg 10{,}000$), skewed flag ratios ($\text{SYN ratio} > 0.95$), or extreme burst deviation ($+3\sigma \dots +10\sigma$). |
| **`BOTNET_C2_BEACONING`** | Attack | Periodic outbound heartbeat connections to external endpoints with low timing variance ($\text{periodicity score} > 0.85$, $\text{jitter} < 20\%$) and high destination IP/domain concentration. |
| **`DGA_DNS_TUNNELLING`** | Attack | High Shannon entropy domain queries ($H > 3.8$), anomalous subdomain lengths ($> 25$ chars), or excessive `NXDOMAIN` query rates. |
| **`ENCRYPTED_MALWARE`** | Attack | Suspicious TLS handshake metadata (known malicious JA3/JA4 client fingerprints, anomalous cipher suite combinations, un-negotiated SNI) without decrypting payloads. |
| **`RECON_PORT_SCAN`** | Attack | Systematic probing of multiple destination ports on a single host (vertical) or across an entire subnet (horizontal) with high destination port cardinality within short temporal windows. |
| **`DATA_EXFILTRATION`** | Attack | Unusually large volume of outbound payload transfers over standard ports (e.g., 443, 80, 53) characterized by high upload-to-download byte ratios ($> 10.0$) and sudden baseline byte velocity shifts. |
| **`UNKNOWN_ANOMALY`** | Anomaly | Statistical outliers detected in feature space (by Isolation Forest or distribution baselines) that do not match existing known heuristics. |

---

## ⏱️ Capture & Event Time Boundaries

In real-world network monitoring, an entire capture file is **rarely 100% malicious**. An attack is typically an interval embedded within benign background traffic.

The manifest framework explicitly distinguishes between:
1. **Capture Boundaries (`capture_start_iso` $\rightarrow$ `capture_end_iso`):** The global timestamp duration of the raw PCAP file.
2. **Event Boundaries (`time_window.start_time_iso` $\rightarrow$ `time_window.end_time_iso`):** The exact active window of the threat event.

```text
[CAPTURE START] ─────────────────────────────────────────────────────────────────────────── [CAPTURE END]
       │                                                                                        │
       ├────────────── Benign Preamble ──────────────┤                                          │
       │                                                                                        │
       │                         [EVENT START] ──── Attack Active ──── [EVENT END]              │
       │                                                                                        │
       └───────────────────────────────────────────────────────────── Benign Recovery ──────────┘
```

This guarantees that evaluation metrics evaluate the detector's **temporal precision** — flagging threats only when they are actually active, rather than scoring the entire file blindly.

---

## 🔒 Data Leakage Prevention Protocols

To ensure completely unbiased model training and empirical evaluation, the following rules are strictly enforced:

1. **Partition Segregation:**
   - **`TRAIN`**: Used exclusively for fitting ML models (LightGBM, Random Forest, Isolation Forest).
   - **`VAL`**: Used for hyperparameter tuning and threshold calibration.
   - **`TEST`**: Used for post-training benchmark evaluations.
   - **`EVALUATION_HOLD_OUT`**: Distinct PCAP captures reserved exclusively for end-to-end replay pipeline verification.
2. **Entity & Scenario Disjointness:** Traffic generated from the same physical scenario or sharing identical IP entity identifiers must **never** be split across both `TRAIN` and `TEST`.
3. **Downstream Target Feature Exclusion:** Features representing target variables or downstream risk scores (such as `recent_risk` or `baseline_deviation`) are explicitly excluded from model input matrices (as documented in `dataset_manifest.json`).

---

## 🔬 Synthetic Lab Traffic Generation Protocols

All synthetic attack traces for evaluation must be generated in an **isolated, authorized local testbed**.

### Safety Rules:
- ⛔ **NO external transmission:** Traffic generation tools must NEVER target internet-routable external infrastructure.
- 🛡️ **Air-Gapped Loopback / VETH Pairs:** Lab traffic is replayed or generated across local virtual Ethernet interfaces or simulated software queues.

### Lab Scenario Templates:

#### 1. Volumetric DDoS SYN Flood
```bash
# Synthetic generation template targeting local test port
# Target: 10.0.0.1:80 | Rate: 10,000 pps | Duration: 60s
# Parameters: TCP SYN flag set, random ephemeral source ports (49152-65535)
```

#### 2. C2 Beaconing Emulation
```text
# Low-jitter HTTPS heartbeat callback
# Source: 10.0.4.88 -> Target: 198.51.100.42:443
# Interval: 60.0s | Jitter: +/- 5% (57s - 63s) | Duration: 30 minutes
```

#### 3. DGA / DNS Tunnelling Emulation
```text
# Base32/Hex encoded pseudo-random queries targeting authoritative nameserver
# Entropy: > 4.2 | Subdomain length: 32 chars | Rate: 50 qps
```

#### 4. Outbound Data Exfiltration
```text
# Asymmetric byte transfer over TLS 1.3
# Source: 10.0.12.3 -> Target: 198.51.100.99:443
# Volume: 50 MB burst | Out/In Byte Ratio: 95.0
```

---

## 🔗 Traceability Chain

Every empirical metric generated in Phase 2 must adhere to the unbroken traceability chain:

$$\text{Evaluation Metric} \longrightarrow \text{Ground Truth Manifest Record} \longrightarrow \text{PCAP File Hash} \longrightarrow \text{Time Window} \longrightarrow \text{Detection Signal}$$

This ensures that every accuracy figure, false-positive count, and latency measurement presented to an evaluation panel is **verifiable, reproducible, and mathematically grounded**.
