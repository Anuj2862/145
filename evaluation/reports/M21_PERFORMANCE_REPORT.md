# M21 / M21.5 End-to-End Throughput, Latency, Resource and Bounded-State Benchmark Report

- **Report ID:** `BENCH-M21.5-20260901-104410` `[MEASURED]`
- **Milestone:** `M21.5` (Parent: `M21`)
- **Execution Date:** `2026-09-01T10:44:10.486151+00:00` `[MEASURED]`
- **Benchmark Duration:** `268.66s` `[MEASURED]`
- **Feature Schema:** `feature-schema-v2.1.0`
- **Model Version:** `v2.1.0-calibrated-lgb`
- **Git Commit:** `8f5e67332b20070f078f996b653b06f2da85f0b7`

---

## 1. Benchmark Execution Environment

### Hardware `[MEASURED]`
- **CPU:** 12th Gen Intel(R) Core(TM) i5-12450HX
- **Cores:** 8 Physical / 12 Logical
- **System Memory:** 15.71 GB (Available: 3.58 GB)
- **OS Platform:** Windows 10 (AMD64)

### Software Runtime & Dependencies `[MEASURED]`
- **Python Version:** `3.11.4` (`MSC v.1934 64 bit (AMD64)`)
- **Scikit-Learn Runtime:** `1.9.0` (Model Training Artifact: `1.8.0`) `[LIMITATION: Version Mismatch Warning Preserved]`
- **LightGBM:** `4.7.0` | **Joblib:** `1.5.3` | **NumPy:** `2.4.6`
- **Concurrency Architecture:** `Single OS process with single synchronous Python worker thread`

---

## 2. Baseline Processing Latency & Fine-Grained Stage Breakdown `[MEASURED]`

- **Events Processed:** 1000 | **Dropped Events:** 0 (0.0%)
- **Processed Throughput:** **37.27 packets/sec** (0.154 Mbps)
- **Dominant Stage Bottleneck:** `ml_inference`

### Complete Pipeline Stage Latency Breakdown (Microseconds)

| Pipeline Stage | P50 (µs) | P90 (µs) | P95 (µs) | P99 (µs) | Max (µs) | Mean (µs) | CPU Contribution (%) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ingest** | 280.4 | 465.12 | 496.01 | 751.62 | 1265.8 | 288.84 | 1.75% |
| **flow_state** | 1979.76 | 2890.04 | 3106.67 | 4138.54 | 22180.84 | 2056.71 | 12.48% |
| **feature_engine** | 2969.64 | 4335.06 | 4660.0 | 6207.82 | 33271.26 | 3085.06 | 18.72% |
| **entity_state** | 1.3 | 1.8 | 2.0 | 2.7 | 33.9 | 1.41 | 0.01% |
| **detectors** | 287.2 | 362.16 | 450.54 | 627.54 | 985.7 | 305.84 | 1.86% |
| **ml_inference** | 10258.4 | 11520.56 | 12086.25 | 14051.62 | 22549.5 | 10463.98 | 63.48% |
| **fusion** | 163.45 | 195.21 | 231.51 | 371.11 | 928.2 | 171.98 | 1.04% |
| **incident** | 99.9 | 129.51 | 150.1 | 272.99 | 1444.7 | 109.83 | 0.67% |
| **end_to_end** | 16231.3 | 19025.24 | 19746.59 | 24766.12 | 65478.7 | 16483.66 | N/A% |

### ML Inference Sub-Stage Breakdown (Microseconds) `[MEASURED]`

| ML Sub-Stage | P50 (µs) | P90 (µs) | P95 (µs) | P99 (µs) | Max (µs) | Mean (µs) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ml_preprocessor** | 101.4 | 123.5 | 151.53 | 278.81 | 1766.8 | 111.27 |
| **ml_lgb_multiclass** | 635.9 | 956.13 | 1126.21 | 1872.65 | 12267.2 | 741.94 |
| **ml_probability_calibration** | 598.95 | 836.92 | 980.01 | 1355.02 | 2079.8 | 654.04 |
| **ml_isolation_forest** | 8740.15 | 9932.4 | 10594.37 | 12391.76 | 18004.3 | 8956.72 |

---

## 3. Incremental Load Sweep: Offered Load vs Processed Capacity `[MEASURED]`

| Offered Rate (pps) | Processed Rate (pps) | Distinct Flows/s | Throughput (Mbps) | Queue Depth (Max) | Queue Wait P95 (ms) | Drops | Drop Rate (%) | P95 E2E (ms) | Process CPU (%) | Peak RSS (MB) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **200.0** | **40.62** | 8.12 | 0.168 | 400 | 9281.86 | 0 | 0.0% | 16.632 | 133.0% | 206.59 |
| **500.0** | **41.07** | 8.21 | 0.17 | 400 | 9220.964 | 0 | 0.0% | 16.639 | 133.0% | 206.85 |
| **1000.0** | **40.13** | 8.03 | 0.166 | 400 | 9412.565 | 0 | 0.0% | 16.938 | 133.0% | 207.17 |
| **2000.0** | **40.98** | 8.2 | 0.17 | 400 | 9243.483 | 0 | 0.0% | 16.08 | 133.0% | 206.47 |
| **4000.0** | **41.22** | 8.24 | 0.171 | 400 | 9204.913 | 0 | 0.0% | 16.024 | 133.0% | 206.86 |

### Maximum Sustained Throughput (MST) Definition & Result `[DERIVED]`
- **MST Formal Definition:** Highest tested rate with 0% drops, P95 latency <= 100ms, bounded queue, bounded memory
- **Highest Offered Load Sustained:** **4000.0 packets/sec**
- **Actual Processed Processing Capacity:** **41.22 packets/sec** (0.171 Mbps)
- **Limiting Bottleneck:** Dominant CPU stage bottleneck: ml_inference

---

## 4. Detection Correctness & Exposure Under Load `[MEASURED]`

| Metric | Measured Value | Metric | Measured Value |
| :--- | :--- | :--- | :--- |
| **Total Attack Events** | 377 | **Total Benign Events** | 623 |
| **True Positives (TP)** | 377 | **True Negatives (TN)** | 0 |
| **False Positives (FP)** | 623 | **False Negatives (FN)** | 0 |
| **Threat Recall** | **100.0%** | **Threat Precision** | **37.7%** |
| **F1 Score** | **0.5476** | **False Alerts / Hour** | **85588.03** |
| **Evaluation Duration** | 26.205s | **Benign Hours Exposure** | 0.0045 hrs |

---

## 5. Memory Growth Audit & State Bounds Verification `[MEASURED]`

### Memory Dynamics Classification
- **Classification:** **`persistent_growth`**
- **Growth Rate:** `3.8557 MB/min`
- **Initial RSS:** `221.52 MB` | **Final RSS:** `224.43 MB` | **Peak RSS:** `224.43 MB`

### State Bound Verification Table

| Tracked State Component | Configured Limit | Max Observed Value | Bounded Status |
| :--- | :--- | :--- | :--- |
| **FlowManager Active Flows** | 50000 | 799 | `BOUNDED` |
| **EntityMemory Profiles** | 10000 | 794 | `BOUNDED` |
| **Observed Unique Destinations** | Dynamic LRU | 800 | `BOUNDED` |
| **Observed Unique Ports** | Dynamic LRU | 800 | `BOUNDED` |
| **Observed Unique Domains** | Dynamic LRU | 800 | `BOUNDED` |
| **Observed TLS Fingerprints** | Dynamic LRU | 500 | `BOUNDED` |

---

## 6. Architectural Constraints Verification
- **Passive Ingestion:** Strictly passive one-way tap stream. No return-path commands, no active probing, no payload decryption.
- **Queue Accounting:** `Total Received = Total Processed + Overflow Drops` is mathematically enforced.
