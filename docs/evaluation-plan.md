# Evaluation Methodology & Benchmark Plan

> [!NOTE]
> All performance metrics and latency numbers in this document are **engineering targets to be measured and verified through empirical experimentation**, rather than predetermined fixed achievements.

---

## 1. Core Evaluation Metrics

| Category | Metric | Definition / Calculation | Engineering Target to Measure |
| :--- | :--- | :--- | :--- |
| **Accuracy** | Precision | $TP / (TP + FP)$ | Minimize false alarms on production-like traffic |
| | Recall / Detection Rate | $TP / (TP + FN)$ | Maximize capture rate across all 6 threat classes |
| | F1-Score | $2 \cdot (P \cdot R) / (P + R)$ | Quantify harmonic balance |
| | False Positive Rate (FPR) | $FP / (FP + TN)$ | Target $< 1\%$ on baseline benign traffic |
| **Latency** | Detection Latency | $T_{\text{alert}} - T_{\text{first\_threat\_packet}}$ | Fast Path: Target $< 1.0\text{s}$; Slow Path: Target $< 30\text{s}$ |
| **System** | Ingestion Throughput | Measured packets/sec, flows/sec, Mbps | High continuous stream rate without packet drops |
| | Memory Footprint | Max RSS memory in MB | Bounded state ($\le \text{configured ceiling}$) |
| | CPU Utilization | Average % core utilization | Efficient multi-threading / async execution |

---

## 2. Comparative Evaluation: Heuristic Baseline vs. ML
For each threat class, identical test datasets will be evaluated against:
1. **Deterministic Baseline Detector** (rule / statistical threshold)
2. **Lightweight ML Detector** (e.g., LightGBM / Random Forest)
3. **Unsupervised Anomaly Detector** (e.g., Isolation Forest / One-Class SVM)

We will measure and document whether ML provides a statistically significant improvement in precision, recall, and false-positive reduction relative to its computational cost.

---

## 3. Signal Ablation Study
To validate the research hypothesis (that multi-signal entity correlation provides superior threat intelligence under one-way monitoring constraints), we execute systematic ablation experiments:

1. **Stage 1 (Flow Only):** Traditional 5-tuple flow metrics.
2. **Stage 2 (Flow + DNS):** Adding observable DNS metadata metrics.
3. **Stage 3 (Flow + DNS + TLS):** Adding observable TLS/QUIC handshake fingerprints and packet size sequences.
4. **Stage 4 (Flow + DNS + TLS + Temporal):** Adding inter-arrival time distributions and jitter analysis.
5. **Stage 5 (All Signals + Entity Baselines):** Incorporating per-host historical profiling.
6. **Stage 6 (All Signals + Graph Fusion):** Full multi-signal Entity Behaviour Graph incident fusion.

We record the marginal precision, recall, and false alarm changes at each incremental stage.
