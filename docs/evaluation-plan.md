# Evaluation Methodology & Benchmark Plan

## 1. Core Evaluation Metrics

To avoid subjective claims, all performance metrics are derived from actual experimental runs:

| Category | Metric | Definition / Calculation | Target / Goal |
| :--- | :--- | :--- | :--- |
| **Accuracy** | Precision | $TP / (TP + FP)$ | Minimizing false alarms |
| | Recall / Detection Rate | $TP / (TP + FN)$ | Maximizing threat capture |
| | F1-Score | $2 \cdot (P \cdot R) / (P + R)$ | Harmonic mean |
| | False Positive Rate (FPR) | $FP / (FP + TN)$ | $< 1\%$ in production-like traffic |
| **Latency** | Detection Latency | $T_{\text{alert}} - T_{\text{first\_threat\_packet}}$ | Fast Path: $< 1.0\text{s}$, Slow Path: $< 30\text{s}$ |
| **System** | Ingestion Throughput | Measured packets/sec, flows/sec, Mbps | High continuous stream rate |
| | Memory Footprint | Max RSS memory in MB | Bounded state ($\le \text{configured limit}$) |
| | CPU Utilization | Average % core utilization | Efficient multi-threading / async |

---

## 2. Comparative Evaluation: Heuristic Baseline vs. ML
For each threat class, we run identical test datasets through:
1. **Deterministic Baseline Detector** (rule / statistical threshold)
2. **Lightweight ML Detector** (trained supervised model, e.g., LightGBM)
3. **Unsupervised Anomaly Detector** (e.g., Isolation Forest / One-Class SVM)

We explicitly document whether ML delivers a statistically meaningful improvement in F1 score and false-positive reduction relative to compute cost.

---

## 3. Signal Ablation Study
To validate the research hypothesis (that multi-signal entity correlation provides superior threat intelligence), we run systematic ablation experiments:

1. **Stage 1 (Flow Only):** Traditional 5-tuple flow metrics.
2. **Stage 2 (Flow + DNS):** Adding DNS entropy, record distributions, NXDOMAIN rates.
3. **Stage 3 (Flow + DNS + TLS):** Adding JA3/JA4 fingerprints and packet size sequences.
4. **Stage 4 (Flow + DNS + TLS + Temporal):** Adding inter-arrival time distributions and jitter analysis.
5. **Stage 5 (All Signals + Entity Baselines):** Incorporating entity historical profiling.
6. **Stage 6 (All Signals + Graph Fusion):** Full multi-signal Entity Behaviour Graph incident fusion.

We record the marginal precision, recall, and false alarm improvements at each incremental stage.
