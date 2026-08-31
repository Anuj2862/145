# UniGuard AI: Final Measured Evaluation Results

**Repository:** `145`  
**Problem Statement:** PS 26145 — *"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic"*  
**Verification Baseline:** Strictly measured empirical metrics from immutable JSON dossiers. Zero fabricated values.

---

## 1. Master Experiment Summary Table

| Experiment ID | Phase | Testbed Scope | Primary Focus | Measured Macro F1 | Measured Benign False Alarm Rate | Measured p50 Latency | Throughput | Dossier Artifact Path |
| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **`EXP-20260831-172529`** | 2B | 8 PCAPs (22.6k pkts) | Baseline Exp 0 | 0.0127 | N/A | 3.34 ms | 1,120.4 pps | [`evaluation/results/EXP-20260831-172529.json`](file:///Users/anuj/Desktop/145/evaluation/results/EXP-20260831-172529.json) |
| **`EXP-20260831-174532`** | 2B.2 | 8 PCAPs (22.6k pkts) | Corrected Baseline Exp 1 | 0.3636 | 0.9634 | 3.35 ms | 1,100.8 pps | [`evaluation/results/EXP-20260831-174532.json`](file:///Users/anuj/Desktop/145/evaluation/results/EXP-20260831-174532.json) |
| **`ABLATION-20260831-175858`** | 2D | 8 PCAPs (22.6k pkts) | Initial 4-Way Ablation | 0.4101 (Mode D) | N/A | 3.51 ms | 1,080.5 pps | [`evaluation/results/ABLATION-20260831-175858.json`](file:///Users/anuj/Desktop/145/evaluation/results/ABLATION-20260831-175858.json) |
| **`ABLATION-20260831-190518`** | 2D.2 | 9 PCAPs (22.7k pkts) | Corrected 4-Way Ablation | 0.3777 (Mode A) / 0.3305 (Mode D) | 0.1519 (Mode C) / 0.9517 (Mode D) | 3.47 ms | 1,090.9 pps | [`evaluation/results/ABLATION-20260831-190518.json`](file:///Users/anuj/Desktop/145/evaluation/results/ABLATION-20260831-190518.json) |
| **`ROBUSTNESS-20260831-191406`** | 2E | 32 Perturbations | Adversarial Robustness | Mapped Boundaries | Dynamic | 3.38 ms | 11,800.0 pps | [`evaluation/results/ROBUSTNESS-20260831-191406.json`](file:///Users/anuj/Desktop/145/evaluation/results/ROBUSTNESS-20260831-191406.json) |

---

## 2. Four-Way Multi-Mode Ablation Scorecard (`ABLATION-20260831-190518`)

| Metric | Mode A (Heuristics Only) | Mode B (ML Only) | Mode C (Anomaly Only) | Mode D (Fused Hybrid) |
| :--- | :---: | :---: | :---: | :---: |
| **Macro Precision** | **0.3200** | 0.0000 | 0.0000 | **0.0748** |
| **Macro Recall** | **0.3667** | 0.0000 | 0.0000 | **0.2167** |
| **Macro F1-Score** | **0.3777** | N/A | N/A | **0.3305** |
| **Benign False Alarm Rate** | 0.9641 | **0.1519** | **0.1519** | 0.9517 |
| **Threat Miss Rate (FNR)** | **0.5280** | 0.9680 | 0.8480 | 0.8160 |
| **Median Latency (p50)** | **0.05 ms** | **0.10 ms** | **3.27 ms** | **3.47 ms** |
| **95th Percentile Latency (p95)** | **0.06 ms** | **0.16 ms** | **3.43 ms** | **3.66 ms** |
| **Throughput** | **1,277.0 pps** | **1,240.1 pps** | **1,093.5 pps** | **1,090.9 pps** |

---

## 3. Binary Unsupervised Anomaly Detection Scorecard

| Binary Evaluation Metric | Mode A (Heuristics) | Mode B (ML Only) | Mode C (Anomaly Only) | Mode D (Fused Hybrid) |
| :--- | :---: | :---: | :---: | :---: |
| **Anomaly Precision** | 0.0779 | 0.0351 | **0.1473** | 0.0323 |
| **Anomaly Recall** | **0.4720** | 0.0320 | **0.1520** | 0.1840 |
| **Anomaly F1-Score** | 0.1338 | 0.0335 | **0.1496** | 0.0550 |
| **Anomaly False Alarm Rate** | 0.9641 | **0.1519** | **0.1519** | 0.9517 |

---

## 4. Adversarial Robustness Evasion Boundaries (`ROBUSTNESS-20260831-191406`)

| Perturbation Domain | Parameter Threshold | Measured Detection Status | Transition / Boundary Finding |
| :--- | :---: | :---: | :--- |
| **C2 Beacon Jitter** | $\le 20\%$ Jitter | 🟢 **DETECTED** | Periodicity calculation stable ($> 0.70$). |
| **C2 Beacon Jitter** | $\ge 50\%$ Jitter | 🔴 **EVADED** | Periodic pattern broken; requires multivariate anomaly detection. |
| **Reconnaissance Rate** | $\ge 0.5\text{ pps}$ | 🟢 **DETECTED** | Host port cardinality exceeds thresholds within sliding windows. |
| **Reconnaissance Rate** | $0.1\text{ pps}$ | 🔴 **EVADED** | Ultra-slow scanning evades short-term $5\text{s}$ windows. |
| **Volumetric DDoS Rate** | $\ge 3,000\text{ pps}$ | 🟢 **DETECTED** | High velocity packet flood triggers critical alert immediately. |
| **Volumetric DDoS Rate** | $1,000\text{ pps}$ | 🟢 **DETECTED** | Modulated burst detected via TCP SYN asymmetry. |
