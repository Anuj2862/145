# M20 Robustness, Evasion, Concept Drift & Stress Testing Report

- **Report ID:** `EVAL-M20-20260901-084234`
- **Execution Date:** `2026-09-01T08:42:34.949602+00:00`
- **Feature Schema Version:** `feature-schema-v2.1.0`
- **Model Version:** `v2.1.0-calibrated-lgb`
- **Duration:** `104.57s`

---

## 1. C2 Jitter Sweep (0% to 70%)

| Jitter Level | Fused Risk | Observed Verdict | Detected | TTFD (s) | Incident Created |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0.0%** | 0.4327 | `BOTNET_C2_BEACONING` | YES | 0.0 | YES |
| **5.0%** | 0.4298 | `BOTNET_C2_BEACONING` | YES | 0.0 | YES |
| **10.0%** | 0.4327 | `BOTNET_C2_BEACONING` | YES | 0.0 | YES |
| **20.0%** | 0.4327 | `BOTNET_C2_BEACONING` | YES | 0.0 | YES |
| **30.0%** | 0.4335 | `BOTNET_C2_BEACONING` | YES | 0.0 | YES |
| **50.0%** | 0.4316 | `BOTNET_C2_BEACONING` | YES | 0.0 | YES |
| **70.0%** | 0.4298 | `BOTNET_C2_BEACONING` | YES | 0.0 | YES |

---

## 2. Slow Reconnaissance Evaluation

| Scan Speed | Rate Scale | Fused Risk | Observed Threat | Fan-Out Effective |
| :--- | :--- | :--- | :--- | :--- |
| **fast_scan** | 1.0 | 0.5565 | `BOTNET_C2_BEACONING` | YES |
| **medium_scan** | 0.5 | 0.5623 | `BOTNET_C2_BEACONING` | YES |
| **slow_scan** | 0.1 | 0.563 | `BOTNET_C2_BEACONING` | YES |
| **very_slow_scan** | 0.02 | 0.5569 | `BOTNET_C2_BEACONING` | YES |

---

## 3. Low-and-Slow Exfiltration Evaluation

| Exfil Rate | Rate Scale | Fused Risk | Observed Threat | Baseline Deviation Tracked |
| :--- | :--- | :--- | :--- | :--- |
| **burst_exfil** | 1.0 | 0.5161 | `BOTNET_C2_BEACONING` | YES |
| **medium_exfil** | 0.4 | 0.5192 | `BOTNET_C2_BEACONING` | YES |
| **slow_exfil** | 0.1 | 0.5195 | `BOTNET_C2_BEACONING` | YES |
| **very_slow_exfil** | 0.02 | 0.5209 | `BOTNET_C2_BEACONING` | YES |

---

## 4. Benign Periodic Traffic Baselines

| Scenario | Fused Risk | Observed Threat | False Alert | Periodicity Misclassification Avoided |
| :--- | :--- | :--- | :--- | :--- |
| **ntp_polling** | 0.5136 | `VOLUMETRIC_DDOS` | YES | YES |
| **infra_monitoring** | 0.5165 | `VOLUMETRIC_DDOS` | YES | YES |
| **scheduled_telemetry** | 0.5103 | `VOLUMETRIC_DDOS` | YES | YES |
| **nightly_backup** | 0.5229 | `DATA_EXFILTRATION` | YES | YES |
| **software_update** | 0.5136 | `VOLUMETRIC_DDOS` | YES | YES |
| **cloud_sync** | 0.514 | `VOLUMETRIC_DDOS` | YES | YES |

---

## 5. Packet Loss Robustness

| Loss Rate | Original Packets | Retained Packets | Fused Risk | Observed Threat | Incident Confirmed |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **loss_0pct** | 10090 | 10090 | 0.6005 | `BOTNET_C2_BEACONING` | YES |
| **loss_1pct** | 10090 | 9985 | 0.6556 | `BOTNET_C2_BEACONING` | YES |
| **loss_5pct** | 10090 | 9569 | 0.5939 | `VOLUMETRIC_DDOS` | YES |
| **loss_10pct** | 10090 | 9078 | 0.5772 | `VOLUMETRIC_DDOS` | YES |
| **loss_20pct** | 10090 | 8044 | 0.5403 | `VOLUMETRIC_DDOS` | YES |

---

## 6. Missing Telemetry Robustness

| Telemetry Mode | Fused Risk | Observed Threat | Detected | Explicit Missing State |
| :--- | :--- | :--- | :--- | :--- |
| **FULL** | 0.4909 | `BOTNET_C2_BEACONING` | NO | YES |
| **NO_DNS** | 0.4909 | `BOTNET_C2_BEACONING` | NO | YES |
| **NO_TLS** | 0.4909 | `BOTNET_C2_BEACONING` | NO | YES |
| **FLOW_ONLY** | 0.4909 | `BOTNET_C2_BEACONING` | NO | YES |

---

## 7. Concept Drift & Calibration Degradation

| Period | Description | Samples | Drift Events | Brier Score | ECE | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **P1_baseline** | Baseline enterprise traffic distribution | 500 | 64 | 0.0385 | 0.1713 | `STABLE` |
| **P2_benign_distribution_shift** | Traffic volume shift & increased packet rate | 500 | 98 | N/A | N/A | `DRIFT_IDENTIFIED` |
| **P3_new_service_mix** | New cloud destination diversity & TLS novelty | 500 | 36 | N/A | N/A | `DRIFT_IDENTIFIED` |
| **P4_unseen_attack_parameterization** | Stealth attack mutations & calibration drift measurement | 500 | N/A | 0.103 | 0.2851 | `EVALUATED` |

---

## 8. Production Retraining Safety Policy
- **Live Automatic Retraining:** **PROHIBITED**
- **Candidate Generation:** **OFFLINE ONLY**
- **Human Approval Gate:** **REQUIRED** (`human_approved = True` required before candidate evaluation)
