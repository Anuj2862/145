# Implementation Plan & Milestone Roadmap

## Development Philosophy
1. **Vertical Slice First:** Establish an end-to-end working pipeline (PCAP $\rightarrow$ Flow $\rightarrow$ Window $\rightarrow$ Heuristic Detector $\rightarrow$ Standardized Alert) before adding breadth.
2. **Deterministic Baseline Before ML:** Always implement and measure an interpretable heuristic baseline before training machine learning models.
3. **Strict Interface Contracts:** Modules communicate exclusively through validated schemas (`schemas/`).
4. **Passive Unidirectional Compliance:** Strictly zero return-path, zero active probing, and zero payload decryption.

---

## Phase Progression & Completion Status

| Milestone | Status | Key Deliverables | Verification Result |
| :--- | :---: | :--- | :--- |
| **Milestone 0: Foundation & Contracts** | ✅ Completed | Shared schemas (`FlowEvent`, `FeatureVector`, `DetectionSignal`, `Incident`, `Alert`), Git workflows, architectural documentation | Verified via `test_schemas.py` |
| **Milestone 1: Vertical Slice & Flow Engine** | ✅ Completed | Zero-dependency PCAP parser, 5-tuple flow state, 5s burst & 30s session windows, alert builder & verifier | Verified via `test_milestone1_integration.py` |
| **Milestone 2: Replay & Streaming Pipeline** | ✅ Completed | Rate-controlled PCAP replay, bounded queue, sliding window stream | Verified via `test_replay_pipeline.py` |
| **Milestone 3: 6 Deterministic Baseline Detectors** | ✅ Completed | Volumetric DDoS, C2 Beaconing, DNS/DGA, Encrypted Threat, Port Recon, Data Exfil | Verified via `test_baseline_detector.py` & detector tests |
| **Milestone 4: Multi-Family Feature Extractors** | ✅ Completed | Flow velocity, DNS entropy, TLS JA3/JA4 metadata, temporal periodicity, recon/exfil cardinality | Verified via feature extractors test suite |
| **Milestone 5: ML Models & Anomaly Detection** | ✅ Completed | LightGBM multi-class (99.89% acc), Random Forest, Isolation Forest (375k samples/sec) | Verified via `test_ml_inference.py` |
| **Milestone 6: Entity Memory & Baseline Profiler** | ✅ Completed | Rolling entity profiles, historical baseline distributions, dynamic $Z$-score deviation scoring | Verified via `test_entity_memory.py` |
| **Milestone 7: Entity Behaviour Graph** | ✅ Completed | Directed temporal graph connecting Hosts $\leftrightarrow$ External IPs $\leftrightarrow$ Signals $\leftrightarrow$ Incidents; D3 JSON export | Verified via `test_entity_graph.py` |
| **Milestone 8: Multi-Signal Fusion & Evidence Engine** | ✅ Completed | Active correlation groups, multi-threat diversity bonus, detector agreement bonus, MITRE stage mapping, human-readable evidence chains | Verified via `test_fusion_engine.py` & `test_evidence_engine.py` |
| **Milestone 9: FastAPI & SOC Command Dashboard** | ✅ Completed | FastAPI REST/WebSocket backend, interactive cyber SOC command dashboard with live oscilloscope, 2D physics graph, and attack injectors | Verified via `test_api_endpoints.py` & live server |
| **Milestone 10: Unified Integrated Streaming Pipeline** | ✅ Completed | Full stack end-to-end pipeline (`pipeline/integrated_runner.py`) running packet $\rightarrow$ flow $\rightarrow$ detect $\rightarrow$ fuse $\rightarrow$ incident $\rightarrow$ UI | **308/308 Automated Tests Passing** |

---

## 🎯 Verification Evidence

1. **Automated Test Suite:**
   ```text
   ======================= 308 passed, 12 warnings in 5.83s =======================
   ```
2. **Machine Learning Performance:**
   - LightGBM Multiclass Validation Accuracy: **99.89%**
   - Macro F1-Score: **0.9985**
   - Isolation Forest Throughput: **374,976 samples/second**
3. **End-to-End Latency Target:**
   - Under passive streaming conditions, total pipeline time from packet arrival to incident creation is **$< 1.0\text{ second}$**.
