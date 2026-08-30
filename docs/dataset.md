# Dataset Strategy & Ground-Truth Specification

## 1. Overview
The evaluation methodology relies on a dual-source dataset strategy:
1. **Public Benchmark Datasets:** Curated subsets of standard network security datasets (e.g., CIC-IDS2017/2018, UNSW-NB15, CTU-13 for C2, Stratosphere IPS datasets) adapted for unidirectional playback.
2. **Controlled Lab-Generated Traffic Scenarios:** Controlled benign background traffic mixed with precisely injected synthetic attack scenarios.

---

## 2. Lab Traffic Generation Categories

### Benign Traffic Generation
- Realistic background flows generated in isolated lab environments using tools like `iperf3`, `Ostinato`, `TRex`, automated HTTP/DNS client resolvers, and benign TLS sessions.

### Controlled Attack Scenarios
1. **DDoS:** SYN floods, UDP amplification floods, spoofed source IP sweeps.
2. **Reconnaissance:** TCP SYN stealth scans, horizontal subnet sweeps, UDP port sweeps.
3. **C2 Beaconing:** Automated agents executing periodic and jittered beacon callbacks (fixed intervals: 10s, 30s, 60s; jittered intervals: $\pm 10-30\%$).
4. **DGA & DNS Tunnelling:** Algorithmic pseudo-random domain queries, base32/base64 encoded DNS TXT/A record queries, high NXDOMAIN volume.
5. **Encrypted Session Malware:** TLS sessions with known suspicious JA3/JA4 fingerprints and abnormal early packet size sequence profiles.
6. **Data Exfiltration:** High-rate outbound transfers over HTTPS/DNS/ICMP with asymmetric flow byte ratios.

---

## 3. Ground-Truth Schema & Labeling

Every dataset scenario is accompanied by a ground-truth JSON manifest:

```json
{
  "scenario_id": "SCN-C2-007",
  "pcap_file": "c2_beacon_007.pcap",
  "threat_class": "BOTNET_C2_BEACONING",
  "target_entity": "10.0.0.42",
  "start_time_iso": "2026-08-30T10:00:00Z",
  "end_time_iso": "2026-08-30T10:05:00Z",
  "ground_truth_flows": [
    {
      "src_ip": "10.0.0.42",
      "dst_ip": "198.51.100.15",
      "src_port": 49152,
      "dst_port": 443,
      "protocol": 6,
      "label": "ATTACK",
      "attack_type": "C2_BEACONING"
    }
  ],
  "parameters": {
    "beacon_interval_sec": 30,
    "jitter_pct": 15
  }
}
```

This ensures zero ambiguity during automated evaluation against pipeline outputs.
