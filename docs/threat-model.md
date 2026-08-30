# Threat Model & Security Boundaries

## 1. System Environment & Security Boundaries

```text
  [ Production / Protected Enclave ]
                 │
                 │ (Hardware Data Diode / Optical TAP / SPAN)
                 ▼  [STRICT ONE-WAY BOUNDARY]
  [ Isolated Analytics / Detection Environment ]
```

### Assumptions
- Traffic monitored enters the detection system strictly in one direction.
- The monitoring system has **no physical or logical return transmission path** to the source network.
- The analytics host could potentially be exposed to malicious or malformed packets crafted to exploit parser vulnerabilities.

---

## 2. Attacker Capabilities & Threat Scenarios
1. **Adversarial Network Camouflage:** Attackers use jitter, sleep delays, and benign cloud domains (domain fronting, legitimate CDNs) to disguise C2 traffic.
2. **Encrypted Malicious Payloads:** Payloads are encrypted via TLS 1.3 / QUIC; attackers rely on encryption to bypass traditional signature inspection.
3. **High-Rate Flooding (DDoS):** Attackers saturate bandwidth or state tables to cause denial of service or exhaust monitoring resources.
4. **Parser Exploitation / Resource Exhaustion:** Malformed PCAP packets, decompression bombs, or high-cardinality spoofing attacks intended to cause out-of-memory (OOM) failures or crashes in the detection engine.

---

## 3. System Defensive Constraints
- **Parser Hardening & Memory Bounds:** Packet ingestion must use bounded memory buffers, memory-bounded sketches (HyperLogLog, Count-Min Sketch), and safe length-checked packet decoding.
- **Fail-Safe Isolation:** In the event of system saturation, shedding occurs gracefully without destabilizing the host.
- **No Active Retaliation / No Probing:** System will never emit probe packets, query external DNS resolvers over the monitored interface, or trigger active network countermeasures.
