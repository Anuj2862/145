# Shared Contracts & Data Schemas

> [!IMPORTANT]
> These schemas define the data exchange contracts between modules. No module may alter these contracts unilaterally.

```text
[ Packet Ingest ]
       │
       ▼ FlowEvent
[ Flow Normalizer / Window Manager ]
       │
       ▼ FeatureVector
[ Feature Extraction Engines ]
       │
       ▼ DetectionSignal
[ Threat Detectors (Baseline & ML) ]
       │
       ▼ EntityEvent
[ Entity Memory & Graph Engine ]
       │
       ▼ Incident
[ Multi-Signal Fusion & Evidence Engine ]
       │
       ▼ Alert
[ API & Visualization Dashboard ]
```

---

## 1. FlowEvent (Output of Flow Normalizer)
```json
{
  "flow_id": "10.0.0.15:49200-198.51.100.2:443-6",
  "conversation_id": "10.0.0.15:49200<->198.51.100.2:443-6",
  "entity_id": "10.0.0.15",
  "sensor_id": "sensor-edge-01",
  "src_ip": "10.0.0.15",
  "dst_ip": "198.51.100.2",
  "src_port": 49200,
  "dst_port": 443,
  "protocol": 6,
  "event_time": 1785405600.123456,
  "ingest_time": 1785405600.223456,
  "processing_time": 1785405600.323456,
  "alert_time": null,
  "start_time_iso": "2026-08-30T10:00:00.123456Z",
  "end_time_iso": "2026-08-30T10:00:05.123456Z",
  "duration_sec": 5.0,
  "packet_count": 45,
  "byte_count": 18450,
  "tcp_flags": {
    "syn_count": 1,
    "ack_count": 44,
    "fin_count": 0,
    "rst_count": 0
  },
  "packet_lengths": [64, 1500, 1500, 128],
  "inter_arrival_times_ms": [10.2, 15.4, 12.1],
  "dns": {
    "query_name": "example.test",
    "query_type": "A",
    "response_code": "NOERROR",
    "answer_count": 1
  },
  "tls": {
    "sni": "example.test",
    "alpn": "h2",
    "ja3_hash": "771,...",
    "ja4_hash": "t13d1516h2_...",
    "tls_version": "1.3"
  },
  "quic": {
    "sni": "example.test",
    "alpn": "h3",
    "version": "1",
    "connection_id": "optional-passive-id"
  }
}
```

`flow_id` remains the directional 5-tuple identity. `conversation_id`
is a deterministic bidirectional grouping key for analysis only; state
updates must still work when only one direction is observed. `entity_id`
defaults to the source IP, or `sensor_id:src_ip` when a non-default
sensor is supplied.

Time fields are intentionally separated:

- `event_time`: capture/network observation time used for traffic reasoning.
- `ingest_time`: time the packet/event entered the pipeline.
- `processing_time`: time the pipeline processed the event.
- `alert_time`: time an alert was emitted, when applicable.

---

## 2. FeatureVector (Output of Feature Extractors)
```json
{
  "feature_id": "fv-10.0.0.15-20260830100005",
  "entity_ip": "10.0.0.15",
  "flow_id": "10.0.0.15:49200-198.51.100.2:443-6",
  "window_size_sec": 5,
  "timestamp_iso": "2026-08-30T10:00:05.000000Z",
  "flow_features": {
    "packets_per_sec": 9.0,
    "bytes_per_sec": 3690.0,
    "syn_ratio": 0.022,
    "fan_out_dest_count": 1
  },
  "dns_features": {
    "query_length_mean": 18.5,
    "entropy_mean": 3.82,
    "nxdomain_count": 0,
    "txt_record_ratio": 0.0
  },
  "tls_features": {
    "ja3_hash": "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
    "ja4_hash": "t13d1516h2_8daaf6152771_b186095e22b6",
    "sni": "c2.threat-domain.net",
    "alpn": "h2"
  },
  "temporal_features": {
    "inter_arrival_mean_ms": 111.1,
    "inter_arrival_std_ms": 5.2,
    "periodicity_score": 0.94,
    "jitter_pct": 4.68
  },
  "entity_features": {
    "historical_mean_pps": 2.5,
    "historical_std_pps": 0.8,
    "pps_z_score": 8.125,
    "is_new_destination": true
  }
}
```

---

## 3. DetectionSignal (Output of Detectors)
```json
{
  "signal_id": "sig-c2-001",
  "threat_class": "BOTNET_C2_BEACONING",
  "detector_type": "DETERMINISTIC_BASELINE",
  "confidence": 0.88,
  "severity": "HIGH",
  "source_entity": "10.0.0.15",
  "target_entity": "198.51.100.2",
  "timestamp_iso": "2026-08-30T10:00:05.000000Z",
  "indicators": {
    "periodicity_score": 0.94,
    "jitter_pct": 4.68,
    "connection_count": 30,
    "destination_cardinality": 1
  }
}
```

---

## 4. EntityEvent (Output of Entity Memory Engine)
```json
{
  "entity_id": "10.0.0.15",
  "entity_type": "HOST_IP",
  "timestamp_iso": "2026-08-30T10:00:05.000000Z",
  "active_signals": ["sig-dns-001", "sig-c2-001"],
  "baseline_deviation_score": 0.85,
  "known_destinations_count": 12,
  "new_destinations_count": 1
}
```

---

## 5. Incident (Output of Incident Builder & Fusion)
```json
{
  "incident_id": "INC-20260830-001",
  "primary_entity": "10.0.0.15",
  "risk_score": 0.92,
  "overall_severity": "CRITICAL",
  "status": "OPEN",
  "first_seen_iso": "2026-08-30T09:58:00.000000Z",
  "last_seen_iso": "2026-08-30T10:00:05.000000Z",
  "threat_stages": [
    {
      "stage": "RECONNAISSANCE",
      "timestamp_iso": "2026-08-30T09:58:00Z",
      "threat_class": "RECON_PORT_SCAN",
      "confidence": 0.79
    },
    {
      "stage": "C2_ESTABLISHMENT",
      "timestamp_iso": "2026-08-30T10:00:05Z",
      "threat_class": "BOTNET_C2_BEACONING",
      "confidence": 0.88
    }
  ],
  "evidence_items": [
    "Identified 120 port scan attempts in 5s window at 09:58:00Z",
    "High periodicity (0.94) and low jitter (4.7%) observed toward 198.51.100.2",
    "Target domain 'c2.threat-domain.net' observed with high character entropy (3.82)",
    "Traffic rate deviates significantly (+8.1 sigma) from historical entity baseline"
  ],
  "recommended_action": "Isolate host 10.0.0.15; inspect local endpoint for active C2 agent execution."
}
```

---

## 6. Alert (Standardized JSON Alert for Dashboard & API)
```json
{
  "alert_id": "ALT-20260830-100005-001",
  "incident_id": "INC-20260830-001",
  "timestamp_iso": "2026-08-30T10:00:05.000000Z",
  "threat_class": "BOTNET_C2_BEACONING",
  "severity": "CRITICAL",
  "confidence": 0.92,
  "source_ip": "10.0.0.15",
  "destination_ip": "198.51.100.2",
  "protocol": 6,
  "summary": "Multi-signal correlation confirmed high-confidence C2 beaconing on host 10.0.0.15",
  "evidence_count": 4
}
```
