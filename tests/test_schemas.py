"""Unit tests for shared Pydantic data contracts using standard unittest."""

import unittest
from schemas import (
    FlowEvent,
    TCPFlags,
    FeatureVector,
    FlowFeatures,
    DNSFeatures,
    TLSFeatures,
    TemporalFeatures,
    DNSMetadata,
    TLSMetadata,
    QUICMetadata,
    DetectionSignal,
    ThreatClass,
    DetectorType,
    Severity,
    EntityEvent,
    Incident,
    ThreatStage,
    Alert,
)


class TestSchemas(unittest.TestCase):
    def test_flow_event_serialization(self):
        flow = FlowEvent(
            flow_id="10.0.0.15:49200-198.51.100.2:443-6",
            src_ip="10.0.0.15",
            dst_ip="198.51.100.2",
            src_port=49200,
            dst_port=443,
            protocol=6,
            start_time_iso="2026-08-30T10:00:00.000000Z",
            end_time_iso="2026-08-30T10:00:05.000000Z",
            duration_sec=5.0,
            packet_count=45,
            byte_count=18450,
            tcp_flags=TCPFlags(syn_count=1, ack_count=44),
            packet_lengths=[64, 1500, 1500, 128],
            inter_arrival_times_ms=[10.2, 15.4, 12.1],
        )
        json_data = flow.model_dump_json()
        self.assertIn("10.0.0.15", json_data)
        self.assertEqual(flow.packet_count, 45)
        self.assertEqual(flow.tcp_flags.syn_count, 1)
        self.assertEqual(flow.entity_id, "10.0.0.15")
        self.assertEqual(
            flow.conversation_id,
            "10.0.0.15:49200<->198.51.100.2:443-6",
        )

    def test_flow_event_accepts_phase2_telemetry_metadata(self):
        flow = FlowEvent(
            flow_id="10.0.0.15:49200-198.51.100.2:443-17",
            sensor_id="sensor-a",
            src_ip="10.0.0.15",
            dst_ip="198.51.100.2",
            src_port=49200,
            dst_port=443,
            protocol=17,
            event_time=1780000000.0,
            ingest_time=1780000000.2,
            processing_time=1780000000.3,
            alert_time=None,
            start_time_iso="2026-08-30T10:00:00.000000Z",
            end_time_iso="2026-08-30T10:00:05.000000Z",
            duration_sec=5.0,
            packet_count=45,
            byte_count=18450,
            dns=DNSMetadata(query_name="example.test", query_type="TXT"),
            tls=TLSMetadata(sni="example.test", alpn="h3"),
            quic=QUICMetadata(version="1", connection_id="abcd"),
        )

        self.assertEqual(flow.entity_id, "sensor-a:10.0.0.15")
        self.assertEqual(flow.event_time, 1780000000.0)
        self.assertEqual(flow.dns.query_type, "TXT")
        self.assertEqual(flow.tls.alpn, "h3")
        self.assertEqual(flow.quic.version, "1")

    def test_feature_vector_serialization(self):
        fv = FeatureVector(
            feature_id="fv-001",
            entity_ip="10.0.0.15",
            window_size_sec=5,
            timestamp_iso="2026-08-30T10:00:05.000000Z",
            flow_features=FlowFeatures(packets_per_sec=9.0, bytes_per_sec=3690.0, syn_ratio=0.022),
            dns_features=DNSFeatures(query_length_mean=18.5, entropy_mean=3.82, nxdomain_count=0),
            tls_features=TLSFeatures(sni="c2.threat-domain.net", alpn="h2"),
            temporal_features=TemporalFeatures(periodicity_score=0.94, jitter_pct=4.68),
        )
        self.assertEqual(fv.flow_features.packets_per_sec, 9.0)
        self.assertEqual(fv.dns_features.entropy_mean, 3.82)
        self.assertEqual(fv.tls_features.sni, "c2.threat-domain.net")

    def test_detection_signal(self):
        sig = DetectionSignal(
            signal_id="sig-001",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            detector_type=DetectorType.DETERMINISTIC_BASELINE,
            confidence=0.88,
            severity=Severity.HIGH,
            source_entity="10.0.0.15",
            target_entity="198.51.100.2",
            timestamp_iso="2026-08-30T10:00:05.000000Z",
            indicators={"periodicity_score": 0.94, "jitter_pct": 4.68},
        )
        self.assertEqual(sig.confidence, 0.88)
        self.assertEqual(sig.threat_class, ThreatClass.BOTNET_C2_BEACONING)

    def test_entity_event(self):
        ee = EntityEvent(
            entity_id="10.0.0.15",
            entity_type="HOST_IP",
            timestamp_iso="2026-08-30T10:00:05.000000Z",
            active_signals=["sig-001"],
            baseline_deviation_score=4.2,
            known_destinations_count=10,
            new_destinations_count=1,
        )
        self.assertEqual(ee.baseline_deviation_score, 4.2)

    def test_incident_and_alert(self):
        inc = Incident(
            incident_id="INC-001",
            primary_entity="10.0.0.15",
            risk_score=0.92,
            overall_severity=Severity.CRITICAL,
            first_seen_iso="2026-08-30T09:58:00Z",
            last_seen_iso="2026-08-30T10:00:05Z",
            threat_stages=[
                ThreatStage(
                    stage="RECONNAISSANCE",
                    timestamp_iso="2026-08-30T09:58:00Z",
                    threat_class=ThreatClass.RECON_PORT_SCAN,
                    confidence=0.80,
                ),
                ThreatStage(
                    stage="C2_ESTABLISHMENT",
                    timestamp_iso="2026-08-30T10:00:05Z",
                    threat_class=ThreatClass.BOTNET_C2_BEACONING,
                    confidence=0.88,
                ),
            ],
            evidence_items=["Observed 120 sweep attempts", "High periodicity (0.94) toward 198.51.100.2"],
            recommended_action="Isolate host 10.0.0.15",
        )
        self.assertEqual(inc.risk_score, 0.92)
        self.assertEqual(len(inc.evidence_items), 2)

        alert = Alert(
            alert_id="ALT-001",
            incident_id=inc.incident_id,
            timestamp_iso="2026-08-30T10:00:05Z",
            threat_class=ThreatClass.BOTNET_C2_BEACONING,
            severity=Severity.CRITICAL,
            confidence=0.92,
            source_ip="10.0.0.15",
            destination_ip="198.51.100.2",
            protocol=6,
            summary="C2 beaconing detected with multi-stage evidence",
            evidence_count=2,
        )
        self.assertEqual(alert.alert_id, "ALT-001")
        self.assertEqual(alert.confidence, 0.92)


if __name__ == "__main__":
    unittest.main()
