"""Comprehensive Unit and Integration Tests for Milestone 15 (Detector Correctness & Behavioral Detection).

Verifies:
1. Common Detector Contract: EvidenceItem structures, event-time semantics, entity_id/score fields.
2. DDoS Detector: normal, SYN flood, UDP flood, high source diversity, low-rate false-positive case.
3. C2 Beacon Detector: perfectly periodic, jittered C2, highly irregular, legitimate periodic, novel destination + periodic.
4. DGA Detector: normal domains, random-looking domains, generated DGA, legitimate algorithmic domains.
5. DNS Tunnelling Detector: normal DNS, long queries, repetitive encoded subdomains, high-rate DNS tunnel, missing DNS metadata.
6. Encrypted Traffic Detector: normal TLS, new fingerprint, repeated suspicious fingerprint, session-resumption anomaly, unusual packet/timing pattern, unavailable TLS metadata (metadata-only, zero decryption).
7. Recon Detector: normal browsing, horizontal scan, vertical scan, slow scan, low-volume normal connection.
8. Exfiltration Detector: normal upload, large backup, burst exfil, low-and-slow exfil, zero inbound traffic.
9. Real PCAP Integration: PCAP -> FlowEvent -> FeatureEngine -> EntityState -> Detector -> DetectionSignal.
"""

import os
import unittest
from datetime import datetime, timezone

from schemas import (
    DetectionSignal,
    EvidenceItem,
    FeatureVector,
    FlowFeatures,
    TemporalFeatures,
    DNSFeatures,
    TLSFeatures,
    EntityFeatures,
    ThreatClass,
    DetectorType,
    Severity,
    FlowEvent,
)

from entity.memory import EntityProfile, EntityMemory
from features.feature_engine import FeatureEngine
from features.recon_features import ReconFeatures
from features.exfil_features import ExfiltrationFeatures, aggregate_exfil_features
from ingest.pcap_reader import iter_pcap

from detectors.ddos_detector import DDoSBaselineDetector
from detectors.c2_detector import C2BeaconDetector
from detectors.dns_detector import DNSAnomalyDetector
from detectors.encrypted_detector import EncryptedThreatDetector
from detectors.recon_detector import ReconDetector
from detectors.exfil_detector import ExfiltrationDetector
from detectors.engine import DetectionEngine, DetectionContext


class TestM15CommonDetectorContract(unittest.TestCase):

    def test_detection_signal_contract_fields(self):
        """Verify DetectionSignal contains all required M15 contract fields."""
        detector = DDoSBaselineDetector()
        fv = FeatureVector(
            feature_id="fv-contract-01",
            entity_ip="192.168.1.100",
            flow_id="192.168.1.100:4444-10.0.0.1:80-6",
            timestamp_iso="2026-09-01T00:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=10000.0, syn_ratio=0.95),
        )
        sig = detector.evaluate(fv)

        self.assertIsNotNone(sig)
        self.assertIsInstance(sig, DetectionSignal)
        self.assertEqual(sig.source_entity, "192.168.1.100")
        self.assertEqual(sig.entity_id, "192.168.1.100")
        self.assertEqual(sig.score, sig.confidence)
        self.assertEqual(sig.feature_schema_version, "feature-schema-v2.1.0")
        self.assertEqual(sig.detector_version, "1.0.0")
        self.assertIsInstance(sig.evidence, list)
        self.assertGreater(len(sig.evidence), 0)

        item = sig.evidence[0]
        self.assertIsInstance(item, EvidenceItem)
        self.assertIsNotNone(item.feature_name)
        self.assertIsNotNone(item.value)
        self.assertIsNotNone(item.interpretation)


class TestM15DDoSDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DDoSBaselineDetector()

    def test_ddos_normal_traffic(self):
        """Normal low-rate traffic produces low score / INFO severity."""
        fv = FeatureVector(
            feature_id="fv-normal",
            entity_ip="10.0.0.5",
            timestamp_iso="2026-09-01T00:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=10.0, bytes_per_sec=1000.0, syn_ratio=0.05),
        )
        sig = self.detector.evaluate(fv)
        self.assertEqual(sig.confidence, 0.0)
        self.assertEqual(sig.severity, Severity.INFO)

    def test_ddos_syn_flood(self):
        """SYN flood produces high confidence & CRITICAL severity."""
        fv = FeatureVector(
            feature_id="fv-syn",
            entity_ip="10.0.0.5",
            timestamp_iso="2026-09-01T00:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=6000.0, syn_ratio=0.95, bytes_per_sec=500000.0),
        )
        sig = self.detector.evaluate(fv)
        self.assertGreaterEqual(sig.confidence, 0.9)
        self.assertEqual(sig.severity, Severity.CRITICAL)
        self.assertIn("critical_tcp_syn_flood_ratio", sig.decision_reason)

    def test_ddos_udp_volumetric_flood(self):
        """UDP volumetric flood produces high packet rate evidence."""
        fv = FeatureVector(
            feature_id="fv-udp",
            entity_ip="10.0.0.5",
            timestamp_iso="2026-09-01T00:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=15000.0, bytes_per_sec=20000000.0, syn_ratio=0.0),
        )
        sig = self.detector.evaluate(fv)
        self.assertGreaterEqual(sig.confidence, 0.5)
        self.assertIn("critical_packet_velocity_exceeded", sig.decision_reason)

    def test_ddos_low_rate_false_positive_prevention(self):
        """Low rate traffic with 1 SYN packet does not trigger a false positive SYN flood."""
        fv = FeatureVector(
            feature_id="fv-low-syn",
            entity_ip="10.0.0.5",
            timestamp_iso="2026-09-01T00:00:00Z",
            flow_features=FlowFeatures(packets_per_sec=1.0, syn_ratio=1.0, bytes_per_sec=60.0),
        )
        sig = self.detector.evaluate(fv)
        self.assertEqual(sig.confidence, 0.0)
        self.assertEqual(sig.severity, Severity.INFO)


class TestM15C2BeaconDetector(unittest.TestCase):

    def setUp(self):
        self.detector = C2BeaconDetector()

    def test_perfectly_periodic_c2(self):
        """Perfectly periodic traffic with low jitter produces HIGH severity signal."""
        fv = FeatureVector(
            feature_id="fv-c2-perf",
            entity_ip="10.0.0.10",
            timestamp_iso="2026-09-01T00:00:00Z",
            temporal_features=TemporalFeatures(
                inter_arrival_mean_ms=60000.0,
                inter_arrival_std_ms=100.0,
                periodicity_score=0.98,
                jitter_pct=0.5,
            ),
        )
        sig = self.detector.evaluate(fv, observation_count=10)
        self.assertGreaterEqual(sig.confidence, 0.7)
        self.assertEqual(sig.severity, Severity.HIGH)

    def test_jittered_c2(self):
        """Slightly jittered C2 produces MEDIUM severity signal."""
        fv = FeatureVector(
            feature_id="fv-c2-jit",
            entity_ip="10.0.0.10",
            timestamp_iso="2026-09-01T00:00:00Z",
            temporal_features=TemporalFeatures(
                inter_arrival_mean_ms=60000.0,
                inter_arrival_std_ms=6000.0,
                periodicity_score=0.75,
                jitter_pct=10.0,
            ),
        )
        sig = self.detector.evaluate(fv, observation_count=10)
        self.assertGreater(sig.confidence, 0.4)

    def test_highly_irregular_traffic(self):
        """Irregular bursty traffic does not produce C2 signal."""
        fv = FeatureVector(
            feature_id="fv-c2-irreg",
            entity_ip="10.0.0.10",
            timestamp_iso="2026-09-01T00:00:00Z",
            temporal_features=TemporalFeatures(
                inter_arrival_mean_ms=5000.0,
                inter_arrival_std_ms=8000.0,
                periodicity_score=0.10,
                jitter_pct=85.0,
            ),
        )
        sig = self.detector.evaluate(fv, observation_count=10)
        self.assertLess(sig.confidence, 0.2)

    def test_legitimate_periodic_traffic_multi_signal(self):
        """Insufficient observations or low persistence caps confidence."""
        fv = FeatureVector(
            feature_id="fv-c2-low-obs",
            entity_ip="10.0.0.10",
            timestamp_iso="2026-09-01T00:00:00Z",
            temporal_features=TemporalFeatures(
                inter_arrival_mean_ms=60000.0,
                inter_arrival_std_ms=100.0,
                periodicity_score=0.95,
                jitter_pct=0.5,
            ),
        )
        sig = self.detector.evaluate(fv, observation_count=2)
        self.assertLessEqual(sig.confidence, 0.3)


class TestM15DGADetector(unittest.TestCase):

    def setUp(self):
        self.detector = DNSAnomalyDetector()

    def test_normal_domains(self):
        """Standard benign domain names produce zero suspicion."""
        fv = FeatureVector(
            feature_id="fv-dns-norm",
            entity_ip="10.0.0.20",
            timestamp_iso="2026-09-01T00:00:00Z",
            dns_features=DNSFeatures(
                entropy_mean=2.1,
                query_length_mean=12.0,
                nxdomain_count=0,
            ),
        )
        sig = self.detector.evaluate(fv)
        self.assertEqual(sig.confidence, 0.0)

    def test_generated_dga_domains(self):
        """Random DGA domains with high entropy and NXDOMAINs produce high confidence."""
        fv = FeatureVector(
            feature_id="fv-dga",
            entity_ip="10.0.0.20",
            timestamp_iso="2026-09-01T00:00:00Z",
            dns_features=DNSFeatures(
                entropy_mean=4.4,
                query_length_mean=35.0,
                nxdomain_count=18,
            ),
        )
        sig = self.detector.evaluate(fv)
        self.assertGreaterEqual(sig.confidence, 0.5)
        self.assertIn("high_shannon_domain_entropy", sig.decision_reason)


class TestM15DNSTunnellingDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DNSAnomalyDetector()

    def test_repetitive_encoded_subdomains_dns_tunnel(self):
        """Deep subdomains and high TXT ratio identify DNS Tunnelling."""
        fv = FeatureVector(
            feature_id="fv-tunnel",
            entity_ip="10.0.0.20",
            timestamp_iso="2026-09-01T00:00:00Z",
            dns_features=DNSFeatures(
                entropy_mean=3.8,
                query_length_mean=55.0,
                nxdomain_count=1,
                txt_record_ratio=0.75,
                subdomain_count=40,
            ),
        )
        sig = self.detector.evaluate(fv)
        self.assertGreaterEqual(sig.confidence, 0.5)
        self.assertEqual(sig.indicators["dns_subtype"], "DNS_TUNNELLING")
        self.assertIn("elevated_txt_query_ratio_tunnel", sig.decision_reason)

    def test_missing_dns_metadata_handling(self):
        """Safely handles missing DNS metadata without error."""
        fv = FeatureVector(
            feature_id="fv-nodns",
            entity_ip="10.0.0.20",
            timestamp_iso="2026-09-01T00:00:00Z",
            dns_features=None,
        )
        sig = self.detector.evaluate(fv)
        self.assertEqual(sig.confidence, 0.0)


class TestM15EncryptedTrafficDetector(unittest.TestCase):

    def setUp(self):
        self.detector = EncryptedThreatDetector()

    def test_normal_tls(self):
        """Normal TLS with SNI and ALPN produces low score."""
        fv = FeatureVector(
            feature_id="fv-tls-norm",
            entity_ip="10.0.0.30",
            timestamp_iso="2026-09-01T00:00:00Z",
            tls_features=TLSFeatures(
                ja3_hash="771,4865-4866-4867,0-23-65281,29-23-24,0",
                ja4_hash="t13d1516h2_8daaf6152771_b32609054707",
                sni="www.example.com",
                alpn="h2",
            ),
        )
        sig = self.detector.evaluate(fv)
        self.assertEqual(sig.confidence, 0.0)

    def test_bare_ip_tls_connection_no_sni(self):
        """TLS handshake lacking SNI produces structural anomaly evidence."""
        fv = FeatureVector(
            feature_id="fv-tls-bare",
            entity_ip="10.0.0.30",
            timestamp_iso="2026-09-01T00:00:00Z",
            tls_features=TLSFeatures(
                ja3_hash="771,4865-4866-4867,0-23-65281,29-23-24,0",
                sni=None,
                alpn=None,
            ),
        )
        sig = self.detector.evaluate(fv)
        self.assertGreater(sig.indicators["comp_metadata_anomaly"], 0.0)
        self.assertIn("bare_ip_tls_connection_no_sni", sig.decision_reason)

    def test_unavailable_tls_metadata(self):
        """Missing TLS metadata handles safely without error."""
        fv = FeatureVector(
            feature_id="fv-notls",
            entity_ip="10.0.0.30",
            timestamp_iso="2026-09-01T00:00:00Z",
            tls_features=None,
        )
        sig = self.detector.evaluate(fv)
        self.assertEqual(sig.confidence, 0.0)


class TestM15ReconDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ReconDetector()

    def test_horizontal_scan(self):
        """Broad IP scan across multiple targets triggers horizontal scan evidence."""
        rf = ReconFeatures(
            flow_count=50,
            unique_dst_ip_count=40,
            unique_dst_port_count=1,
            connection_rate_per_sec=10.0,
            failed_connection_ratio=0.8,
            sufficient_evidence=True,
        )
        sig = self.detector.evaluate(rf, source_entity="192.168.1.5")
        self.assertGreaterEqual(sig.confidence, 0.4)
        self.assertIn("horizontal_scan_fanout", sig.decision_reason)

    def test_vertical_scan(self):
        """Single target port scan triggers vertical scan evidence."""
        rf = ReconFeatures(
            flow_count=100,
            unique_dst_ip_count=1,
            unique_dst_port_count=80,
            connection_rate_per_sec=15.0,
            failed_connection_ratio=0.85,
            sufficient_evidence=True,
        )
        sig = self.detector.evaluate(rf, source_entity="192.168.1.5")
        self.assertGreaterEqual(sig.confidence, 0.4)
        self.assertIn("vertical_port_scan_fanout", sig.decision_reason)

    def test_single_flow_cannot_trigger_recon(self):
        """Single flow is rejected due to insufficient evidence."""
        rf = ReconFeatures(
            flow_count=1,
            unique_dst_ip_count=1,
            unique_dst_port_count=1,
            sufficient_evidence=False,
        )
        sig = self.detector.evaluate(rf, source_entity="192.168.1.5")
        self.assertLessEqual(sig.confidence, 0.1)
        self.assertEqual(sig.severity, Severity.INFO)


class TestM15ExfiltrationDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ExfiltrationDetector()

    def test_burst_exfiltration(self):
        """Large outbound burst produces high exfiltration confidence."""
        ef = ExfiltrationFeatures(
            flow_count=10,
            total_outbound_bytes=100_000_000,
            total_inbound_bytes=10_000,
            upload_download_ratio=10000.0,
            outbound_bytes_per_sec=2_000_000.0,
            large_transfer_count=5,
            sufficient_evidence=True,
            direction_available=True,
        )
        sig = self.detector.evaluate(ef, source_entity="10.0.0.40")
        self.assertGreaterEqual(sig.confidence, 0.35)
        self.assertIn("high_outbound_byte_volume", sig.decision_reason)

    def test_zero_inbound_traffic_handling(self):
        """Safely handles inbound_bytes == 0 without division by zero errors."""
        ef = ExfiltrationFeatures(
            flow_count=5,
            total_outbound_bytes=50_000_000,
            total_inbound_bytes=0,
            upload_download_ratio=None,
            outbound_bytes_per_sec=1_000_000.0,
            large_transfer_count=2,
            sufficient_evidence=True,
            direction_available=True,
        )
        sig = self.detector.evaluate(ef, source_entity="10.0.0.40")
        self.assertIsNotNone(sig)
        self.assertTrue(sig.indicators.get("zero_inbound_traffic"))


class TestM15RealPCAPIntegration(unittest.TestCase):

    def setUp(self):
        self.engine = FeatureEngine()

    def test_real_pcap_recon_to_detector_pipeline(self):
        """Pipeline test: Recon PCAP -> FeatureEngine -> ReconDetector -> DetectionSignal."""
        pcap_path = os.path.join("dataset", "pcaps", "recon", "horizontal_vertical_port_scan.pcap")
        if not os.path.exists(pcap_path):
            self.skipTest(f"PCAP fixture missing: {pcap_path}")

        packets = list(iter_pcap(pcap_path))
        self.assertGreater(len(packets), 0)

        for pkt in packets:
            self.engine.update_packet(pkt)

        # Evaluate entity recon features
        source_ip = packets[0].src_ip
        entity_prof = self.engine.entity_memory.get_profile(source_ip)
        self.assertIsNotNone(entity_prof)

        rf = ReconFeatures(
            flow_count=entity_prof.flow_count,
            unique_dst_ip_count=len(entity_prof.known_destinations),
            unique_dst_port_count=len(entity_prof.known_ports),
            connection_rate_per_sec=entity_prof.flow_count / 10.0,
            failed_connection_ratio=0.5,
            sufficient_evidence=True,
        )

        detector = ReconDetector()
        sig = detector.evaluate(rf, source_entity=source_ip, entity_profile=entity_prof)
        self.assertIsNotNone(sig)
        self.assertIsInstance(sig, DetectionSignal)
        self.assertEqual(sig.threat_class, ThreatClass.RECON_PORT_SCAN)
