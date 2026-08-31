import unittest
from schemas import FlowEvent, TCPFlags
from features.feature_extractor import FeatureExtractor
from features.flow_features import extract_flow_features

class TestFlowFeatures(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window_size_sec=5)
        self.base_flow = FlowEvent(
            flow_id="10.0.0.1:1000-10.0.0.2:80-6",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1000,
            dst_port=80,
            protocol=6,
            start_time_iso="2026-08-30T10:00:00Z",
            end_time_iso="2026-08-30T10:00:05Z",
            duration_sec=5.0,
            packet_count=10,
            byte_count=1000,
            tcp_flags=TCPFlags(syn_count=1, ack_count=9),
            packet_lengths=[100]*10,
            inter_arrival_times_ms=[]
        )

    def test_normal_flow_extraction(self):
        """Test benign flow feature extraction."""
        fv = self.extractor.extract(self.base_flow)
        
        self.assertEqual(fv.entity_ip, "10.0.0.1")
        self.assertEqual(fv.flow_features.packets_per_sec, 2.0)
        self.assertEqual(fv.flow_features.bytes_per_sec, 200.0)
        self.assertEqual(fv.flow_features.syn_ratio, 0.1)

    def test_high_packet_rate_flow(self):
        """Test flow with high packet rate."""
        self.base_flow.packet_count = 10000
        self.base_flow.duration_sec = 2.0
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.packets_per_sec, 5000.0)

    def test_high_byte_rate_flow(self):
        """Test flow with high byte rate."""
        self.base_flow.byte_count = 5000000
        self.base_flow.duration_sec = 2.0
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.bytes_per_sec, 2500000.0)

    def test_tcp_syn_heavy_flow(self):
        """Test flow heavily weighted with SYN packets."""
        self.base_flow.packet_count = 100
        self.base_flow.tcp_flags = TCPFlags(syn_count=95, ack_count=5)
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.syn_ratio, 0.95)

    def test_zero_duration_handling(self):
        """Test safe handling of zero duration flows."""
        self.base_flow.duration_sec = 0.0
        self.base_flow.packet_count = 10
        self.base_flow.byte_count = 1000
        
        fv = self.extractor.extract(self.base_flow)
        # Should default to 1.0 duration divisor
        self.assertEqual(fv.flow_features.packets_per_sec, 10.0)
        self.assertEqual(fv.flow_features.bytes_per_sec, 1000.0)

    def test_empty_packet_handling(self):
        """Test flow with no packets (edge case)."""
        self.base_flow.packet_count = 0
        self.base_flow.duration_sec = 5.0
        
        fv = self.extractor.extract(self.base_flow)
        self.assertEqual(fv.flow_features.packets_per_sec, 0.0)
        self.assertEqual(fv.flow_features.syn_ratio, 0.0)
