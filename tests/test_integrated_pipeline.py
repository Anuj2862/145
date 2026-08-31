"""End-to-end integration test for full IntegratedThreatPipeline (Members 1, 2, and 3)."""

import unittest
import struct
import tempfile
import os

from pipeline.integrated_runner import IntegratedThreatPipeline


def create_minimal_syn_flood_pcap(filepath: str, packet_count: int = 50):
    """Generate a valid binary PCAP file containing synthetic TCP SYN flood packets."""
    with open(filepath, "wb") as f:
        # PCAP Global Header (24 bytes)
        # magic_number (0xa1b2c3d4), version_major (2), version_minor (4), thiszone (0), sigfigs (0), snaplen (65535), network (1 = Ethernet)
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        # Synthetic SYN packets
        for i in range(packet_count):
            ts_sec = 1700000000 + (i // 10)
            ts_usec = (i % 10) * 100000

            # Ethernet Header (14 bytes): Dst MAC, Src MAC, EtherType (0x0800 IPv4)
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

            # IPv4 Header (20 bytes): 192.168.1.100 -> 10.0.0.1, Proto=6 (TCP)
            src_ip = bytes([192, 168, 1, 100])
            dst_ip = bytes([10, 0, 0, 1])
            ip = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00" + src_ip + dst_ip

            # TCP Header (20 bytes): SrcPort=49152+i, DstPort=80, SYN Flag=0x02
            src_port = 49152 + (i % 1000)
            tcp = struct.pack("!HHIIBBHHH", src_port, 80, 1000 + i, 0, 0x50, 0x02, 64240, 0, 0)

            packet_data = eth + ip + tcp
            caplen = len(packet_data)

            # PCAP Packet Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, caplen, caplen)
            f.write(pkt_hdr + packet_data)


class TestIntegratedPipeline(unittest.TestCase):
    def setUp(self):
        self.temp_pcap = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        self.temp_pcap.close()
        create_minimal_syn_flood_pcap(self.temp_pcap.name, packet_count=60)

    def tearDown(self):
        if os.path.exists(self.temp_pcap.name):
            os.remove(self.temp_pcap.name)

    def test_end_to_end_pcap_processing(self):
        dispatched_alerts = []
        created_incidents = []

        pipeline = IntegratedThreatPipeline(
            artifact_dir="models/artifacts",
            window_size_sec=5.0,
            step_size_sec=1.0,
            enable_ml=True,
            on_alert_callback=lambda a: dispatched_alerts.append(a),
            on_incident_callback=lambda inc: created_incidents.append(inc),
        )

        stats = pipeline.process_pcap(self.temp_pcap.name)

        # 1. Verify ingestion stats
        self.assertEqual(stats.packets_processed, 60)
        self.assertGreaterEqual(stats.flows_tracked, 1)
        self.assertGreaterEqual(stats.windows_emitted, 1)

        # 2. Verify Entity Memory & Graph
        profiles = pipeline.entity_memory.get_all_profiles()
        self.assertIn("192.168.1.100", profiles)
        self.assertGreaterEqual(profiles["192.168.1.100"].total_observations, 1)

        graph_d3 = pipeline.entity_graph.export_d3_format()
        self.assertGreaterEqual(len(graph_d3["nodes"]), 1)


if __name__ == "__main__":
    unittest.main()
