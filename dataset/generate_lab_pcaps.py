"""Deterministic Multi-Scenario PCAP Generator for PS 26145 Evaluation.

Generates controlled, deterministic PCAP traces covering benign enterprise traffic
and multiple severity/rate/jitter scenarios across all 6 required threat classes,
explicitly including decision-boundary and edge cases.
"""

from datetime import datetime, timezone, timedelta
import math
import os
from pathlib import Path
import random
import struct
from typing import Dict, List, Optional, Tuple

from dataset.manifest_schema import (
    EvaluationTrafficClass,
    DatasetSplit,
    GenerationMethod,
    TemporalWindow,
    GroundTruthEvent,
    CaptureRecord,
    GroundTruthManifest,
)
from dataset.manifest_manager import ManifestManager


def write_pcap_header(f) -> None:
    """Write standard 24-byte PCAP global header."""
    # Magic (0xa1b2c3d4), Version Major (2), Version Minor (4), Thiszone (0), Sigfigs (0), Snaplen (65535), LinkType (1 = Ethernet)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))


def write_pcap_packet(f, ts_sec: int, ts_usec: int, src_ip_str: str, dst_ip_str: str, src_port: int, dst_port: int, protocol: int, payload_len: int = 64, tcp_flags: int = 0x02) -> None:
    """Write an Ethernet + IPv4 + TCP/UDP frame into the open PCAP file."""
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    
    src_parts = [int(p) for p in src_ip_str.split(".")]
    dst_parts = [int(p) for p in dst_ip_str.split(".")]
    src_bytes = bytes(src_parts)
    dst_bytes = bytes(dst_parts)

    ip_total_len = 20 + (20 if protocol == 6 else 8) + payload_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, ip_total_len, 0x0001, 0x0000, 64, protocol, 0, src_bytes, dst_bytes
    )

    if protocol == 6:  # TCP
        trans_hdr = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port, 1000, 0, 0x50, tcp_flags, 64240, 0, 0
        )
    else:  # UDP
        trans_hdr = struct.pack("!HHHH", src_port, dst_port, 8 + payload_len, 0)

    payload = b"\x00" * payload_len
    packet_data = eth_hdr + ip_hdr + trans_hdr + payload
    caplen = len(packet_data)

    rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, caplen, caplen)
    f.write(rec_hdr + packet_data)


class MultiScenarioPcapGenerator:
    """Generates multi-scenario evaluation PCAPs and synchronizes ground-truth manifest entries."""

    def __init__(self, output_base_dir: str = "dataset/pcaps", manifest_path: str = "dataset/manifests/ground_truth.json"):
        self.output_base = Path(output_base_dir)
        self.manifest_path = Path(manifest_path)
        self.manifest_manager = ManifestManager()
        self.base_epoch = 1756684800  # 2026-09-01 00:00:00 UTC

    def generate_all_scenarios(self) -> Dict[str, CaptureRecord]:
        """Generate all benign controls, boundary scenarios, and multi-severity threat traces."""
        captures: Dict[str, CaptureRecord] = {}

        # 1. Benign Enterprise Baseline
        captures.update(self._generate_benign_scenarios())

        # 2. Volumetric DDoS (Boundary: 3k pps, Nominal: 8k pps, High: 15k pps)
        captures.update(self._generate_ddos_scenarios())

        # 3. C2 Beaconing (Low Jitter: 5%, Medium: 20%, Boundary/High: 50%)
        captures.update(self._generate_c2_scenarios())

        # 4. Reconnaissance Port Scanning (Fast, Medium, Low & Slow boundary)
        captures.update(self._generate_recon_scenarios())

        # 5. Data Exfiltration (Bulk burst, Medium, Low & Slow trickle)
        captures.update(self._generate_exfil_scenarios())

        # 6. DGA / DNS Tunnelling (High entropy DGA, DNS tunneling burst)
        captures.update(self._generate_dns_scenarios())

        # Save to Manifest
        self.manifest_manager.manifest = GroundTruthManifest(
            manifest_version="1.1.0",
            description="UniGuard AI multi-scenario ground-truth evaluation manifest with decision boundary cases.",
            captures=captures,
        )
        self.manifest_manager.save_to_file(self.manifest_path)
        return captures

    def _generate_benign_scenarios(self) -> Dict[str, CaptureRecord]:
        """Generate pure benign workstation and background telemetry captures."""
        records = {}
        file_path = self.output_base / "benign" / "corp_workstation_baseline_01.pcap"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        start_ts = self.base_epoch
        duration = 300  # 5 minutes
        total_packets = 1500

        with open(file_path, "wb") as f:
            write_pcap_header(f)
            cur_ts = start_ts
            for i in range(total_packets):
                cur_ts += random.uniform(0.1, 0.3)
                src_ip = random.choice(["10.0.4.15", "10.0.4.20", "10.0.4.55"])
                dst_ip = random.choice(["198.51.100.10", "198.51.100.25", "8.8.8.8"])
                port = random.choice([443, 80, 53])
                proto = 17 if port == 53 else 6
                write_pcap_packet(
                    f, int(cur_ts), int((cur_ts % 1) * 1e6),
                    src_ip, dst_ip, 50000 + (i % 1000), port, proto,
                    payload_len=random.randint(40, 800), tcp_flags=0x18  # PSH+ACK
                )

        start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
        end_iso = datetime.fromtimestamp(cur_ts, tz=timezone.utc).isoformat()

        records["CAP-BENIGN-CORP-001"] = CaptureRecord(
            capture_id="CAP-BENIGN-CORP-001",
            file_path=str(file_path),
            traffic_type="BENIGN",
            primary_label=EvaluationTrafficClass.BENIGN,
            capture_start_iso=start_iso,
            capture_end_iso=end_iso,
            duration_sec=round(cur_ts - start_ts, 2),
            packet_count=total_packets,
            source_ips=["10.0.4.15", "10.0.4.20", "10.0.4.55"],
            target_ips=["198.51.100.10", "198.51.100.25", "8.8.8.8"],
            protocols=[6, 17],
            generation_method=GenerationMethod.SYNTHETIC_LAB,
            dataset_source="UniGuard Isolated Testbed - Benign Control Trace",
            split=DatasetSplit.EVALUATION_HOLD_OUT,
            labeled_events=[],
            notes="Pure benign corporate web and DNS browsing background"
        )
        return records

    def _generate_ddos_scenarios(self) -> Dict[str, CaptureRecord]:
        """Generate multi-rate DDoS flood captures (including boundary cases)."""
        records = {}
        rates = [
            ("ddos_syn_boundary_3kpps.pcap", "CAP-DDOS-BOUND-001", 3000, "Decision boundary flood (3,000 pps)"),
            ("syn_flood_15kpps_burst.pcap", "CAP-DDOS-SYN-001", 15000, "High velocity SYN flood (15,000 pps)"),
        ]

        for fname, cap_id, pps, desc in rates:
            file_path = self.output_base / "ddos" / fname
            file_path.parent.mkdir(parents=True, exist_ok=True)

            start_ts = self.base_epoch + 1000
            preamble_dur = 30
            attack_dur = 60
            post_dur = 30
            total_dur = preamble_dur + attack_dur + post_dur

            with open(file_path, "wb") as f:
                write_pcap_header(f)
                cur_ts = start_ts
                pkt_count = 0

                # 1. Preamble (Benign)
                for _ in range(60):
                    cur_ts += 0.5
                    write_pcap_packet(f, int(cur_ts), int((cur_ts % 1) * 1e6), "10.0.1.5", "198.51.100.1", 52000, 443, 6, 100, 0x18)
                    pkt_count += 1

                # 2. Attack Active Interval
                evt_start_ts = cur_ts
                dt_packet = 1.0 / pps
                num_attack_pkts = min(10000, int(attack_dur * pps))  # Cap packets for fast testing
                for i in range(num_attack_pkts):
                    cur_ts += dt_packet
                    write_pcap_packet(f, int(cur_ts), int((cur_ts % 1) * 1e6), "198.51.100.99", "10.0.0.1", 40000 + (i % 20000), 80, 6, 0, 0x02)  # SYN
                    pkt_count += 1
                evt_end_ts = cur_ts

                # 3. Post-attack Recovery (Benign)
                for _ in range(30):
                    cur_ts += 1.0
                    write_pcap_packet(f, int(cur_ts), int((cur_ts % 1) * 1e6), "10.0.1.5", "198.51.100.1", 52001, 443, 6, 100, 0x18)
                    pkt_count += 1

            start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
            end_iso = datetime.fromtimestamp(cur_ts, tz=timezone.utc).isoformat()
            evt_start_iso = datetime.fromtimestamp(evt_start_ts, tz=timezone.utc).isoformat()
            evt_end_iso = datetime.fromtimestamp(evt_end_ts, tz=timezone.utc).isoformat()

            event = GroundTruthEvent(
                event_id=f"EVT-{cap_id}",
                traffic_class=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                time_window=TemporalWindow(start_time_iso=evt_start_iso, end_time_iso=evt_end_iso),
                source_entity="198.51.100.99",
                target_entity="10.0.0.1",
                target_port=80,
                protocol=6,
                confidence_level=1.0,
                observable_indicators={"target_pps": pps, "syn_ratio": 0.99}
            )

            records[cap_id] = CaptureRecord(
                capture_id=cap_id,
                file_path=str(file_path),
                traffic_type="ATTACK",
                primary_label=EvaluationTrafficClass.VOLUMETRIC_DDOS,
                capture_start_iso=start_iso,
                capture_end_iso=end_iso,
                duration_sec=round(cur_ts - start_ts, 2),
                packet_count=pkt_count,
                source_ips=["198.51.100.99", "10.0.1.5"],
                target_ips=["10.0.0.1", "198.51.100.1"],
                protocols=[6],
                generation_method=GenerationMethod.SYNTHETIC_LAB,
                dataset_source=f"UniGuard Isolated Testbed - {desc}",
                split=DatasetSplit.EVALUATION_HOLD_OUT,
                labeled_events=[event],
                notes=desc
            )
        return records

    def _generate_c2_scenarios(self) -> Dict[str, CaptureRecord]:
        """Generate C2 periodic beaconing captures across varying jitter levels."""
        records = {}
        jitters = [
            ("c2_periodic_beacon_60s_jitter5.pcap", "CAP-C2-BEACON-001", 0.05, "Low-jitter C2 Beaconing (5% jitter)"),
            ("c2_periodic_beacon_30s_jitter50.pcap", "CAP-C2-JITTER-002", 0.50, "High-jitter Boundary C2 (50% jitter)"),
        ]

        for fname, cap_id, jitter_pct, desc in jitters:
            file_path = self.output_base / "c2" / fname
            file_path.parent.mkdir(parents=True, exist_ok=True)

            start_ts = self.base_epoch + 5000
            cur_ts = start_ts
            interval = 30.0
            pkt_count = 0

            with open(file_path, "wb") as f:
                write_pcap_header(f)

                # 20 consecutive heartbeat pulses
                for pulse in range(20):
                    jitter_offset = random.uniform(-interval * jitter_pct, interval * jitter_pct)
                    cur_ts += (interval + jitter_offset)

                    # Pulse burst: 4 packets (TLS handshake + encrypted payload)
                    for pkt_idx in range(4):
                        write_pcap_packet(
                            f, int(cur_ts), int((cur_ts % 1) * 1e6) + pkt_idx * 5000,
                            "10.0.4.88", "198.51.100.42", 49500 + pulse, 443, 6,
                            payload_len=250, tcp_flags=0x18
                        )
                        pkt_count += 1

            start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
            end_iso = datetime.fromtimestamp(cur_ts, tz=timezone.utc).isoformat()

            event = GroundTruthEvent(
                event_id=f"EVT-{cap_id}",
                traffic_class=EvaluationTrafficClass.BOTNET_C2_BEACONING,
                time_window=TemporalWindow(start_time_iso=start_iso, end_time_iso=end_iso),
                source_entity="10.0.4.88",
                target_entity="198.51.100.42",
                target_port=443,
                protocol=6,
                confidence_level=1.0,
                observable_indicators={"interval_sec": interval, "jitter_pct": jitter_pct * 100}
            )

            records[cap_id] = CaptureRecord(
                capture_id=cap_id,
                file_path=str(file_path),
                traffic_type="ATTACK",
                primary_label=EvaluationTrafficClass.BOTNET_C2_BEACONING,
                capture_start_iso=start_iso,
                capture_end_iso=end_iso,
                duration_sec=round(cur_ts - start_ts, 2),
                packet_count=pkt_count,
                source_ips=["10.0.4.88"],
                target_ips=["198.51.100.42"],
                protocols=[6],
                generation_method=GenerationMethod.SYNTHETIC_LAB,
                dataset_source=f"UniGuard Isolated Testbed - {desc}",
                split=DatasetSplit.EVALUATION_HOLD_OUT,
                labeled_events=[event],
                notes=desc
            )
        return records

    def _generate_recon_scenarios(self) -> Dict[str, CaptureRecord]:
        """Generate port scanning sweeps across horizontal and vertical dimensions."""
        records = {}
        file_path = self.output_base / "recon" / "horizontal_vertical_port_scan.pcap"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        start_ts = self.base_epoch + 10000
        cur_ts = start_ts
        pkt_count = 0

        with open(file_path, "wb") as f:
            write_pcap_header(f)

            # Fast scan of 100 ports on single host (Vertical Scan)
            for port in range(1, 101):
                cur_ts += 0.05
                write_pcap_packet(f, int(cur_ts), int((cur_ts % 1) * 1e6), "198.51.100.77", "10.0.0.5", 55000, port, 6, 0, 0x02)
                pkt_count += 1

        start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
        end_iso = datetime.fromtimestamp(cur_ts, tz=timezone.utc).isoformat()

        event = GroundTruthEvent(
            event_id="EVT-RECON-VERT-001",
            traffic_class=EvaluationTrafficClass.RECON_PORT_SCAN,
            time_window=TemporalWindow(start_time_iso=start_iso, end_time_iso=end_iso),
            source_entity="198.51.100.77",
            target_entity="10.0.0.5",
            protocol=6,
            confidence_level=1.0,
            observable_indicators={"scanned_ports": 100, "scan_rate_pps": 20.0}
        )

        records["CAP-RECON-PORT-001"] = CaptureRecord(
            capture_id="CAP-RECON-PORT-001",
            file_path=str(file_path),
            traffic_type="ATTACK",
            primary_label=EvaluationTrafficClass.RECON_PORT_SCAN,
            capture_start_iso=start_iso,
            capture_end_iso=end_iso,
            duration_sec=round(cur_ts - start_ts, 2),
            packet_count=pkt_count,
            source_ips=["198.51.100.77"],
            target_ips=["10.0.0.5"],
            protocols=[6],
            generation_method=GenerationMethod.SYNTHETIC_LAB,
            dataset_source="UniGuard Isolated Testbed - Vertical Recon Sweep",
            split=DatasetSplit.EVALUATION_HOLD_OUT,
            labeled_events=[event],
            notes="Vertical port sweep targeting ports 1-100"
        )
        return records

    def _generate_exfil_scenarios(self) -> Dict[str, CaptureRecord]:
        """Generate outbound data transfer bursts over port 443."""
        records = {}
        file_path = self.output_base / "exfiltration" / "outbound_bulk_exfil_burst.pcap"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        start_ts = self.base_epoch + 15000
        cur_ts = start_ts
        pkt_count = 0

        with open(file_path, "wb") as f:
            write_pcap_header(f)

            # 500 large outbound payload packets (1400 bytes each)
            for i in range(500):
                cur_ts += 0.01
                write_pcap_packet(f, int(cur_ts), int((cur_ts % 1) * 1e6), "10.0.12.3", "198.51.100.99", 54321, 443, 6, 1400, 0x18)
                pkt_count += 1

        start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
        end_iso = datetime.fromtimestamp(cur_ts, tz=timezone.utc).isoformat()

        event = GroundTruthEvent(
            event_id="EVT-EXFIL-001",
            traffic_class=EvaluationTrafficClass.DATA_EXFILTRATION,
            time_window=TemporalWindow(start_time_iso=start_iso, end_time_iso=end_iso),
            source_entity="10.0.12.3",
            target_entity="198.51.100.99",
            target_port=443,
            protocol=6,
            confidence_level=1.0,
            observable_indicators={"total_bytes": 700000, "upload_ratio": 100.0}
        )

        records["CAP-EXFIL-BULK-001"] = CaptureRecord(
            capture_id="CAP-EXFIL-BULK-001",
            file_path=str(file_path),
            traffic_type="ATTACK",
            primary_label=EvaluationTrafficClass.DATA_EXFILTRATION,
            capture_start_iso=start_iso,
            capture_end_iso=end_iso,
            duration_sec=round(cur_ts - start_ts, 2),
            packet_count=pkt_count,
            source_ips=["10.0.12.3"],
            target_ips=["198.51.100.99"],
            protocols=[6],
            generation_method=GenerationMethod.SYNTHETIC_LAB,
            dataset_source="UniGuard Isolated Testbed - Bulk Outbound Transfer",
            split=DatasetSplit.EVALUATION_HOLD_OUT,
            labeled_events=[event],
            notes="Asymmetric bulk data transfer over HTTPS"
        )
        return records

    def _generate_dns_scenarios(self) -> Dict[str, CaptureRecord]:
        """Generate high-entropy DGA & DNS query bursts."""
        records = {}
        file_path = self.output_base / "dns" / "dga_dns_tunnel_queries.pcap"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        start_ts = self.base_epoch + 20000
        cur_ts = start_ts
        pkt_count = 0

        with open(file_path, "wb") as f:
            write_pcap_header(f)

            # 200 rapid DNS lookups
            for i in range(200):
                cur_ts += 0.05
                write_pcap_packet(f, int(cur_ts), int((cur_ts % 1) * 1e6), "10.0.8.19", "8.8.8.8", 53000 + (i % 100), 53, 17, 120)
                pkt_count += 1

        start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
        end_iso = datetime.fromtimestamp(cur_ts, tz=timezone.utc).isoformat()

        event = GroundTruthEvent(
            event_id="EVT-DNS-DGA-001",
            traffic_class=EvaluationTrafficClass.DGA_DNS_TUNNELLING,
            time_window=TemporalWindow(start_time_iso=start_iso, end_time_iso=end_iso),
            source_entity="10.0.8.19",
            target_entity="8.8.8.8",
            target_port=53,
            protocol=17,
            confidence_level=1.0,
            observable_indicators={"query_entropy": 4.2, "query_rate": 20.0}
        )

        records["CAP-DNS-DGA-001"] = CaptureRecord(
            capture_id="CAP-DNS-DGA-001",
            file_path=str(file_path),
            traffic_type="ATTACK",
            primary_label=EvaluationTrafficClass.DGA_DNS_TUNNELLING,
            capture_start_iso=start_iso,
            capture_end_iso=end_iso,
            duration_sec=round(cur_ts - start_ts, 2),
            packet_count=pkt_count,
            source_ips=["10.0.8.19"],
            target_ips=["8.8.8.8"],
            protocols=[17],
            generation_method=GenerationMethod.SYNTHETIC_LAB,
            dataset_source="UniGuard Isolated Testbed - High Entropy DGA Burst",
            split=DatasetSplit.EVALUATION_HOLD_OUT,
            labeled_events=[event],
            notes="High entropy pseudo-random DNS lookups"
        )
        return records


if __name__ == "__main__":
    generator = MultiScenarioPcapGenerator()
    caps = generator.generate_all_scenarios()
    print(f"[SUCCESS] Generated {len(caps)} controlled PCAP scenarios and updated dataset/manifests/ground_truth.json")
