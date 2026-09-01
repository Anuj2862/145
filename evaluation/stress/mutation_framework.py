"""Scenario Mutation Framework for Robustness & Evasion Stress Testing (M20).

Provides deterministic, parameterized mutation over canonical packet traces and event streams:
- Timing & Jitter scaling
- Rate variation
- Destination & Port rotation/dispersion
- Packet size perturbation
- TLS & DNS metadata drift
- Observation loss (packet drop)
- Out-of-order packet reordering

Every mutated scenario generates strict cryptographic provenance and never fabricates ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import random
from typing import Any, Dict, Iterator, List, Optional, Tuple

from schemas import (
    FlowEvent,
    ThreatClass,
)
from ingest.pcap_reader import NormalizedPacket
import numpy as np


@dataclass
class MutationParameters:
    """Configuration parameters for scenario perturbation."""
    timing_scale: float = 1.0
    jitter_pct: float = 0.0
    rate_scale: float = 1.0
    destination_rotation: bool = False
    new_destinations_count: int = 0
    port_dispersion: bool = False
    packet_size_jitter_pct: float = 0.0
    tls_fingerprint_drift: bool = False
    mutated_ja3: Optional[str] = None
    mutated_ja4: Optional[str] = None
    mutated_alpn: Optional[str] = None
    dns_characteristic_drift: bool = False
    packet_loss_rate: float = 0.0
    reordering_rate: float = 0.0
    reordering_delay_sec: float = 0.5
    random_seed: int = 42

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timing_scale": self.timing_scale,
            "jitter_pct": self.jitter_pct,
            "rate_scale": self.rate_scale,
            "destination_rotation": self.destination_rotation,
            "new_destinations_count": self.new_destinations_count,
            "port_dispersion": self.port_dispersion,
            "packet_size_jitter_pct": self.packet_size_jitter_pct,
            "tls_fingerprint_drift": self.tls_fingerprint_drift,
            "mutated_ja3": self.mutated_ja3,
            "mutated_ja4": self.mutated_ja4,
            "mutated_alpn": self.mutated_alpn,
            "dns_characteristic_drift": self.dns_characteristic_drift,
            "packet_loss_rate": self.packet_loss_rate,
            "reordering_rate": self.reordering_rate,
            "reordering_delay_sec": self.reordering_delay_sec,
            "random_seed": self.random_seed,
        }


@dataclass
class MutatedScenario:
    """Standardized metadata and container for a mutated scenario."""
    scenario_id: str
    parent_scenario_id: str
    mutation_params: MutationParameters
    expected_threat: Optional[ThreatClass]
    ground_truth_start_time: float
    ground_truth_end_time: float
    original_packet_count: int
    mutated_packet_count: int
    provenance_hash: str
    iat_statistics: Dict[str, Any] = field(default_factory=dict)
    packets: List[NormalizedPacket] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "parent_scenario_id": self.parent_scenario_id,
            "mutation_params": self.mutation_params.to_dict(),
            "expected_threat": self.expected_threat.value if self.expected_threat else "BENIGN",
            "ground_truth_start_time": self.ground_truth_start_time,
            "ground_truth_end_time": self.ground_truth_end_time,
            "original_packet_count": self.original_packet_count,
            "mutated_packet_count": self.mutated_packet_count,
            "provenance_hash": self.provenance_hash,
            "iat_statistics": self.iat_statistics,
        }


class ScenarioMutator:
    """Deterministic mutator for network packet traces."""

    @staticmethod
    def mutate_packets(
        packets: List[NormalizedPacket],
        params: MutationParameters,
        parent_scenario_id: str,
        expected_threat: Optional[ThreatClass],
    ) -> MutatedScenario:
        """Apply deterministic mutations to packet trace according to specified parameters."""
        if not packets:
            raise ValueError("Cannot mutate an empty packet list")

        rng = random.Random(params.random_seed)
        orig_count = len(packets)
        mutated_list: List[NormalizedPacket] = []

        # 1. Packet Loss Simulation (Observation Loss)
        for pkt in packets:
            if params.packet_loss_rate > 0.0 and rng.random() < params.packet_loss_rate:
                continue  # Drop packet
            mutated_list.append(pkt)

        if not mutated_list:
            # Prevent complete empty trace if 100% loss was not intended
            mutated_list = [packets[0]]

        # 2. Timing, Jitter, Rate & Attribute Mutations
        t_base = mutated_list[0].timestamp
        t_curr = t_base

        # Destination pool for destination rotation
        rotated_dst_pool = [
            f"198.51.100.{10 + i}" for i in range(max(1, params.new_destinations_count))
        ]

        result_packets: List[NormalizedPacket] = []
        for i, pkt in enumerate(mutated_list):
            # Compute IAT delta from previous packet
            if i == 0:
                dt = 0.0
            else:
                orig_dt = max(0.0, pkt.timestamp - mutated_list[i - 1].timestamp)
                # Scale timing and rate
                dt = orig_dt * params.timing_scale / max(1e-6, params.rate_scale)
                # Apply jitter (normal distribution centered at 1.0)
                if params.jitter_pct > 0.0:
                    jitter_factor = max(0.01, rng.gauss(1.0, params.jitter_pct / 100.0))
                    dt *= jitter_factor

            t_curr += dt

            # Packet Size Perturbation
            length = pkt.packet_length
            if params.packet_size_jitter_pct > 0.0:
                length_delta = int(length * rng.uniform(-params.packet_size_jitter_pct / 100.0, params.packet_size_jitter_pct / 100.0))
                length = max(40, length + length_delta)

            # Destination & Port Mutations
            dst_ip = pkt.dst_ip
            if params.destination_rotation and rotated_dst_pool:
                dst_ip = rotated_dst_pool[i % len(rotated_dst_pool)]

            dst_port = pkt.dst_port
            if params.port_dispersion:
                dst_port = 1024 + (i * 37) % 64000

            # TLS Fingerprint Drift
            tls_meta = pkt.tls
            if tls_meta is not None and isinstance(tls_meta, dict):
                tls_meta = dict(tls_meta)
                if params.tls_fingerprint_drift:
                    if params.mutated_ja3:
                        tls_meta["ja3"] = params.mutated_ja3
                        tls_meta["ja3_hash"] = params.mutated_ja3
                    if params.mutated_ja4:
                        tls_meta["ja4"] = params.mutated_ja4
                        tls_meta["ja4_hash"] = params.mutated_ja4
                    if params.mutated_alpn:
                        tls_meta["alpn"] = params.mutated_alpn

            # DNS Characteristic Drift
            dns_meta = pkt.dns
            if dns_meta is not None and isinstance(dns_meta, dict):
                dns_meta = dict(dns_meta)
                if params.dns_characteristic_drift:
                    dns_meta["query_count"] = dns_meta.get("query_count", 1) * 2
                    if "query" in dns_meta:
                        dns_meta["query"] = f"mutated-{rng.randint(100,999)}.{dns_meta['query']}"

            mut_pkt = NormalizedPacket(
                timestamp=t_curr,
                src_ip=pkt.src_ip,
                dst_ip=dst_ip,
                src_port=pkt.src_port,
                dst_port=dst_port,
                protocol=pkt.protocol,
                packet_length=length,
                tcp_syn=pkt.tcp_syn,
                tcp_ack=pkt.tcp_ack,
                tcp_fin=pkt.tcp_fin,
                tcp_rst=pkt.tcp_rst,
                tcp_psh=pkt.tcp_psh,
                tcp_urg=pkt.tcp_urg,
                sensor_id=pkt.sensor_id,
                dns=dns_meta,
                tls=tls_meta,
                quic=pkt.quic,
            )
            result_packets.append(mut_pkt)

        # 3. Out-of-Order Reordering Simulation
        if params.reordering_rate > 0.0 and len(result_packets) > 3:
            for idx in range(1, len(result_packets) - 1):
                if rng.random() < params.reordering_rate:
                    p_orig = result_packets[idx]
                    next_t = result_packets[idx + 1].timestamp
                    result_packets[idx] = NormalizedPacket(
                        timestamp=next_t + params.reordering_delay_sec,
                        src_ip=p_orig.src_ip,
                        dst_ip=p_orig.dst_ip,
                        src_port=p_orig.src_port,
                        dst_port=p_orig.dst_port,
                        protocol=p_orig.protocol,
                        packet_length=p_orig.packet_length,
                        tcp_syn=p_orig.tcp_syn,
                        tcp_ack=p_orig.tcp_ack,
                        tcp_fin=p_orig.tcp_fin,
                        tcp_rst=p_orig.tcp_rst,
                        tcp_psh=p_orig.tcp_psh,
                        tcp_urg=p_orig.tcp_urg,
                        sensor_id=p_orig.sensor_id,
                        dns=p_orig.dns,
                        tls=p_orig.tls,
                        quic=p_orig.quic,
                    )

        # Sort or preserve arrival stream as physically received
        # (Out-of-order events arrive in perturbed arrival order)
        gt_start = result_packets[0].timestamp
        gt_end = max(p.timestamp for p in result_packets)

        # Compute deterministic scenario provenance hash
        h = hashlib.sha256()
        h.update(f"{parent_scenario_id}-{params.to_dict()}".encode("utf-8"))
        for p in result_packets[:50]:
            h.update(f"{p.timestamp}:{p.src_ip}->{p.dst_ip}:{p.packet_length}".encode("utf-8"))
        scenario_hash = h.hexdigest()
        scenario_id = f"mut-{parent_scenario_id}-{scenario_hash[:10]}"

        # Compute IAT statistics
        orig_iats = [packets[j].timestamp - packets[j-1].timestamp for j in range(1, len(packets))] if len(packets) > 1 else [0.0]
        mut_iats = [result_packets[j].timestamp - result_packets[j-1].timestamp for j in range(1, len(result_packets))] if len(result_packets) > 1 else [0.0]
        iat_stats = {
            "original_iat_mean_ms": round(float(np.mean(orig_iats) * 1000.0), 3),
            "original_iat_std_ms": round(float(np.std(orig_iats) * 1000.0), 3),
            "mutated_iat_mean_ms": round(float(np.mean(mut_iats) * 1000.0), 3),
            "mutated_iat_std_ms": round(float(np.std(mut_iats) * 1000.0), 3),
            "target_jitter_pct": params.jitter_pct,
        }

        return MutatedScenario(
            scenario_id=scenario_id,
            parent_scenario_id=parent_scenario_id,
            mutation_params=params,
            expected_threat=expected_threat,
            ground_truth_start_time=gt_start,
            ground_truth_end_time=gt_end,
            original_packet_count=orig_count,
            mutated_packet_count=len(result_packets),
            provenance_hash=scenario_hash,
            iat_statistics=iat_stats,
            packets=result_packets,
        )
