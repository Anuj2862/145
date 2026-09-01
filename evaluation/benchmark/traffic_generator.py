"""Deterministic Multi-Class Traffic Stream & Backpressure Queue (Milestones 21 & 21.5).

Implements:
1. SyntheticTrafficGenerator: Deterministic packet generation across benign + 6 threat families with label tracking.
2. BoundedPipelineQueue: Thread-safe, capacity-bounded queue with overflow drop accounting and queue-wait latency tracking.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import random
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from schemas import ThreatClass
from schemas.telemetry import DNSMetadata, TLSMetadata
from ingest.pcap_reader import NormalizedPacket


@dataclass
class TrafficStreamConfig:
    """Configuration for synthetic/mixed benchmark traffic stream."""
    duration_sec: float = 10.0
    target_pps: float = 1000.0
    packet_size_mean: int = 512
    packet_size_std: int = 128
    flow_duration_mean_sec: float = 5.0
    entity_cardinality: int = 100
    destination_cardinality: int = 50
    port_cardinality: int = 100
    random_seed: int = 42
    traffic_mix: Dict[str, float] = field(default_factory=lambda: {
        "benign": 0.70,
        "ddos": 0.05,
        "c2": 0.05,
        "dns": 0.05,
        "encrypted": 0.05,
        "recon": 0.05,
        "exfil": 0.05,
    })


class SyntheticTrafficGenerator:
    """Generates deterministic, rate-controlled packet streams with heterogeneous threat profiles."""

    def __init__(self, config: TrafficStreamConfig):
        self.config = config
        self.rng = random.Random(config.random_seed)
        self.entities = [f"192.168.1.{10 + (i % 240)}" for i in range(config.entity_cardinality)]
        self.destinations = [f"203.0.113.{5 + (i % 240)}" for i in range(config.destination_cardinality)]

    def generate_packets_with_labels(self, total_packets: Optional[int] = None) -> Tuple[List[NormalizedPacket], List[str]]:
        """Generate deterministic batch of normalized packets along with ground truth labels."""
        n_pkts = total_packets or int(self.config.duration_sec * self.config.target_pps)
        if n_pkts <= 0:
            n_pkts = 100

        t_start = 1756680000.0
        dt_avg = 1.0 / max(1.0, self.config.target_pps)
        packets: List[NormalizedPacket] = []
        labels: List[str] = []

        t_curr = t_start
        mix_keys = list(self.config.traffic_mix.keys())
        mix_weights = list(self.config.traffic_mix.values())

        for i in range(n_pkts):
            dt = max(1e-6, self.rng.expovariate(1.0 / dt_avg))
            t_curr += dt

            # Select traffic class
            t_type = self.rng.choices(mix_keys, weights=mix_weights, k=1)[0]
            src_ip = self.rng.choice(self.entities)
            dst_ip = self.rng.choice(self.destinations)
            src_port = self.rng.randint(1024, 65535)
            dst_port = 443 if t_type in ("encrypted", "c2") else (53 if t_type == "dns" else 80)
            proto = 17 if t_type == "dns" else 6
            length = max(40, int(self.rng.gauss(self.config.packet_size_mean, self.config.packet_size_std)))

            syn = 1 if (i % 10 == 0 or t_type in ("recon", "ddos")) else 0
            ack = 1 if not syn else 0
            fin = 1 if (i % 30 == 0) else 0
            rst = 1 if (t_type == "recon" and i % 5 == 0) else 0

            dns_meta = None
            if t_type == "dns":
                domain = f"sub-{self.rng.randint(100, 999)}.tunnel-{src_ip.replace('.', '-')}.example.org"
                dns_meta = DNSMetadata(
                    query_name=domain,
                    query_type="TXT" if self.rng.random() < 0.4 else "A",
                    response_code="NOERROR",
                    answer_count=1,
                )

            tls_meta = None
            if t_type in ("encrypted", "c2"):
                tls_meta = TLSMetadata(
                    tls_version="TLSv1.3",
                    sni=f"api-{self.rng.randint(1, 10)}.service.internal",
                    ja3_hash="771,4865-4866,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
                    ja4_hash="t13d1516h2_8daaf6152771_b74621d9b3a0",
                    alpn="h2",
                )

            pkt = NormalizedPacket(
                timestamp=t_curr,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                packet_length=length,
                tcp_syn=syn,
                tcp_ack=ack,
                tcp_fin=fin,
                tcp_rst=rst,
                tcp_psh=1 if length > 1000 else 0,
                tcp_urg=0,
                sensor_id="benchmark-sensor-01",
                dns=dns_meta,
                tls=tls_meta,
                quic=None,
            )
            packets.append(pkt)
            
            # Canonical threat label
            if t_type == "benign":
                labels.append("BENIGN")
            elif t_type == "ddos":
                labels.append("VOLUMETRIC_DDOS")
            elif t_type == "c2":
                labels.append("BOTNET_C2_BEACONING")
            elif t_type == "dns":
                labels.append("DGA_DNS_TUNNELLING")
            elif t_type == "encrypted":
                labels.append("ENCRYPTED_MALWARE")
            elif t_type == "recon":
                labels.append("RECON_PORT_SCAN")
            elif t_type == "exfil":
                labels.append("DATA_EXFILTRATION")
            else:
                labels.append("BENIGN")

        return packets, labels

    def generate_packets(self, total_packets: Optional[int] = None) -> List[NormalizedPacket]:
        """Generate a complete deterministic batch of normalized packets."""
        packets, _ = self.generate_packets_with_labels(total_packets=total_packets)
        return packets


@dataclass
class QueueItem:
    """Envelope wrapping a packet with enqueue timing for latency tracking."""
    packet: NormalizedPacket
    enqueue_time: float


class BoundedPipelineQueue:
    """Bounded, thread-safe queue enforcing memory ceilings and tracking backpressure."""

    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self._queue: deque[QueueItem] = deque()
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)

        # Telemetry metrics
        self.total_enqueued = 0
        self.total_dequeued = 0
        self.overflow_drops = 0
        self.max_depth_observed = 0
        self._wait_latencies_ms: List[float] = []

    def enqueue(self, packet: NormalizedPacket, wall_time: Optional[float] = None) -> bool:
        """Enqueue packet if within capacity; drop and increment counter on overflow."""
        t_enq = wall_time if wall_time is not None else time.perf_counter()
        with self._lock:
            if len(self._queue) >= self.capacity:
                self.overflow_drops += 1
                return False

            self._queue.append(QueueItem(packet=packet, enqueue_time=t_enq))
            self.total_enqueued += 1
            curr_len = len(self._queue)
            if curr_len > self.max_depth_observed:
                self.max_depth_observed = curr_len
            self._not_empty.notify()
            return True

    def dequeue(self, timeout: Optional[float] = None) -> Optional[Tuple[NormalizedPacket, float]]:
        """Dequeue packet and compute queue wait latency (ms)."""
        t_deq = time.perf_counter()
        with self._lock:
            if not self._queue:
                if timeout is not None:
                    self._not_empty.wait(timeout=timeout)
                if not self._queue:
                    return None

            item = self._queue.popleft()
            self.total_dequeued += 1
            wait_ms = max(0.0, (t_deq - item.enqueue_time) * 1000.0)
            if len(self._wait_latencies_ms) < 100000:
                self._wait_latencies_ms.append(wait_ms)
            return item.packet, wait_ms

    def get_stats(self) -> Dict[str, Any]:
        """Produce statistical summary of queue performance and backpressure."""
        with self._lock:
            waits = list(self._wait_latencies_ms)
            enq = self.total_enqueued
            deq = self.total_dequeued
            drops = self.overflow_drops
            max_d = self.max_depth_observed

        total_received = enq + drops
        drop_pct = (drops / max(1, total_received)) * 100.0

        if not waits:
            return {
                "capacity": self.capacity,
                "current_depth": len(self._queue),
                "total_received": total_received,
                "total_enqueued": enq,
                "total_processed": deq,
                "overflow_drops": drops,
                "drop_rate_pct": round(drop_pct, 4),
                "max_depth_observed": max_d,
                "queue_wait_p50_ms": 0.0,
                "queue_wait_p95_ms": 0.0,
                "queue_wait_p99_ms": 0.0,
            }

        waits_sorted = sorted(waits)
        n = len(waits_sorted)
        p50 = waits_sorted[int(n * 0.50)]
        p95 = waits_sorted[min(n - 1, int(n * 0.95))]
        p99 = waits_sorted[min(n - 1, int(n * 0.99))]

        return {
            "capacity": self.capacity,
            "current_depth": len(self._queue),
            "total_received": total_received,
            "total_enqueued": enq,
            "total_processed": deq,
            "overflow_drops": drops,
            "drop_rate_pct": round(drop_pct, 4),
            "max_depth_observed": max_d,
            "queue_wait_p50_ms": round(p50, 3),
            "queue_wait_p95_ms": round(p95, 3),
            "queue_wait_p99_ms": round(p99, 3),
        }
