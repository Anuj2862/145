"""Entity Behaviour State, Baselines and Novelty (Member 3 / M14).

Maintains bounded rolling statistical baselines, multi-window aggregations,
and novelty tracking per network entity (Host IP / Entity Identity) across
deterministic event time.

Key Capabilities:
- Event-time ordered state and multi-window aggregations (1s, 5s, 15s, 30s, 60s, 300s).
- Robust statistical baselines: EWMA volume, moving variance, and median/MAD robust z-scores.
- Baseline Contamination Protection: Warm-up phase, trusted-benign updates, suspicious
  observation freeze, and high-confidence attack freeze.
- Explicit Novelty Features: Destination, port, domain, and TLS/QUIC fingerprint novelty,
  frequency, and first-seen age tracking.
- Bounded Memory: Strict LRU capacity and per-entity collection limits with zero silent growth.
- Graph Compatibility: Stable entity and relation descriptors for EntityBehaviourGraph.
"""

from __future__ import annotations

import bisect
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from statistics import median, pstdev
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from schemas import DetectionSignal, EntityEvent, FeatureVector
from schemas.flow_event import FlowEvent
from schemas.telemetry import DNSMetadata, QUICMetadata, TLSMetadata, canonical_entity_id


@dataclass
class BaselineUpdatePolicy:
    """Configurable policy preventing baseline contamination during anomalies."""

    warmup_min_observations: int = 5
    freeze_z_threshold: float = 3.5
    attack_freeze_ratio: float = 10.0
    alpha: float = 0.05
    max_history: int = 60


class MetricBaseline:
    """Robust statistical baseline estimator combining EWMA and Median/MAD."""

    def __init__(self, policy: Optional[BaselineUpdatePolicy] = None):
        self.policy = policy or BaselineUpdatePolicy()
        self.count: int = 0
        self.ewma_mean: float = 0.0
        self.ewma_var: float = 0.0
        self.history: deque[float] = deque(maxlen=self.policy.max_history)
        self.frozen_count: int = 0

    def compute_robust_stats(self) -> Tuple[float, float]:
        """Compute rolling median and robust scale (1.4826 * MAD)."""
        if not self.history:
            return self.ewma_mean, math.sqrt(max(0.0, self.ewma_var))
        if len(self.history) < 2:
            return self.history[0], 0.0

        hist = list(self.history)
        med = float(median(hist))
        abs_devs = [abs(x - med) for x in hist]
        mad = float(median(abs_devs))
        robust_std = 1.4826 * mad
        return med, robust_std

    def compute_z_score(self, current_value: float) -> float:
        """Calculate robust Z-score deviation of current_value from baseline."""
        if self.count == 0 and not self.history:
            return 0.0 if current_value <= 10.0 else (current_value / 10.0)

        med, robust_scale = self.compute_robust_stats()

        if robust_scale > 1e-4:
            return max(0.0, (current_value - med) / robust_scale)

        # Fallback to EWMA standard deviation if MAD is degenerate (e.g. constant values)
        std_val = math.sqrt(max(0.0, self.ewma_var))
        if std_val > 1e-4:
            return max(0.0, (current_value - self.ewma_mean) / std_val)

        if self.ewma_mean > 0:
            return max(0.0, (current_value - self.ewma_mean) / max(self.ewma_mean, 1.0))

        return 0.0 if current_value <= 10.0 else (current_value / 10.0)

    def is_suspicious(self, value: float, is_attack: bool = False) -> bool:
        """Evaluate if an observation should be frozen to protect the baseline."""
        if is_attack:
            return True
        if self.count < self.policy.warmup_min_observations:
            return False

        z_score = self.compute_z_score(value)
        if z_score > self.policy.freeze_z_threshold:
            return True

        if self.ewma_mean > 1.0 and value > (self.policy.attack_freeze_ratio * self.ewma_mean):
            return True

        return False

    def update(self, value: float, is_attack: bool = False, force: bool = False) -> bool:
        """Update baseline with value unless frozen by contamination protection."""
        if not force and self.is_suspicious(value, is_attack=is_attack):
            self.frozen_count += 1
            return False

        if self.count == 0:
            self.ewma_mean = float(value)
            self.ewma_var = 0.0
        else:
            delta = value - self.ewma_mean
            self.ewma_mean += self.policy.alpha * delta
            self.ewma_var = (1.0 - self.policy.alpha) * (self.ewma_var + self.policy.alpha * (delta ** 2))

        self.history.append(float(value))
        self.count += 1
        return True


@dataclass(frozen=True)
class EntityFlowRecord:
    """Immutable record of an individual flow observed for an entity."""

    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    byte_count: int
    packet_count: int
    is_failed: bool
    is_outbound: bool
    dns: Optional[DNSMetadata] = None
    tls: Optional[TLSMetadata] = None
    quic: Optional[QUICMetadata] = None


class EntityProfile:
    """Stateful behavioral profile and rolling multi-window state for a network entity."""

    def __init__(
        self,
        entity_id: str,
        max_history_windows: int = 60,
        max_destinations: int = 2048,
        max_ports: int = 1024,
        max_domains: int = 2048,
        max_fingerprints: int = 512,
        baseline_policy: Optional[BaselineUpdatePolicy] = None,
    ):
        self.entity_id = entity_id
        self.max_history = max_history_windows
        self.max_destinations = max_destinations
        self.max_ports = max_ports
        self.max_domains = max_domains
        self.max_fingerprints = max_fingerprints
        self.policy = baseline_policy or BaselineUpdatePolicy()

        # Timestamps
        self.first_seen: float = 0.0
        self.last_seen: float = 0.0
        self.first_seen_iso: str = datetime.now(timezone.utc).isoformat()
        self.last_seen_iso: str = self.first_seen_iso

        # Cumulative Counters
        self.total_observations: int = 0
        self.flow_count: int = 0
        self.packet_count: int = 0
        self.byte_count: int = 0
        self.outbound_flow_count: int = 0
        self.inbound_flow_count: int = 0
        self.total_outbound_bytes: int = 0
        self.total_inbound_bytes: int = 0
        self.failed_connection_count: int = 0

        # Rolling Flow Records & Timestamps (Bounded)
        self.flow_records: deque[EntityFlowRecord] = deque(maxlen=5000)
        self.flow_timestamps: deque[float] = deque(maxlen=5000)
        self.packet_lengths: deque[int] = deque(maxlen=1000)

        # Legacy lists for backward compatibility
        self.pps_history: deque[float] = deque(maxlen=max_history_windows)
        self.bps_history: deque[float] = deque(maxlen=max_history_windows)

        # Destinations: tracking first_seen, last_seen, count
        self.destination_meta: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.known_destinations: Set[str] = set()

        # Destination Ports
        self.port_meta: OrderedDict[int, dict[str, Any]] = OrderedDict()
        self.known_ports: Set[int] = set()

        # DNS State
        self.domain_meta: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.known_domains: Set[str] = set()
        self.dns_query_count: int = 0
        self.dns_nxdomain_count: int = 0
        self.dns_txt_count: int = 0
        self.dns_query_names: deque[str] = deque(maxlen=500)

        # TLS / QUIC State
        self.known_ja3: Set[str] = set()
        self.known_ja4: Set[str] = set()
        self.fingerprint_meta: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.first_seen_fingerprint: Optional[str] = None
        self.tls_versions: Set[str] = set()
        self.alpn_protocols: Set[str] = set()
        self.session_resumption_count: int = 0

        # Signals & Incidents
        self.active_signal_ids: deque[str] = deque(maxlen=100)

        # Statistical Baselines
        self.pps_baseline = MetricBaseline(self.policy)
        self.bps_baseline = MetricBaseline(self.policy)
        self.outbound_rate_baseline = MetricBaseline(self.policy)
        self.dns_rate_baseline = MetricBaseline(self.policy)
        self.flow_rate_baseline = MetricBaseline(self.policy)

    def _update_timestamps(self, timestamp: float) -> None:
        if self.first_seen == 0.0:
            self.first_seen = timestamp
            self.first_seen_iso = _to_iso(timestamp)
        self.last_seen = max(self.last_seen, timestamp)
        self.last_seen_iso = _to_iso(self.last_seen)

    def update_from_feature_vector(self, fv: FeatureVector, is_attack: bool = False) -> None:
        """Update historical profile from an extracted FeatureVector (backward compatible)."""
        self.last_seen_iso = fv.timestamp_iso
        self.total_observations += 1

        ts = _parse_iso(fv.timestamp_iso)
        self._update_timestamps(ts)

        if fv.flow_features:
            pps = fv.flow_features.packets_per_sec or 0.0
            bps = fv.flow_features.bytes_per_sec or 0.0
            self.pps_history.append(pps)
            self.bps_history.append(bps)
            self.pps_baseline.update(pps, is_attack=is_attack)
            self.bps_baseline.update(bps, is_attack=is_attack)

        if fv.tls_features:
            if fv.tls_features.ja3_hash:
                self.record_tls(ja3=fv.tls_features.ja3_hash, event_time=ts)
            if fv.tls_features.ja4_hash:
                self.record_tls(ja4=fv.tls_features.ja4_hash, event_time=ts)
            if fv.tls_features.sni:
                self.record_dns(query_name=fv.tls_features.sni, event_time=ts)

    def update_from_flow(self, event: FlowEvent, is_attack: bool = False) -> None:
        """Ingest a FlowEvent into the entity behavioral state."""
        ts = float(event.event_time if event.event_time is not None else event.timestamp)
        self._update_timestamps(ts)

        self.total_observations += 1
        self.flow_count += 1
        self.packet_count += event.packet_count
        self.byte_count += event.byte_count

        entity_ip = _entity_ip(self.entity_id)
        is_outbound = (event.src_ip == entity_ip or event.entity_id == self.entity_id)
        is_failed = _is_failed_flow(event)

        if is_outbound:
            self.outbound_flow_count += 1
            self.total_outbound_bytes += event.byte_count
            if is_failed:
                self.failed_connection_count += 1
            self.record_destination(event.dst_ip, event.dst_port, event_time=ts)
        else:
            self.inbound_flow_count += 1
            self.total_inbound_bytes += event.byte_count

        # Append packet lengths
        for length in event.packet_lengths:
            self.packet_lengths.append(length)

        # Record Flow
        record = EntityFlowRecord(
            timestamp=ts,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            byte_count=event.byte_count,
            packet_count=event.packet_count,
            is_failed=is_failed,
            is_outbound=is_outbound,
            dns=event.dns,
            tls=event.tls,
            quic=event.quic,
        )
        self.flow_records.append(record)
        if self.flow_timestamps.maxlen is not None and len(self.flow_timestamps) >= self.flow_timestamps.maxlen:
            self.flow_timestamps.popleft()
        bisect.insort(self.flow_timestamps, ts)

        # DNS Metadata
        if event.dns:
            self.record_dns(
                query_name=event.dns.query_name,
                response_code=event.dns.response_code,
                query_type=event.dns.query_type,
                event_time=ts,
            )

        # TLS/QUIC Metadata
        if event.tls:
            self.record_tls(
                ja3=event.tls.ja3_hash,
                ja4=event.tls.ja4_hash,
                sni=event.tls.sni,
                version=event.tls.tls_version,
                alpn=event.tls.alpn,
                event_time=ts,
            )
        elif event.quic:
            self.record_tls(
                sni=event.quic.sni,
                version=event.quic.version,
                alpn=event.quic.alpn,
                event_time=ts,
            )

        # Rate calculations for baseline updates
        pps = event.packet_rate if event.packet_rate > 0 else (event.packet_count / max(0.001, event.duration))
        bps = event.byte_rate if event.byte_rate > 0 else (event.byte_count / max(0.001, event.duration))
        self.pps_history.append(pps)
        self.bps_history.append(bps)

        self.pps_baseline.update(pps, is_attack=is_attack)
        self.bps_baseline.update(bps, is_attack=is_attack)

        if is_outbound:
            self.outbound_rate_baseline.update(bps, is_attack=is_attack)

    def record_destination(self, dst_ip: str, dst_port: Optional[int] = None, event_time: Optional[float] = None) -> bool:
        """Record destination IP and port. Returns True if destination IP is newly observed."""
        ts = event_time or self.last_seen or 0.0
        if ts > 0.0:
            self._update_timestamps(ts)
        is_new_dst = dst_ip not in self.known_destinations

        if is_new_dst:
            if len(self.destination_meta) >= self.max_destinations:
                oldest = next(iter(self.destination_meta))
                del self.destination_meta[oldest]
                self.known_destinations.discard(oldest)

            self.destination_meta[dst_ip] = {
                "first_seen": ts,
                "last_seen": ts,
                "count": 1,
            }
            self.known_destinations.add(dst_ip)
        else:
            meta = self.destination_meta[dst_ip]
            meta["last_seen"] = ts
            meta["count"] += 1
            self.destination_meta.move_to_end(dst_ip)

        if dst_port is not None:
            self.record_port(dst_port, event_time=ts)

        return is_new_dst

    def record_port(self, port: int, event_time: Optional[float] = None) -> bool:
        """Record destination port. Returns True if port is newly observed."""
        ts = event_time or self.last_seen or 0.0
        if ts > 0.0:
            self._update_timestamps(ts)
        is_new_port = port not in self.known_ports

        if is_new_port:
            if len(self.port_meta) >= self.max_ports:
                oldest = next(iter(self.port_meta))
                del self.port_meta[oldest]
                self.known_ports.discard(oldest)

            self.port_meta[port] = {
                "first_seen": ts,
                "last_seen": ts,
                "count": 1,
            }
            self.known_ports.add(port)
        else:
            meta = self.port_meta[port]
            meta["last_seen"] = ts
            meta["count"] += 1
            self.port_meta.move_to_end(port)

        return is_new_port

    def record_dns(
        self,
        query_name: Optional[str] = None,
        response_code: Optional[str] = None,
        query_type: Optional[str] = None,
        event_time: Optional[float] = None,
    ) -> bool:
        """Record DNS observation. Returns True if query_name is newly observed."""
        ts = event_time or self.last_seen or 0.0
        if ts > 0.0:
            self._update_timestamps(ts)
        self.dns_query_count += 1

        if str(response_code).upper() == "NXDOMAIN":
            self.dns_nxdomain_count += 1
        if str(query_type).upper() == "TXT":
            self.dns_txt_count += 1

        if not query_name:
            return False

        self.dns_query_names.append(query_name)
        is_new = query_name not in self.known_domains

        if is_new:
            if len(self.domain_meta) >= self.max_domains:
                oldest = next(iter(self.domain_meta))
                del self.domain_meta[oldest]
                self.known_domains.discard(oldest)

            self.domain_meta[query_name] = {
                "first_seen": ts,
                "last_seen": ts,
                "count": 1,
            }
            self.known_domains.add(query_name)
        else:
            meta = self.domain_meta[query_name]
            meta["last_seen"] = ts
            meta["count"] += 1
            self.domain_meta.move_to_end(query_name)

        return is_new

    def record_tls(
        self,
        ja3: Optional[str] = None,
        ja4: Optional[str] = None,
        sni: Optional[str] = None,
        version: Optional[str] = None,
        alpn: Optional[str] = None,
        resumption: Optional[bool] = None,
        event_time: Optional[float] = None,
    ) -> bool:
        """Record TLS/QUIC observation. Returns True if fingerprint is newly observed."""
        ts = event_time or self.last_seen or 0.0
        if ts > 0.0:
            self._update_timestamps(ts)
        is_new_fp = False

        if ja3:
            self.known_ja3.add(ja3)
        if ja4:
            self.known_ja4.add(ja4)
        if sni:
            self.record_dns(query_name=sni, event_time=ts)
        if version:
            self.tls_versions.add(version)
        if alpn:
            self.alpn_protocols.add(alpn)
        if resumption:
            self.session_resumption_count += 1

        fp = (f"ja4:{ja4}" if ja4 else f"ja3:{ja3}" if ja3 else None)
        if fp:
            if self.first_seen_fingerprint is None:
                self.first_seen_fingerprint = fp

            is_new_fp = fp not in self.fingerprint_meta
            if is_new_fp:
                if len(self.fingerprint_meta) >= self.max_fingerprints:
                    oldest = next(iter(self.fingerprint_meta))
                    del self.fingerprint_meta[oldest]
                self.fingerprint_meta[fp] = {
                    "first_seen": ts,
                    "last_seen": ts,
                    "count": 1,
                }
            else:
                meta = self.fingerprint_meta[fp]
                meta["last_seen"] = ts
                meta["count"] += 1
                self.fingerprint_meta.move_to_end(fp)

        return is_new_fp

    def get_destination_novelty_stats(self, dst_ip: str, as_of: float) -> Tuple[bool, int, float]:
        """Return (is_new, frequency, age_seconds) for a destination IP."""
        if dst_ip not in self.destination_meta:
            return True, 0, 0.0
        meta = self.destination_meta[dst_ip]
        age = max(0.0, as_of - meta["first_seen"])
        return False, meta["count"], age

    def compute_pps_baseline(self) -> Tuple[float, float]:
        """Compute rolling mean and standard deviation of PPS (backward compatible)."""
        if not self.pps_history:
            return self.pps_baseline.ewma_mean, math.sqrt(max(0.0, self.pps_baseline.ewma_var))
        n = len(self.pps_history)
        mean_val = sum(self.pps_history) / n
        if n < 2:
            return mean_val, 0.0
        variance = sum((x - mean_val) ** 2 for x in self.pps_history) / (n - 1)
        return mean_val, math.sqrt(variance)

    def compute_pps_z_score(self, current_pps: float) -> float:
        """Calculate Z-score deviation of PPS from entity historical baseline."""
        return self.pps_baseline.compute_z_score(current_pps)

    def compute_outbound_rate_z_score(self, current_rate: float) -> float:
        """Calculate Z-score deviation of outbound byte rate from baseline."""
        return self.outbound_rate_baseline.compute_z_score(current_rate)

    def compute_dns_rate_z_score(self, current_dns_rate: float) -> float:
        """Calculate Z-score deviation of DNS query rate from baseline."""
        return self.dns_rate_baseline.compute_z_score(current_dns_rate)

    def compute_flow_rate_z_score(self, current_flow_rate: float) -> float:
        """Calculate Z-score deviation of flow rate from baseline."""
        return self.flow_rate_baseline.compute_z_score(current_flow_rate)

    def get_temporal_features(self) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[float]]:
        """Compute (iat_mean_ms, iat_std_ms, periodicity_score, jitter_pct) over timestamp history."""
        n = len(self.flow_timestamps)
        if n < 5:
            return None, None, None, None

        iats = [
            max(0.0, (self.flow_timestamps[i] - self.flow_timestamps[i - 1]) * 1000.0)
            for i in range(1, n)
        ]
        if not iats:
            return None, None, None, None

        mean_iat = sum(iats) / len(iats)
        if len(iats) > 1:
            variance = sum((x - mean_iat) ** 2 for x in iats) / (len(iats) - 1)
            std_iat = math.sqrt(variance)
        else:
            std_iat = 0.0

        if mean_iat > 0:
            cv = std_iat / mean_iat
            jitter_pct = cv * 100.0
            periodicity = max(0.0, 1.0 - min(1.0, cv))
        else:
            jitter_pct = 0.0
            periodicity = 1.0

        return mean_iat, std_iat, periodicity, jitter_pct

    def get_window_events(self, window_sec: float, as_of: Optional[float] = None) -> List[EntityFlowRecord]:
        """Extract flows strictly within [as_of - window_sec, as_of]."""
        ref_time = as_of if as_of is not None else self.last_seen
        cutoff = ref_time - window_sec
        return [r for r in self.flow_records if cutoff <= r.timestamp <= ref_time]

    def get_graph_summary(self) -> Dict[str, Any]:
        """Return stable properties for EntityBehaviourGraph export."""
        entity_ip = _entity_ip(self.entity_id)
        return {
            "entity_id": self.entity_id,
            "entity_ip": entity_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_seen_iso": self.first_seen_iso,
            "last_seen_iso": self.last_seen_iso,
            "flow_count": self.flow_count,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "unique_destinations": len(self.known_destinations),
            "unique_ports": len(self.known_ports),
            "unique_domains": len(self.known_domains),
            "known_ja4": list(self.known_ja4),
            "first_seen_fingerprint": self.first_seen_fingerprint,
        }


# Alias for domain consistency
EntityState = EntityProfile


class EntityMemory:
    """Bounded in-memory entity registry tracking host profiles across the enclave."""

    def __init__(
        self,
        max_entities: int = 10000,
        history_window_size: int = 60,
        entity_ttl_sec: float = 900.0,
        baseline_policy: Optional[BaselineUpdatePolicy] = None,
    ):
        self.max_entities = max_entities
        self.history_window_size = history_window_size
        self.entity_ttl_sec = entity_ttl_sec
        self.policy = baseline_policy or BaselineUpdatePolicy()
        self._profiles: OrderedDict[str, EntityProfile] = OrderedDict()
        self.latest_event_time: float = 0.0

    def get_or_create_profile(self, entity_id: str, event_time: Optional[float] = None) -> EntityProfile:
        """Retrieve existing entity profile or create a new one with bounded LRU eviction."""
        if event_time is not None:
            self.latest_event_time = max(self.latest_event_time, event_time)

        if entity_id in self._profiles:
            self._profiles.move_to_end(entity_id)
            return self._profiles[entity_id]

        if len(self._profiles) >= self.max_entities:
            # Evict oldest LRU entity
            self._profiles.popitem(last=False)

        profile = EntityProfile(
            entity_id=entity_id,
            max_history_windows=self.history_window_size,
            baseline_policy=self.policy,
        )
        if event_time is not None:
            profile._update_timestamps(event_time)
        self._profiles[entity_id] = profile
        return profile

    def get_profile(self, entity_id: str) -> Optional[EntityProfile]:
        """Retrieve existing entity profile if present, or None."""
        return self._profiles.get(entity_id)

    def record_signal(self, signal: DetectionSignal) -> None:
        """Associate an incoming DetectionSignal with the originating entity."""
        profile = self.get_or_create_profile(signal.source_entity)
        profile.active_signal_ids.append(signal.signal_id)
        if signal.target_entity:
            profile.record_destination(signal.target_entity)

    def evaluate_entity_event(self, entity_id: str, current_pps: float = 0.0) -> EntityEvent:
        """Produce a standardized EntityEvent snapshot."""
        profile = self.get_or_create_profile(entity_id)
        z_score = profile.compute_pps_z_score(current_pps)

        return EntityEvent(
            entity_id=entity_id,
            entity_type="HOST_IP",
            timestamp_iso=profile.last_seen_iso or datetime.now(timezone.utc).isoformat(),
            active_signals=list(profile.active_signal_ids),
            baseline_deviation_score=round(z_score, 3),
            known_destinations_count=len(profile.known_destinations),
            new_destinations_count=0,
        )

    def cleanup_idle_entities(self, current_event_time: float) -> int:
        """Evict entities that have been inactive longer than entity_ttl_sec."""
        cutoff = current_event_time - self.entity_ttl_sec
        idle_keys = [
            eid for eid, profile in self._profiles.items()
            if profile.last_seen < cutoff
        ]
        for eid in idle_keys:
            del self._profiles[eid]
        return len(idle_keys)

    def get_all_profiles(self) -> Dict[str, EntityProfile]:
        """Return all tracked profiles."""
        return dict(self._profiles)

    def __len__(self) -> int:
        return len(self._profiles)


def _entity_ip(entity_id: str) -> str:
    if ":" in entity_id:
        _, possible_ip = entity_id.split(":", 1)
        if "." in possible_ip:
            return possible_ip
    return entity_id


def _is_failed_flow(flow: Any) -> bool:
    if getattr(flow, "byte_count", 0) == 0:
        return True
    if getattr(flow, "protocol", 0) == 6:
        syn = getattr(flow, "syn_count", 0)
        ack = getattr(flow, "ack_count", 0)
        rst = getattr(flow, "rst_count", 0)
        packets = getattr(flow, "packet_count", 0)
        bytes_cnt = getattr(flow, "byte_count", 0)
        if syn > 0 and ack == 0 and packets <= 1:
            return True
        if rst > 0 and bytes_cnt < 64:
            return True
    return False


def _to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(iso_str: str) -> float:
    try:
        clean = iso_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).timestamp()
    except Exception:
        return 0.0
