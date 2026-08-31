"""Persistent Entity & Window Context Manager (PS 26145).

Maintains rolling entity-level context across sliding window batches for Member-2 feature extraction
and baseline threat detection.

DESIGN & BOUNDARY PRINCIPLES:
- 100% Deterministic Event-Time Semantics (uses flow.timestamp, not wall-clock).
- Reference-Counted Destination IP & Port Tracking (expire-accurate, no permanent sets).
- Direction Isolation: Recon destination cardinality uses outbound flows only (src_ip == entity_ip).
  Exfiltration tracks bidirectional traffic for upload/download ratio accumulation.
- Minimum Temporal Evidence: Requires at least 5 observations for periodicity/jitter.
- Bounded Memory: Enforces LRU capacity (50,000 entities) and idle TTL cleanup (900s).
- Frozen ML Contract & Non-Leakage: Pure physical packet metadata; no target labels or risk scores.
"""

import bisect
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from typing import Dict, List, Optional, Tuple, Union

from schemas.flow_event import FlowEvent as M1FlowEvent
from schemas import TemporalFeatures
from features.recon_features import ReconFeatures
from features.exfil_features import ExfiltrationFeatures


@dataclass(frozen=True)
class EntityFlowRecord:
    """Immutable record of an individual flow observed for an entity."""
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    byte_count: int
    is_failed: bool
    is_outbound: bool


@dataclass
class EntityState:
    """Stateful rolling context container for a single network entity (IP address)."""
    entity_ip: str
    first_seen: float
    last_seen: float

    # Flow records within retention window
    flow_records: deque[EntityFlowRecord] = field(default_factory=deque)
    flow_timestamps: deque[float] = field(default_factory=deque)  # sorted timestamps

    # Reference-counted outbound destination tracking (outbound only)
    dst_ips: Counter[str] = field(default_factory=Counter)
    dst_ports: Counter[int] = field(default_factory=Counter)

    # Rolling aggregate counters
    outbound_flow_count: int = 0
    inbound_flow_count: int = 0
    total_outbound_bytes: int = 0
    total_inbound_bytes: int = 0
    failed_connection_count: int = 0  # outbound failed
    large_transfer_count: int = 0     # outbound transfers >= threshold

    def add_flow(self, record: EntityFlowRecord, large_transfer_threshold: int = 1_000_000) -> None:
        """Ingest a new flow record for this entity and update counters."""
        self.flow_records.append(record)
        self.last_seen = max(self.last_seen, record.timestamp)

        # Insert timestamp into sorted order (handles out-of-order safely)
        bisect.insort(self.flow_timestamps, record.timestamp)

        if record.is_outbound:
            self.outbound_flow_count += 1
            self.total_outbound_bytes += record.byte_count
            self.dst_ips[record.dst_ip] += 1
            self.dst_ports[record.dst_port] += 1

            if record.is_failed:
                self.failed_connection_count += 1
            if record.byte_count >= large_transfer_threshold:
                self.large_transfer_count += 1
        else:
            self.inbound_flow_count += 1
            self.total_inbound_bytes += record.byte_count

    def expire_old(self, cutoff_timestamp: float, large_transfer_threshold: int = 1_000_000) -> None:
        """Evict flow records older than cutoff_timestamp and decrement reference-counted stats."""
        while self.flow_records and self.flow_records[0].timestamp < cutoff_timestamp:
            old = self.flow_records.popleft()

            if old.is_outbound:
                self.outbound_flow_count = max(0, self.outbound_flow_count - 1)
                self.total_outbound_bytes = max(0, self.total_outbound_bytes - old.byte_count)

                # Reference-counted destination removal
                if old.dst_ip in self.dst_ips:
                    self.dst_ips[old.dst_ip] -= 1
                    if self.dst_ips[old.dst_ip] <= 0:
                        del self.dst_ips[old.dst_ip]

                if old.dst_port in self.dst_ports:
                    self.dst_ports[old.dst_port] -= 1
                    if self.dst_ports[old.dst_port] <= 0:
                        del self.dst_ports[old.dst_port]

                if old.is_failed:
                    self.failed_connection_count = max(0, self.failed_connection_count - 1)
                if old.byte_count >= large_transfer_threshold:
                    self.large_transfer_count = max(0, self.large_transfer_count - 1)
            else:
                self.inbound_flow_count = max(0, self.inbound_flow_count - 1)
                self.total_inbound_bytes = max(0, self.total_inbound_bytes - old.byte_count)

        # Evict old timestamps
        while self.flow_timestamps and self.flow_timestamps[0] < cutoff_timestamp:
            self.flow_timestamps.popleft()

    @property
    def maximum_single_flow_bytes(self) -> int:
        """Compute exact maximum byte transfer across active outbound flows dynamically."""
        outbound_bytes = [r.byte_count for r in self.flow_records if r.is_outbound]
        return max(outbound_bytes, default=0)

    def get_temporal_features(self) -> TemporalFeatures:
        """Extract TemporalFeatures from rolling timestamp history (requires >= 5 observations)."""
        n = len(self.flow_timestamps)
        if n < 5:
            return TemporalFeatures(
                inter_arrival_mean_ms=None,
                inter_arrival_std_ms=None,
                periodicity_score=None,
                jitter_pct=None,
            )

        # Compute inter-arrival times in milliseconds
        iats = []
        for i in range(1, n):
            delta_ms = max(0.0, (self.flow_timestamps[i] - self.flow_timestamps[i - 1]) * 1000.0)
            iats.append(delta_ms)

        num_iats = len(iats)
        mean_iat = sum(iats) / num_iats

        if num_iats > 1:
            variance = sum((x - mean_iat) ** 2 for x in iats) / (num_iats - 1)
            std_iat = math.sqrt(variance)
        else:
            std_iat = 0.0

        if mean_iat > 0:
            jitter_pct = (std_iat / mean_iat) * 100.0
            cv = std_iat / mean_iat
            periodicity_score = max(0.0, 1.0 - cv)
        else:
            jitter_pct = 0.0
            periodicity_score = 1.0

        return TemporalFeatures(
            inter_arrival_mean_ms=mean_iat,
            inter_arrival_std_ms=std_iat,
            periodicity_score=periodicity_score,
            jitter_pct=jitter_pct,
        )

    def get_recon_features(
        self,
        window_duration_sec: float,
        min_flows_required: int = 3,
        horizontal_ip_threshold: int = 5,
        vertical_port_threshold: int = 5,
    ) -> ReconFeatures:
        """Construct ReconFeatures using accumulated outbound destination metrics."""
        rf = ReconFeatures()
        rf.window_duration_sec = window_duration_sec
        rf.flow_count = self.outbound_flow_count

        if rf.flow_count == 0:
            return rf

        rf.unique_dst_ips = set(self.dst_ips.keys())
        rf.unique_dst_ip_count = len(self.dst_ips)
        rf.unique_dst_ports = set(self.dst_ports.keys())
        rf.unique_dst_port_count = len(self.dst_ports)
        rf.failed_connection_count = self.failed_connection_count
        rf.failed_connection_ratio = (
            self.failed_connection_count / float(rf.flow_count)
        )

        if window_duration_sec > 0:
            rf.connection_rate_per_sec = rf.flow_count / window_duration_sec

        h_scan = rf.unique_dst_ip_count >= horizontal_ip_threshold
        v_scan = rf.unique_dst_port_count >= vertical_port_threshold

        if h_scan and v_scan:
            rf.is_broad = True
        elif h_scan:
            rf.is_horizontal = True
        elif v_scan:
            rf.is_vertical = True

        rf.sufficient_evidence = rf.flow_count >= min_flows_required
        return rf

    def get_exfil_features(
        self,
        window_duration_sec: float,
        min_flows_required: int = 3,
        large_transfer_bytes: int = 1_000_000,
    ) -> ExfiltrationFeatures:
        """Construct ExfiltrationFeatures using accumulated bidirectional metrics."""
        ef = ExfiltrationFeatures()
        total_flows = self.outbound_flow_count + self.inbound_flow_count

        if total_flows == 0:
            ef.window_duration_sec = window_duration_sec
            ef.direction_available = False
            return ef

        ef.flow_count = total_flows
        ef.outbound_flow_count = self.outbound_flow_count
        ef.inbound_flow_count = self.inbound_flow_count
        ef.total_outbound_bytes = self.total_outbound_bytes
        ef.total_inbound_bytes = self.total_inbound_bytes
        ef.destination_count = len(self.dst_ips)
        ef.maximum_single_flow_bytes = self.maximum_single_flow_bytes
        ef.large_transfer_count = self.large_transfer_count
        ef.direction_available = True
        ef.window_duration_sec = window_duration_sec

        total_bytes = self.total_outbound_bytes + self.total_inbound_bytes
        if total_bytes > 0:
            ef.outbound_bytes_ratio = self.total_outbound_bytes / float(total_bytes)

        if self.total_inbound_bytes > 0:
            ef.upload_download_ratio = self.total_outbound_bytes / float(self.total_inbound_bytes)
        else:
            ef.upload_download_ratio = None

        if window_duration_sec > 0:
            ef.outbound_bytes_per_sec = self.total_outbound_bytes / window_duration_sec

        ef.sufficient_evidence = total_flows >= min_flows_required
        return ef


def _is_failed_flow(flow: M1FlowEvent) -> bool:
    """Heuristic helper checking if flow represents a likely failed connection attempt."""
    if flow.byte_count == 0:
        return True
    if flow.protocol == 6 and flow.rst_count > 0 and flow.byte_count < 64:
        return True
    return False


class EntityContextManager:
    """Stateful multi-window entity context manager for Member-2.

    Maintains rolling EntityState instances across consecutive sliding windows.
    Enforces LRU capacity limits and idle TTL cleanup.
    """

    def __init__(
        self,
        retention_window_sec: float = 300.0,
        entity_ttl_sec: float = 900.0,
        max_active_entities: int = 50_000,
        max_timestamps_per_entity: int = 1_000,
        large_transfer_bytes: int = 1_000_000,
    ):
        self.retention_window_sec = retention_window_sec
        self.entity_ttl_sec = entity_ttl_sec
        self.max_active_entities = max_active_entities
        self.max_timestamps_per_entity = max_timestamps_per_entity
        self.large_transfer_bytes = large_transfer_bytes

        self.entities: OrderedDict[str, EntityState] = OrderedDict()
        self.latest_event_timestamp: float = 0.0

    def update(self, flows: List[M1FlowEvent]) -> None:
        """Ingest new M1 FlowEvents and update entity states."""
        if not flows:
            return

        for flow in flows:
            self.latest_event_timestamp = max(self.latest_event_timestamp, flow.timestamp)
            is_failed = _is_failed_flow(flow)

            # 1. Update Source Entity (Outbound Flow)
            src_ip = flow.src_ip
            src_state = self._get_or_create_entity(src_ip, flow.timestamp)
            src_record = EntityFlowRecord(
                timestamp=flow.timestamp,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                byte_count=flow.byte_count,
                is_failed=is_failed,
                is_outbound=True,
            )
            src_state.add_flow(src_record, large_transfer_threshold=self.large_transfer_bytes)
            self.entities.move_to_end(src_ip)

            # 2. Update Destination Entity (Inbound Flow)
            dst_ip = flow.dst_ip
            dst_state = self._get_or_create_entity(dst_ip, flow.timestamp)
            dst_record = EntityFlowRecord(
                timestamp=flow.timestamp,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                byte_count=flow.byte_count,
                is_failed=is_failed,
                is_outbound=False,
            )
            dst_state.add_flow(dst_record, large_transfer_threshold=self.large_transfer_bytes)
            self.entities.move_to_end(dst_ip)

        # 3. Perform sliding window eviction and idle TTL cleanup
        cutoff = self.latest_event_timestamp - self.retention_window_sec
        for state in list(self.entities.values()):
            state.expire_old(cutoff, large_transfer_threshold=self.large_transfer_bytes)

        self._cleanup_idle_entities()
        self._enforce_capacity()

    def _get_or_create_entity(self, entity_ip: str, timestamp: float) -> EntityState:
        """Retrieve existing entity state or lazily create a new one."""
        state = self.entities.get(entity_ip)
        if state is None:
            state = EntityState(
                entity_ip=entity_ip,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            self.entities[entity_ip] = state
        return state

    def _cleanup_idle_entities(self) -> None:
        """Remove entities inactive longer than entity_ttl_sec."""
        ttl_cutoff = self.latest_event_timestamp - self.entity_ttl_sec
        idle_keys = [
            ip for ip, state in self.entities.items()
            if state.last_seen < ttl_cutoff
        ]
        for ip in idle_keys:
            del self.entities[ip]

    def _enforce_capacity(self) -> None:
        """Evict oldest inactive entities if max_active_entities is exceeded."""
        while len(self.entities) > self.max_active_entities:
            self.entities.popitem(last=False)

    def get_recon_features(self, entity_ip: str, window_duration_sec: float = 60.0) -> ReconFeatures:
        """Get ReconFeatures for entity IP."""
        state = self.entities.get(entity_ip)
        if state is None:
            rf = ReconFeatures()
            rf.window_duration_sec = window_duration_sec
            return rf
        return state.get_recon_features(window_duration_sec=window_duration_sec)

    def get_exfil_features(self, entity_ip: str, window_duration_sec: float = 60.0) -> ExfiltrationFeatures:
        """Get ExfiltrationFeatures for entity IP."""
        state = self.entities.get(entity_ip)
        if state is None:
            ef = ExfiltrationFeatures()
            ef.window_duration_sec = window_duration_sec
            ef.direction_available = False
            return ef
        return state.get_exfil_features(window_duration_sec=window_duration_sec)

    def get_temporal_features(self, entity_ip: str) -> TemporalFeatures:
        """Get TemporalFeatures for entity IP."""
        state = self.entities.get(entity_ip)
        if state is None:
            return TemporalFeatures(
                inter_arrival_mean_ms=None,
                inter_arrival_std_ms=None,
                periodicity_score=None,
                jitter_pct=None,
            )
        return state.get_temporal_features()

    def get_observation_count(self, entity_ip: str) -> int:
        """Get total rolling flow observation count for entity IP."""
        state = self.entities.get(entity_ip)
        if state is None:
            return 0
        return len(state.flow_timestamps)
