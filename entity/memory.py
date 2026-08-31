"""Entity Memory and Historical Baseline Profiler (Member 3).

Maintains rolling statistical baselines per network entity (Host IP, Subnet, Domain).
Computes real-time Z-score deviations from historical norms without unbounded memory.
"""

from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any
import math

from schemas import EntityEvent, FeatureVector, DetectionSignal


class EntityProfile:
    """Statistical profile and rolling historical state for a single entity."""

    def __init__(self, entity_id: str, max_history_windows: int = 60):
        self.entity_id = entity_id
        self.max_history = max_history_windows
        self.first_seen_iso = datetime.now(timezone.utc).isoformat()
        self.last_seen_iso = self.first_seen_iso

        # Rolling window history of metrics (e.g. packets_per_sec, bytes_per_sec)
        self.pps_history: deque = deque(maxlen=max_history_windows)
        self.bps_history: deque = deque(maxlen=max_history_windows)

        # Set of known destination IPs and ports
        self.known_destinations: Set[str] = set()
        self.known_ports: Set[int] = set()
        self.known_ja3: Set[str] = set()
        self.known_ja4: Set[str] = set()
        self.known_domains: Set[str] = set()

        # Active detection signal IDs associated with this entity
        self.active_signal_ids: deque = deque(maxlen=100)
        self.total_observations: int = 0

    def update_from_feature_vector(self, fv: FeatureVector) -> None:
        """Update historical profile from an extracted FeatureVector."""
        self.last_seen_iso = fv.timestamp_iso
        self.total_observations += 1

        if fv.flow_features:
            self.pps_history.append(fv.flow_features.packets_per_sec)
            self.bps_history.append(fv.flow_features.bytes_per_sec)

        if fv.tls_features:
            if fv.tls_features.ja3_hash:
                self.known_ja3.add(fv.tls_features.ja3_hash)
            if fv.tls_features.ja4_hash:
                self.known_ja4.add(fv.tls_features.ja4_hash)
            if fv.tls_features.sni:
                self.known_domains.add(fv.tls_features.sni)

    def record_destination(self, dst_ip: str, dst_port: Optional[int] = None) -> bool:
        """Record an observed destination. Returns True if this destination is newly observed."""
        is_new = dst_ip not in self.known_destinations
        self.known_destinations.add(dst_ip)
        if dst_port is not None:
            self.known_ports.add(dst_port)
        return is_new

    def compute_pps_baseline(self) -> tuple[float, float]:
        """Compute rolling mean and standard deviation of packets per second."""
        if not self.pps_history:
            return 0.0, 0.0
        n = len(self.pps_history)
        mean_val = sum(self.pps_history) / n
        if n < 2:
            return mean_val, 0.0
        variance = sum((x - mean_val) ** 2 for x in self.pps_history) / (n - 1)
        return mean_val, math.sqrt(variance)

    def compute_pps_z_score(self, current_pps: float) -> float:
        """Calculate Z-score deviation of current PPS from entity historical baseline."""
        mean_val, std_val = self.compute_pps_baseline()
        if std_val < 1e-5:
            # If standard deviation is negligible, measure relative ratio
            if mean_val > 0:
                return max(0.0, (current_pps - mean_val) / max(mean_val, 1.0))
            return 0.0 if current_pps <= 10.0 else (current_pps / 10.0)
        return max(0.0, (current_pps - mean_val) / std_val)


class EntityMemory:
    """Bounded in-memory entity registry tracking host profiles across the enclave."""

    def __init__(self, max_entities: int = 10000, history_window_size: int = 60):
        self.max_entities = max_entities
        self.history_window_size = history_window_size
        self._profiles: Dict[str, EntityProfile] = {}

    def get_or_create_profile(self, entity_id: str) -> EntityProfile:
        """Retrieve existing entity profile or create a new one with bounded eviction."""
        if entity_id not in self._profiles:
            if len(self._profiles) >= self.max_entities:
                # Evict oldest entity
                oldest_key = min(self._profiles, key=lambda k: self._profiles[k].last_seen_iso)
                del self._profiles[oldest_key]
            self._profiles[entity_id] = EntityProfile(entity_id, max_history_windows=self.history_window_size)
        return self._profiles[entity_id]

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
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            active_signals=list(profile.active_signal_ids),
            baseline_deviation_score=round(z_score, 3),
            known_destinations_count=len(profile.known_destinations),
            new_destinations_count=0,
        )

    def get_all_profiles(self) -> Dict[str, EntityProfile]:
        """Return all tracked profiles."""
        return self._profiles
