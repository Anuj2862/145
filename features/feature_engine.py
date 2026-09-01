from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import math
from statistics import median, pstdev
from typing import Any, Iterable

from flow.flow_key import FlowKey
from flow.flow_manager import FlowManager
from ingest.pcap_reader import NormalizedPacket
from schemas.flow_event import FlowEvent
from schemas.telemetry import DNSMetadata, TLSMetadata, QUICMetadata
from schemas.telemetry import canonical_entity_id
from entity.memory import EntityMemory, EntityProfile


FEATURE_SCHEMA_VERSION = "feature-schema-v2.0.0"
DEFAULT_WINDOWS_SECONDS = (1, 5, 15, 30, 60, 300)


@dataclass(frozen=True)
class FeatureMetadata:
    name: str
    family: str
    source: str
    window: str
    calculation: str
    missing_data_policy: str
    version: str = FEATURE_SCHEMA_VERSION


@dataclass(frozen=True)
class FeatureValue:
    name: str
    value: float | int | str | bool | None
    metadata: FeatureMetadata
    missing_reason: str | None = None

    @property
    def available(self) -> bool:
        return self.missing_reason is None


@dataclass(frozen=True)
class CanonicalFeatureSet:
    entity_id: str
    as_of_event_time: float
    schema_version: str
    windows: tuple[int, ...]
    features: dict[str, FeatureValue]

    def values(self) -> dict[str, float | int | str | bool | None]:
        return {name: item.value for name, item in self.features.items()}

    def metadata(self) -> dict[str, dict[str, Any]]:
        return {
            name: asdict(item.metadata)
            for name, item in self.features.items()
        }

    def available_values(self) -> dict[str, float | int | str | bool]:
        return {
            name: item.value
            for name, item in self.features.items()
            if item.available
        }

    def missing_values(self) -> dict[str, str]:
        return {
            name: item.missing_reason or "unknown"
            for name, item in self.features.items()
            if not item.available
        }


@dataclass(frozen=True)
class _FeatureSpec:
    name: str
    family: str
    source: str
    calculation: str
    missing_data_policy: str


def _specs() -> tuple[_FeatureSpec, ...]:
    return (
        _FeatureSpec("duration", "flow", "flow_state", "max(end) - min(start)", "0 only for single-packet/zero-duration observations"),
        _FeatureSpec("total_packets", "flow", "flow_state", "sum packet_count", "0 means no observed packets"),
        _FeatureSpec("total_bytes", "flow", "flow_state", "sum byte_count", "0 means no observed bytes"),
        _FeatureSpec("bytes_forward", "flow", "entity_direction", "sum bytes where src_ip is entity", "0 means no observed forward bytes"),
        _FeatureSpec("bytes_backward", "flow", "entity_direction", "sum bytes where dst_ip is entity", "0 means no observed backward bytes"),
        _FeatureSpec("packets_forward", "flow", "entity_direction", "sum packets where src_ip is entity", "0 means no observed forward packets"),
        _FeatureSpec("packets_backward", "flow", "entity_direction", "sum packets where dst_ip is entity", "0 means no observed backward packets"),
        _FeatureSpec("packets_per_sec", "flow", "flow_state", "total_packets / window seconds", "missing when window is invalid"),
        _FeatureSpec("bytes_per_sec", "flow", "flow_state", "total_bytes / window seconds", "missing when window is invalid"),
        _FeatureSpec("packet_size_mean", "flow", "packet_sizes", "mean packet size", "missing when no packet sizes are observed"),
        _FeatureSpec("packet_size_std", "flow", "packet_sizes", "population stddev packet size", "missing when no packet sizes are observed"),
        _FeatureSpec("packet_size_min", "flow", "packet_sizes", "minimum packet size", "missing when no packet sizes are observed"),
        _FeatureSpec("packet_size_max", "flow", "packet_sizes", "maximum packet size", "missing when no packet sizes are observed"),
        _FeatureSpec("syn_ratio", "flow", "tcp_flags", "syn_count / total_packets", "missing when no packets are observed"),
        _FeatureSpec("ack_ratio", "flow", "tcp_flags", "ack_count / total_packets", "missing when no packets are observed"),
        _FeatureSpec("fin_ratio", "flow", "tcp_flags", "fin_count / total_packets", "missing when no packets are observed"),
        _FeatureSpec("rst_ratio", "flow", "tcp_flags", "rst_count / total_packets", "missing when no packets are observed"),
        _FeatureSpec("psh_ratio", "flow", "tcp_flags", "psh_count / total_packets", "missing when no packets are observed"),
        _FeatureSpec("urg_ratio", "flow", "tcp_flags", "urg_count / total_packets", "missing when no packets are observed"),
        _FeatureSpec("iat_mean", "temporal", "event_time", "mean inter-arrival time in ms", "missing when fewer than 2 events"),
        _FeatureSpec("iat_std", "temporal", "event_time", "population stddev IAT in ms", "missing when fewer than 2 events"),
        _FeatureSpec("iat_median", "temporal", "event_time", "median IAT in ms", "missing when fewer than 2 events"),
        _FeatureSpec("iat_mad", "temporal", "event_time", "median absolute deviation of IAT in ms", "missing when fewer than 2 events"),
        _FeatureSpec("iat_cv", "temporal", "event_time", "IAT stddev / mean", "missing when mean IAT is zero/unavailable"),
        _FeatureSpec("periodicity_score", "temporal", "event_time", "1 - min(1, coefficient of variation)", "missing when IAT unavailable"),
        _FeatureSpec("jitter", "temporal", "event_time", "IAT stddev / mean as percent", "missing when mean IAT is zero/unavailable"),
        _FeatureSpec("burst_rate", "temporal", "event_time", "max 1s event bucket count / window seconds", "0 means no burst observed"),
        _FeatureSpec("autocorrelation", "temporal", "event_time", "lag-1 autocorrelation of IAT sequence", "missing when fewer than 3 IATs"),
        _FeatureSpec("dns_query_count", "dns", "dns_metadata", "count DNS observations", "0 means no DNS metadata observed"),
        _FeatureSpec("unique_domain_count", "dns", "dns_metadata", "count unique DNS query names", "0 means no DNS names observed"),
        _FeatureSpec("unique_subdomain_count", "dns", "dns_metadata", "count names with label depth > 2", "0 means no subdomains observed"),
        _FeatureSpec("dns_query_rate", "dns", "dns_metadata", "query count / window seconds", "missing when window is invalid"),
        _FeatureSpec("domain_length_mean", "dns", "dns_metadata", "mean query-name length", "missing when no DNS names observed"),
        _FeatureSpec("domain_length_p95", "dns", "dns_metadata", "95th percentile query-name length", "missing when no DNS names observed"),
        _FeatureSpec("domain_entropy", "dns", "dns_metadata", "mean Shannon entropy of query names", "missing when no DNS names observed"),
        _FeatureSpec("character_diversity", "dns", "dns_metadata", "unique chars / total chars", "missing when no DNS names observed"),
        _FeatureSpec("digit_ratio", "dns", "dns_metadata", "digit chars / total chars", "missing when no DNS names observed"),
        _FeatureSpec("ngram_score", "dns", "dns_metadata", "lexical rarity proxy from entropy and digit ratio", "missing when no DNS names observed"),
        _FeatureSpec("nxdomain_ratio", "dns", "dns_metadata", "NXDOMAIN responses / DNS observations", "missing when no DNS observations"),
        _FeatureSpec("txt_ratio", "dns", "dns_metadata", "TXT queries / DNS observations", "missing when no DNS observations"),
        _FeatureSpec("label_depth_mean", "dns", "dns_metadata", "mean DNS label count", "missing when no DNS names observed"),
        _FeatureSpec("tls_version", "tls_quic", "tls_quic_metadata", "first observed TLS version", "missing when unavailable"),
        _FeatureSpec("ja3", "tls_quic", "tls_metadata", "first observed JA3", "missing when unavailable"),
        _FeatureSpec("ja4", "tls_quic", "tls_quic_metadata", "first observed JA4", "missing when unavailable"),
        _FeatureSpec("sni", "tls_quic", "tls_quic_metadata", "first observed SNI", "missing when unavailable"),
        _FeatureSpec("alpn", "tls_quic", "tls_quic_metadata", "first observed ALPN", "missing when unavailable"),
        _FeatureSpec("session_resumption", "tls_quic", "tls_metadata", "observed session resumption flag", "missing when unavailable"),
        _FeatureSpec("tls_packet_size_mean", "tls_quic", "packet_sizes", "mean packet size for TLS/QUIC-like flows", "missing when no TLS/QUIC-like packets"),
        _FeatureSpec("tls_packet_size_std", "tls_quic", "packet_sizes", "stddev packet size for TLS/QUIC-like flows", "missing when no TLS/QUIC-like packets"),
        _FeatureSpec("tls_packet_size_min", "tls_quic", "packet_sizes", "min packet size for TLS/QUIC-like flows", "missing when no TLS/QUIC-like packets"),
        _FeatureSpec("tls_packet_size_max", "tls_quic", "packet_sizes", "max packet size for TLS/QUIC-like flows", "missing when no TLS/QUIC-like packets"),
        _FeatureSpec("tls_packet_size_sequence_mean_delta", "tls_quic", "packet_sizes", "mean adjacent packet-size delta", "missing when fewer than 2 packets"),
        _FeatureSpec("tls_timing_mean", "tls_quic", "event_time", "mean TLS/QUIC-like IAT in ms", "missing when fewer than 2 TLS/QUIC-like events"),
        _FeatureSpec("tls_fingerprint_novelty", "tls_quic", "entity_history", "1 when first fingerprint for entity", "missing when no fingerprint observed"),
        _FeatureSpec("tls_fingerprint_frequency", "tls_quic", "entity_history", "historical fingerprint count", "missing when no fingerprint observed"),
        _FeatureSpec("unique_dst_ips", "recon", "flow_state", "count unique destination IPs", "0 means no destinations observed"),
        _FeatureSpec("unique_dst_ports", "recon", "flow_state", "count unique destination ports", "0 means no destination ports observed"),
        _FeatureSpec("new_destinations", "recon", "entity_history", "destinations not previously seen for entity", "0 means none new"),
        _FeatureSpec("new_ports", "recon", "entity_history", "destination ports not previously seen for entity", "0 means none new"),
        _FeatureSpec("connection_attempt_rate", "recon", "flow_state", "flow count / window seconds", "missing when window is invalid"),
        _FeatureSpec("failed_connection_ratio", "recon", "tcp_flags", "failed-connection proxy / flow count", "missing when no flows observed"),
        _FeatureSpec("fan_out", "recon", "flow_state", "unique destinations / flow count", "missing when no flows observed"),
        _FeatureSpec("destination_entropy", "recon", "flow_state", "Shannon entropy of destination IP distribution", "missing when no destinations observed"),
        _FeatureSpec("outbound_bytes", "exfil", "entity_direction", "sum outbound bytes", "0 means no outbound bytes observed"),
        _FeatureSpec("inbound_bytes", "exfil", "entity_direction", "sum inbound bytes", "0 means no inbound bytes observed"),
        _FeatureSpec("outbound_rate", "exfil", "entity_direction", "outbound bytes / window seconds", "missing when window is invalid"),
        _FeatureSpec("inbound_rate", "exfil", "entity_direction", "inbound bytes / window seconds", "missing when window is invalid"),
        _FeatureSpec("upload_download_ratio", "exfil", "entity_direction", "outbound bytes / inbound bytes", "missing when inbound bytes are zero"),
        _FeatureSpec("large_flow_count", "exfil", "flow_state", "count flows above large-flow threshold", "0 means none observed"),
        _FeatureSpec("long_flow_count", "exfil", "flow_state", "count flows above long-flow threshold", "0 means none observed"),
        _FeatureSpec("destination_novelty", "exfil", "entity_history", "new destinations / unique destinations", "missing when no destinations observed"),
        _FeatureSpec("entity_flow_count", "entity", "entity_window", "count flows touching entity", "0 means no flows observed"),
        _FeatureSpec("entity_unique_destinations", "entity", "entity_window", "count unique destinations from entity", "0 means none observed"),
        _FeatureSpec("entity_new_destinations", "entity", "entity_history", "count new destinations for entity", "0 means none new"),
        _FeatureSpec("entity_avg_connection_interval", "entity", "event_time", "mean interval between entity flows in seconds", "missing when fewer than 2 events"),
        _FeatureSpec("entity_periodicity", "entity", "event_time", "periodicity score over entity flow intervals", "missing when unavailable"),
        _FeatureSpec("baseline_deviation", "entity", "entity_history", "absolute z-score of current flow count vs history", "missing until baseline exists"),
        _FeatureSpec("entity_packet_rate_z", "entity", "entity_baseline", "robust z-score of packet rate vs entity baseline", "missing until baseline exists"),
        _FeatureSpec("entity_outbound_rate_z", "entity", "entity_baseline", "robust z-score of outbound rate vs entity baseline", "missing until baseline exists"),
        _FeatureSpec("entity_dns_rate_z", "entity", "entity_baseline", "robust z-score of DNS query rate vs entity baseline", "missing until baseline exists"),
        _FeatureSpec("entity_port_novelty", "entity", "entity_history", "new ports / unique ports", "missing when no ports observed"),
        _FeatureSpec("entity_domain_novelty", "entity", "entity_history", "new domains / unique domains", "missing when no domains observed"),
        _FeatureSpec("entity_tls_novelty", "entity", "entity_history", "1.0 if new TLS fingerprint else 0.0", "missing when no TLS fingerprint observed"),
    )


FEATURE_SPECS = _specs()
CANONICAL_FEATURE_NAMES = tuple(spec.name for spec in FEATURE_SPECS)
CANONICAL_NUMERIC_FEATURE_NAMES = tuple(
    name for name in CANONICAL_FEATURE_NAMES
    if name not in {"tls_version", "ja3", "ja4", "sni", "alpn"}
)


class FeatureEngine:
    def __init__(
        self,
        windows_seconds: Iterable[int] = DEFAULT_WINDOWS_SECONDS,
        max_events: int = 50_000,
        large_flow_bytes: int = 1_000_000,
        long_flow_seconds: float = 60.0,
        max_history_values_per_entity: int = 4096,
    ):
        self.windows_seconds = tuple(int(w) for w in windows_seconds)
        self.max_window = max(self.windows_seconds)
        self.max_events = max_events
        self.large_flow_bytes = large_flow_bytes
        self.long_flow_seconds = long_flow_seconds
        self.max_history_values_per_entity = max_history_values_per_entity
        self.flow_manager = FlowManager()
        self.entity_memory = EntityMemory(max_entities=50_000, history_window_size=max_history_values_per_entity)
        self._events: deque[FlowEvent] = deque()
        self._seen_destinations: dict[str, set[str]] = defaultdict(set)
        self._seen_ports: dict[str, set[int]] = defaultdict(set)
        self._seen_destination_order: dict[str, deque[str]] = defaultdict(deque)
        self._seen_port_order: dict[str, deque[int]] = defaultdict(deque)
        self._fingerprints: dict[str, Counter[str]] = defaultdict(Counter)
        self._entity_flow_count_history: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=128))

    @property
    def schema_version(self) -> str:
        return FEATURE_SCHEMA_VERSION

    def schema(self) -> dict[str, FeatureMetadata]:
        return {
            spec.name: FeatureMetadata(
                name=spec.name,
                family=spec.family,
                source=spec.source,
                window="multi",
                calculation=spec.calculation,
                missing_data_policy=spec.missing_data_policy,
            )
            for spec in FEATURE_SPECS
        }

    def ingest_packet(self, packet: NormalizedPacket) -> FlowEvent:
        """Ingest a normalized packet and update streaming flow state without forcing feature extraction."""
        self.flow_manager.process_packet(packet)
        key = FlowKey(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        state = self.flow_manager.get_flow(key)
        if state is None:
            raise ValueError("Flow state unavailable after packet update")
        event = self._event_from_packet(packet, state)
        self._events.append(event)
        self._trim(packet.event_time)
        return event

    def update_packet(
        self,
        packet: NormalizedPacket,
    ) -> CanonicalFeatureSet:
        event = self.ingest_packet(packet)
        return self.extract(entity_id=event.entity_id, as_of_event_time=packet.event_time, update_history=True)

    def extract_from_events(
        self,
        events: Iterable[FlowEvent],
        entity_id: str | None = None,
        as_of_event_time: float | None = None,
        update_history: bool = False,
    ) -> CanonicalFeatureSet:
        event_list = sorted(list(events), key=_event_time)
        if not event_list:
            raise ValueError("Cannot extract canonical features from an empty event sequence")
        as_of = float(as_of_event_time if as_of_event_time is not None else max(_event_time(e) for e in event_list))
        ent = entity_id or event_list[-1].entity_id or canonical_entity_id(event_list[-1].src_ip, event_list[-1].sensor_id)
        return self._extract(event_list, ent, as_of, update_history=update_history)

    def extract(
        self,
        entity_id: str,
        as_of_event_time: float | None = None,
        update_history: bool = False,
    ) -> CanonicalFeatureSet:
        if not self._events:
            raise ValueError("Cannot extract canonical features before any events are observed")
        as_of = float(as_of_event_time if as_of_event_time is not None else max(_event_time(e) for e in self._events))
        return self._extract(list(self._events), entity_id, as_of, update_history=update_history)

    def project_legacy_ml_features(
        self,
        feature_set: CanonicalFeatureSet,
        feature_names: Iterable[str],
        window_seconds: int = 60,
        missing_value: float = -1.0,
    ) -> dict[str, float]:
        from features.feature_contract import ModelFeatureSchema, build_model_vector, legacy_model_schema

        base_schema = legacy_model_schema()
        schema = ModelFeatureSchema(
            schema_version=base_schema.schema_version,
            feature_names=tuple(feature_names),
            source_feature_schema_version=base_schema.source_feature_schema_version,
            missing_value=missing_value,
            model_window_seconds=window_seconds,
            normalization_policy=base_schema.normalization_policy,
        )
        vector = build_model_vector(feature_set, schema)
        return dict(zip(vector.feature_names, vector.values))

    def _extract(
        self,
        events: list[FlowEvent],
        entity_id: str,
        as_of: float,
        update_history: bool,
    ) -> CanonicalFeatureSet:
        features: dict[str, FeatureValue] = {}
        for window in self.windows_seconds:
            window_events = [
                e for e in events
                if as_of - window <= _event_time(e) <= as_of
                and _touches_entity(e, entity_id)
            ]
            self._extract_window(features, window_events, entity_id, window)
        if update_history:
            self._update_history(entity_id, events, as_of)
        return CanonicalFeatureSet(
            entity_id=entity_id,
            as_of_event_time=as_of,
            schema_version=FEATURE_SCHEMA_VERSION,
            windows=self.windows_seconds,
            features=features,
        )

    def _extract_window(
        self,
        out: dict[str, FeatureValue],
        events: list[FlowEvent],
        entity_id: str,
        window: int,
    ) -> None:
        spec_map = {spec.name: spec for spec in FEATURE_SPECS}
        values = self._calculate_values(events, entity_id, window)
        for name, value in values.items():
            spec = spec_map[name]
            missing_reason = _missing_reason(name, value, events)
            key = f"{window}s.{name}"
            out[key] = FeatureValue(
                name=key,
                value=value,
                metadata=FeatureMetadata(
                    name=key,
                    family=spec.family,
                    source=spec.source,
                    window=f"{window}s",
                    calculation=spec.calculation,
                    missing_data_policy=spec.missing_data_policy,
                ),
                missing_reason=missing_reason,
            )

    def _calculate_values(
        self,
        events: list[FlowEvent],
        entity_id: str,
        window: int,
    ) -> dict[str, Any]:
        entity_ip = _entity_ip(entity_id)
        total_packets = sum(e.packet_count for e in events)
        total_bytes = sum(e.byte_count for e in events)
        outbound = [e for e in events if e.src_ip == entity_ip or e.entity_id == entity_id]
        inbound = [e for e in events if e.dst_ip == entity_ip]
        packet_sizes = [size for e in events for size in e.packet_lengths]
        iats = _inter_arrival_ms(events)
        dns_meta = [_dns(e) for e in events if _dns(e) is not None]
        dns_names = [d.query_name for d in dns_meta if d.query_name]
        tls_like = [e for e in events if e.dst_port in {443, 8443} or e.src_port in {443, 8443} or _tls(e) or _quic(e)]
        tls_sizes = [size for e in tls_like for size in e.packet_lengths]
        tls_iats = _inter_arrival_ms(tls_like)
        dst_ips = [e.dst_ip for e in outbound]
        dst_ports = [e.dst_port for e in outbound]
        new_dests = {d for d in dst_ips if d not in self._seen_destinations[entity_id]}
        new_ports = {p for p in dst_ports if p not in self._seen_ports[entity_id]}
        fingerprint = _first_fingerprint(events)
        history = self._entity_flow_count_history[entity_id]
        baseline_deviation = None
        if len(history) >= 2:
            mean = sum(history) / len(history)
            std = pstdev(history)
            if std > 0:
                baseline_deviation = abs((len(events) - mean) / std)

        outbound_bytes = sum(e.byte_count for e in outbound)
        inbound_bytes = sum(e.byte_count for e in inbound)
        profile = self.entity_memory.get_or_create_profile(entity_id, event_time=window_events_as_of if 'window_events_as_of' in locals() else None)

        pps_val = total_packets / window if window > 0 else 0.0
        out_rate_val = outbound_bytes / window if window > 0 else 0.0
        dns_rate_val = len(dns_meta) / window if window > 0 else 0.0

        entity_packet_rate_z = (
            profile.compute_pps_z_score(pps_val)
            if (window > 0 and (profile.pps_baseline.count >= 2 or len(profile.pps_baseline.history) >= 2))
            else None
        )
        entity_outbound_rate_z = (
            profile.compute_outbound_rate_z_score(out_rate_val)
            if (window > 0 and (profile.outbound_rate_baseline.count >= 2 or len(profile.outbound_rate_baseline.history) >= 2))
            else None
        )
        entity_dns_rate_z = (
            profile.compute_dns_rate_z_score(dns_rate_val)
            if (window > 0 and (profile.dns_rate_baseline.count >= 2 or len(profile.dns_rate_baseline.history) >= 2))
            else None
        )
        new_domains = {d for d in dns_names if d not in profile.known_domains}
        entity_domain_novelty = _ratio(len(new_domains), len(set(dns_names))) if dns_names else None
        entity_port_novelty = _ratio(len(new_ports), len(set(dst_ports))) if dst_ports else None
        entity_tls_novelty = None if fingerprint is None else (1.0 if self._fingerprints[entity_id][fingerprint] == 0 else 0.0)

        values = {
            "duration": _duration(events),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "bytes_forward": outbound_bytes,
            "bytes_backward": inbound_bytes,
            "packets_forward": sum(e.packet_count for e in outbound),
            "packets_backward": sum(e.packet_count for e in inbound),
            "packets_per_sec": total_packets / window if window > 0 else None,
            "bytes_per_sec": total_bytes / window if window > 0 else None,
            "packet_size_mean": _mean(packet_sizes),
            "packet_size_std": _std(packet_sizes),
            "packet_size_min": min(packet_sizes) if packet_sizes else None,
            "packet_size_max": max(packet_sizes) if packet_sizes else None,
            "syn_ratio": _flag_ratio(events, "syn_count", total_packets),
            "ack_ratio": _flag_ratio(events, "ack_count", total_packets),
            "fin_ratio": _flag_ratio(events, "fin_count", total_packets),
            "rst_ratio": _flag_ratio(events, "rst_count", total_packets),
            "psh_ratio": _flag_ratio(events, "psh_count", total_packets),
            "urg_ratio": _flag_ratio(events, "urg_count", total_packets),
            "iat_mean": _mean(iats),
            "iat_std": _std(iats),
            "iat_median": median(iats) if iats else None,
            "iat_mad": _mad(iats),
            "iat_cv": _cv(iats),
            "periodicity_score": _periodicity(iats),
            "jitter": (_cv(iats) * 100.0) if _cv(iats) is not None else None,
            "burst_rate": _burst_rate(events, window),
            "autocorrelation": _autocorrelation(iats),
            "dns_query_count": len(dns_meta),
            "unique_domain_count": len(set(dns_names)),
            "unique_subdomain_count": sum(1 for name in set(dns_names) if _label_depth(name) > 2),
            "dns_query_rate": len(dns_meta) / window if window > 0 else None,
            "domain_length_mean": _mean([len(name) for name in dns_names]),
            "domain_length_p95": _percentile([len(name) for name in dns_names], 95),
            "domain_entropy": _mean([_entropy(name) for name in dns_names]),
            "character_diversity": _mean([len(set(name)) / len(name) for name in dns_names if name]),
            "digit_ratio": _mean([sum(ch.isdigit() for ch in name) / len(name) for name in dns_names if name]),
            "ngram_score": _ngram_score(dns_names),
            "nxdomain_ratio": _ratio(sum(1 for d in dns_meta if str(d.response_code).upper() == "NXDOMAIN"), len(dns_meta)),
            "txt_ratio": _ratio(sum(1 for d in dns_meta if str(d.query_type).upper() == "TXT"), len(dns_meta)),
            "label_depth_mean": _mean([_label_depth(name) for name in dns_names]),
            "tls_version": _first_attr(events, "tls_version"),
            "ja3": _first_attr(events, "ja3_hash"),
            "ja4": _first_attr(events, "ja4_hash"),
            "sni": _first_attr(events, "sni"),
            "alpn": _first_attr(events, "alpn"),
            "session_resumption": _first_attr(events, "session_resumption"),
            "tls_packet_size_mean": _mean(tls_sizes),
            "tls_packet_size_std": _std(tls_sizes),
            "tls_packet_size_min": min(tls_sizes) if tls_sizes else None,
            "tls_packet_size_max": max(tls_sizes) if tls_sizes else None,
            "tls_packet_size_sequence_mean_delta": _mean([abs(tls_sizes[i] - tls_sizes[i - 1]) for i in range(1, len(tls_sizes))]),
            "tls_timing_mean": _mean(tls_iats),
            "tls_fingerprint_novelty": None if fingerprint is None else int(self._fingerprints[entity_id][fingerprint] == 0),
            "tls_fingerprint_frequency": None if fingerprint is None else self._fingerprints[entity_id][fingerprint],
            "unique_dst_ips": len(set(dst_ips)),
            "unique_dst_ports": len(set(dst_ports)),
            "new_destinations": len(new_dests),
            "new_ports": len(new_ports),
            "connection_attempt_rate": len(outbound) / window if window > 0 else None,
            "failed_connection_ratio": _ratio(sum(_failed(e) for e in outbound), len(outbound)),
            "fan_out": _ratio(len(set(dst_ips)), len(outbound)),
            "destination_entropy": _entropy_counts(Counter(dst_ips)),
            "outbound_bytes": outbound_bytes,
            "inbound_bytes": inbound_bytes,
            "outbound_rate": outbound_bytes / window if window > 0 else None,
            "inbound_rate": inbound_bytes / window if window > 0 else None,
            "upload_download_ratio": _ratio(outbound_bytes, inbound_bytes),
            "large_flow_count": sum(e.byte_count >= self.large_flow_bytes for e in outbound),
            "long_flow_count": sum(e.duration >= self.long_flow_seconds for e in outbound),
            "destination_novelty": _ratio(len(new_dests), len(set(dst_ips))),
            "entity_flow_count": len(events),
            "entity_unique_destinations": len(set(dst_ips)),
            "entity_new_destinations": len(new_dests),
            "entity_avg_connection_interval": (_mean(iats) / 1000.0) if iats else None,
            "entity_periodicity": _periodicity(iats),
            "baseline_deviation": baseline_deviation,
            "entity_packet_rate_z": entity_packet_rate_z,
            "entity_outbound_rate_z": entity_outbound_rate_z,
            "entity_dns_rate_z": entity_dns_rate_z,
            "entity_port_novelty": entity_port_novelty,
            "entity_domain_novelty": entity_domain_novelty,
            "entity_tls_novelty": entity_tls_novelty,
        }
        return values

    def _update_history(self, entity_id: str, events: list[FlowEvent], as_of: float) -> None:
        sixty_second_events = [
            event for event in events
            if as_of - 60 <= _event_time(event) <= as_of
            and _touches_entity(event, entity_id)
        ]
        self._entity_flow_count_history[entity_id].append(len(sixty_second_events))
        profile = self.entity_memory.get_or_create_profile(entity_id, event_time=as_of)
        for event in events:
            if _touches_entity(event, entity_id):
                profile.update_from_flow(event)
            if event.src_ip == _entity_ip(entity_id) or event.entity_id == entity_id:
                self._remember_seen_value(
                    self._seen_destinations[entity_id],
                    self._seen_destination_order[entity_id],
                    event.dst_ip,
                )
                self._remember_seen_value(
                    self._seen_ports[entity_id],
                    self._seen_port_order[entity_id],
                    event.dst_port,
                )
            fingerprint = _first_fingerprint([event])
            if fingerprint is not None:
                self._fingerprints[entity_id][fingerprint] += 1

    def _trim(self, as_of: float) -> None:
        cutoff = as_of - self.max_window
        while self._events and _event_time(self._events[0]) < cutoff:
            self._events.popleft()
        while len(self._events) > self.max_events:
            self._events.popleft()

    def _remember_seen_value(
        self,
        values: set[Any],
        order: deque[Any],
        value: Any,
    ) -> None:
        if value in values:
            return
        values.add(value)
        order.append(value)
        while len(order) > self.max_history_values_per_entity:
            expired = order.popleft()
            values.discard(expired)

    @staticmethod
    def _event_from_packet(packet: NormalizedPacket, state: Any) -> FlowEvent:
        return FlowEvent(
            timestamp=packet.event_time,
            event_time=packet.event_time,
            ingest_time=packet.ingest_time,
            sensor_id=packet.sensor_id,
            flow_id=state.flow_id,
            conversation_id=state.conversation_id,
            entity_id=state.entity_id,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            packet_count=1,
            byte_count=packet.packet_length,
            duration=state.duration,
            packet_rate=state.packet_rate,
            byte_rate=state.byte_rate,
            syn_count=packet.tcp_syn,
            ack_count=packet.tcp_ack,
            fin_count=packet.tcp_fin,
            rst_count=packet.tcp_rst,
            psh_count=packet.tcp_psh,
            urg_count=packet.tcp_urg,
            syn_ratio=state.syn_ratio,
            ack_ratio=state.ack_ratio,
            fin_ratio=state.fin_ratio,
            rst_ratio=state.rst_ratio,
            packet_length_min=float(packet.packet_length),
            packet_length_max=float(packet.packet_length),
            packet_length_mean=float(packet.packet_length),
            packet_length_std=0.0,
            iat_min_ms=state.iat_min_ms,
            iat_max_ms=state.iat_max_ms,
            iat_mean_ms=state.iat_mean_ms,
            iat_std_ms=state.iat_std_ms,
            packet_lengths=(packet.packet_length,),
            inter_arrival_times_ms=(),
            dns=packet.dns,
            tls=packet.tls,
            quic=packet.quic,
        )

    @staticmethod
    def _event_from_state(state: Any) -> FlowEvent:
        start_iso = _timestamp_iso(state.start_time)
        end_iso = _timestamp_iso(state.last_seen)
        return FlowEvent(
            timestamp=state.last_seen,
            event_time=state.event_time,
            ingest_time=state.ingest_time,
            sensor_id=state.sensor_id,
            flow_id=state.flow_id,
            conversation_id=state.conversation_id,
            entity_id=state.entity_id,
            src_ip=state.key.src_ip,
            dst_ip=state.key.dst_ip,
            src_port=state.key.src_port,
            dst_port=state.key.dst_port,
            protocol=state.key.protocol,
            packet_count=state.packet_count,
            byte_count=state.byte_count,
            duration=state.duration,
            packet_rate=state.packet_rate,
            byte_rate=state.byte_rate,
            syn_count=state.syn_count,
            ack_count=state.ack_count,
            fin_count=state.fin_count,
            rst_count=state.rst_count,
            psh_count=state.psh_count,
            urg_count=state.urg_count,
            syn_ratio=state.syn_ratio,
            ack_ratio=state.ack_ratio,
            fin_ratio=state.fin_ratio,
            rst_ratio=state.rst_ratio,
            packet_length_min=state.packet_length_min,
            packet_length_max=state.packet_length_max,
            packet_length_mean=state.packet_length_mean,
            packet_length_std=state.packet_length_std,
            iat_min_ms=state.iat_min_ms,
            iat_max_ms=state.iat_max_ms,
            iat_mean_ms=state.iat_mean_ms,
            iat_std_ms=state.iat_std_ms,
            packet_lengths=tuple(state.packet_lengths),
            inter_arrival_times_ms=tuple(state.inter_arrival_times_ms),
            dns=state.dns,
            tls=state.tls,
            quic=state.quic,
        )


def _event_time(event: FlowEvent) -> float:
    return float(event.event_time if event.event_time is not None else event.timestamp)


def _timestamp_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _entity_ip(entity_id: str) -> str:
    if ":" in entity_id:
        _, possible_ip = entity_id.split(":", 1)
        if "." in possible_ip:
            return possible_ip
    return entity_id


def _touches_entity(event: FlowEvent, entity_id: str) -> bool:
    entity_ip = _entity_ip(entity_id)
    return event.entity_id == entity_id or event.src_ip == entity_ip or event.dst_ip == entity_ip


def _duration(events: list[FlowEvent]) -> float:
    if not events:
        return 0.0
    starts = [_event_time(e) - e.duration for e in events]
    ends = [_event_time(e) for e in events]
    return max(0.0, max(ends) - min(starts))


def _mean(values: list[float | int]) -> float | None:
    return sum(values) / len(values) if values else None


def _std(values: list[float | int]) -> float | None:
    return pstdev(values) if values else None


def _mad(values: list[float]) -> float | None:
    if not values:
        return None
    center = median(values)
    return median([abs(value - center) for value in values])


def _cv(values: list[float]) -> float | None:
    mean = _mean(values)
    std = _std(values)
    if mean is None or std is None or mean == 0:
        return None
    return std / mean


def _periodicity(values: list[float]) -> float | None:
    cv = _cv(values)
    if cv is None:
        return None
    return max(0.0, 1.0 - min(1.0, cv))


def _autocorrelation(values: list[float]) -> float | None:
    if len(values) < 3:
        return None
    x = values[:-1]
    y = values[1:]
    x_mean = _mean(x)
    y_mean = _mean(y)
    if x_mean is None or y_mean is None:
        return None
    numerator = sum((a - x_mean) * (b - y_mean) for a, b in zip(x, y))
    denom_x = math.sqrt(sum((a - x_mean) ** 2 for a in x))
    denom_y = math.sqrt(sum((b - y_mean) ** 2 for b in y))
    if denom_x == 0 or denom_y == 0:
        return None
    return numerator / (denom_x * denom_y)


def _inter_arrival_ms(events: list[FlowEvent]) -> list[float]:
    timestamps = sorted(_event_time(e) for e in events)
    return [
        max(0.0, (timestamps[index] - timestamps[index - 1]) * 1000.0)
        for index in range(1, len(timestamps))
    ]


def _flag_ratio(events: list[FlowEvent], attr: str, total_packets: int) -> float | None:
    if total_packets <= 0:
        return None
    return sum(getattr(e, attr) for e in events) / float(total_packets)


def _ratio(numerator: float | int, denominator: float | int) -> float | None:
    if denominator == 0:
        return None
    return numerator / float(denominator)


def _burst_rate(events: list[FlowEvent], window: int) -> float:
    if not events or window <= 0:
        return 0.0
    buckets = Counter(int(_event_time(e)) for e in events)
    return max(buckets.values(), default=0) / float(window)


def _dns(event: FlowEvent) -> DNSMetadata | None:
    return event.dns


def _tls(event: FlowEvent) -> TLSMetadata | None:
    return event.tls


def _quic(event: FlowEvent) -> QUICMetadata | None:
    return event.quic


def _first_attr(events: list[FlowEvent], attr: str) -> Any:
    for event in events:
        for meta in (_tls(event), _quic(event)):
            if meta is None:
                continue
            value = getattr(meta, attr, None)
            if value not in (None, ""):
                return value
    return None


def _first_fingerprint(events: list[FlowEvent]) -> str | None:
    for event in events:
        ja4 = _first_attr([event], "ja4_hash")
        ja3 = _first_attr([event], "ja3_hash")
        if ja4:
            return f"ja4:{ja4}"
        if ja3:
            return f"ja3:{ja3}"
    return None


def _failed(event: FlowEvent) -> bool:
    return (
        event.byte_count == 0
        or (
            event.protocol == 6
            and event.syn_count > 0
            and event.ack_count == 0
            and event.packet_count <= 1
        )
        or (
            event.protocol == 6
            and event.rst_count > 0
            and event.byte_count < 64
        )
    )


def _entropy(text: str) -> float:
    counts = Counter(text)
    length = len(text)
    if length == 0:
        return 0.0
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _entropy_counts(counts: Counter[Any]) -> float | None:
    total = sum(counts.values())
    if total == 0:
        return None
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _label_depth(name: str) -> int:
    return len([part for part in name.split(".") if part])


def _percentile(values: list[int], percentile: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, math.ceil((percentile / 100.0) * len(ordered)) - 1)
    return float(ordered[index])


def _ngram_score(names: list[str]) -> float | None:
    if not names:
        return None
    entropy_score = _mean([_entropy(name) / 6.0 for name in names]) or 0.0
    digit_score = _mean([sum(ch.isdigit() for ch in name) / len(name) for name in names if name]) or 0.0
    return max(0.0, min(1.0, (entropy_score + digit_score) / 2.0))


def _missing_reason(name: str, value: Any, events: list[FlowEvent]) -> str | None:
    if not events:
        return "not_yet_observable"
    if value is not None:
        return None
    dns_observations = [_dns(event) for event in events if _dns(event) is not None]
    dns_names = [metadata.query_name for metadata in dns_observations if metadata.query_name]
    if name.startswith("iat") or name in {"periodicity_score", "jitter", "autocorrelation", "entity_avg_connection_interval", "entity_periodicity"}:
        return "insufficient_event_time_observations"
    if name.startswith("domain") or name in {"character_diversity", "digit_ratio", "ngram_score", "label_depth_mean", "nxdomain_ratio", "txt_ratio"}:
        if dns_observations and not dns_names and name not in {"nxdomain_ratio", "txt_ratio"}:
            return "dns_query_name_unavailable"
        return "dns_metadata_unavailable"
    if name.startswith("tls") or name in {"ja3", "ja4", "sni", "alpn", "session_resumption"}:
        return "tls_quic_metadata_unavailable"
    if name in {"upload_download_ratio"}:
        return "inbound_bytes_zero"
    if name in {"destination_novelty", "destination_entropy", "fan_out", "failed_connection_ratio"}:
        return "insufficient_destination_observations"
    if name in {"entity_packet_rate_z", "entity_outbound_rate_z", "entity_dns_rate_z", "baseline_deviation"}:
        return "insufficient_entity_baseline"
    if name in {"entity_port_novelty"}:
        return "insufficient_port_observations"
    if name in {"entity_domain_novelty"}:
        return "insufficient_domain_observations"
    if name in {"entity_tls_novelty"}:
        return "tls_quic_metadata_unavailable"
    return "unavailable"

