from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

import numpy as np

from features.feature_engine import (
    DEFAULT_WINDOWS_SECONDS,
    FEATURE_SCHEMA_VERSION,
    FEATURE_SPECS,
    CanonicalFeatureSet,
)


MODEL_FEATURE_SCHEMA_VERSION = "legacy-52-from-feature-schema-v2.0.0"
LEGACY_MODEL_ARTIFACT_SCHEMA_VERSION = "legacy-52-v1"
MODEL_MISSING_VALUE = -1.0
MODEL_WINDOW_SECONDS = 60


LEGACY_MODEL_FEATURE_NAMES: tuple[str, ...] = (
    "duration",
    "total_packets",
    "total_bytes",
    "bytes_forward",
    "bytes_backward",
    "packets_per_sec",
    "bytes_per_sec",
    "packet_size_mean",
    "iat_mean",
    "iat_std",
    "periodicity_score",
    "jitter",
    "burst_rate",
    "dns_query_count",
    "unique_domain_count",
    "domain_length_mean",
    "domain_entropy",
    "ngram_score",
    "dns_query_rate",
    "session_resumption",
    "tls_packet_size_mean",
    "unique_dst_ips",
    "unique_dst_ports",
    "connection_attempt_rate",
    "failed_connection_ratio",
    "fan_out",
    "outbound_bytes",
    "outbound_rate",
    "upload_download_ratio",
    "destination_count",
    "large_transfer_score",
    "entity_flow_count_1m",
    "entity_unique_destinations_1m",
    "entity_new_destinations_5m",
    "entity_avg_connection_interval",
    "entity_periodicity",
    "ja3_JA3_A",
    "ja3_JA3_B",
    "ja3_JA3_C",
    "ja3_JA3_D",
    "ja3_JA3_E",
    "ja4_JA4_A",
    "ja4_JA4_B",
    "ja4_JA4_C",
    "ja4_JA4_D",
    "ja4_JA4_E",
    "ja4_JA4_SUS_1",
    "ja4_JA4_SUS_2",
    "ja4_JA4_SUS_3",
    "tls_version_NONE",
    "tls_version_TLS1.2",
    "tls_version_TLS1.3",
)


LEGACY_TO_CANONICAL_SOURCE: dict[str, str] = {
    "duration": "duration",
    "total_packets": "total_packets",
    "total_bytes": "total_bytes",
    "bytes_forward": "bytes_forward",
    "bytes_backward": "bytes_backward",
    "packets_per_sec": "packets_per_sec",
    "bytes_per_sec": "bytes_per_sec",
    "packet_size_mean": "packet_size_mean",
    "iat_mean": "iat_mean",
    "iat_std": "iat_std",
    "periodicity_score": "periodicity_score",
    "jitter": "jitter",
    "burst_rate": "burst_rate",
    "dns_query_count": "dns_query_count",
    "unique_domain_count": "unique_domain_count",
    "domain_length_mean": "domain_length_mean",
    "domain_entropy": "domain_entropy",
    "ngram_score": "ngram_score",
    "dns_query_rate": "dns_query_rate",
    "session_resumption": "session_resumption",
    "tls_packet_size_mean": "tls_packet_size_mean",
    "unique_dst_ips": "unique_dst_ips",
    "unique_dst_ports": "unique_dst_ports",
    "connection_attempt_rate": "connection_attempt_rate",
    "failed_connection_ratio": "failed_connection_ratio",
    "fan_out": "fan_out",
    "outbound_bytes": "outbound_bytes",
    "outbound_rate": "outbound_rate",
    "upload_download_ratio": "upload_download_ratio",
    "destination_count": "entity_unique_destinations",
    "large_transfer_score": "large_flow_count",
    "entity_flow_count_1m": "entity_flow_count",
    "entity_unique_destinations_1m": "entity_unique_destinations",
    "entity_new_destinations_5m": "entity_new_destinations",
    "entity_avg_connection_interval": "entity_avg_connection_interval",
    "entity_periodicity": "entity_periodicity",
    "ja3_JA3_A": "ja3",
    "ja3_JA3_B": "ja3",
    "ja3_JA3_C": "ja3",
    "ja3_JA3_D": "ja3",
    "ja3_JA3_E": "ja3",
    "ja4_JA4_A": "ja4",
    "ja4_JA4_B": "ja4",
    "ja4_JA4_C": "ja4",
    "ja4_JA4_D": "ja4",
    "ja4_JA4_E": "ja4",
    "ja4_JA4_SUS_1": "ja4",
    "ja4_JA4_SUS_2": "ja4",
    "ja4_JA4_SUS_3": "ja4",
    "tls_version_NONE": "tls_version",
    "tls_version_TLS1.2": "tls_version",
    "tls_version_TLS1.3": "tls_version",
}

if set(LEGACY_TO_CANONICAL_SOURCE) != set(LEGACY_MODEL_FEATURE_NAMES):
    raise RuntimeError("Legacy-to-canonical mapping must cover every model feature exactly once")


@dataclass(frozen=True)
class FeatureContractEntry:
    canonical_name: str
    family: str
    datatype: str
    source: str
    window: str
    calculation: str
    availability_policy: str
    normalization_policy: str
    model_input: bool
    schema_version: str = FEATURE_SCHEMA_VERSION
    model_feature_name: str | None = None


@dataclass(frozen=True)
class FeatureSchema:
    schema_version: str
    features: tuple[FeatureContractEntry, ...]

    @property
    def feature_names(self) -> tuple[str, ...]:
        return tuple(feature.canonical_name for feature in self.features)

    @property
    def model_feature_names(self) -> tuple[str, ...]:
        return tuple(
            feature.model_feature_name or feature.canonical_name
            for feature in self.features
            if feature.model_input
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "features": [asdict(feature) for feature in self.features],
        }


@dataclass(frozen=True)
class ModelFeatureSchema:
    schema_version: str
    feature_names: tuple[str, ...]
    source_feature_schema_version: str
    missing_value: float = MODEL_MISSING_VALUE
    model_window_seconds: int = MODEL_WINDOW_SECONDS
    normalization_policy: str = (
        "Numeric missing values are encoded with documented sentinel -1.0; "
        "availability_mask and missing_reasons preserve original semantics. "
        "High-cardinality fingerprints use explicit known-category indicators "
        "plus frequency/novelty canonical features."
    )


@dataclass(frozen=True)
class ModelVector:
    values: np.ndarray
    feature_names: tuple[str, ...]
    availability_mask: tuple[bool, ...]
    missing_reasons: dict[str, str]
    schema_version: str
    feature_schema_version: str

    def as_2d_array(self) -> np.ndarray:
        return self.values.reshape(1, -1)


@dataclass(frozen=True)
class FeatureDriftReport:
    ok: bool
    missing: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()
    reordered: bool = False
    datatype_mismatch: dict[str, str] | None = None
    version_mismatch: str | None = None

    def raise_for_error(self) -> None:
        if self.ok:
            return
        parts = [
            f"missing={list(self.missing)}",
            f"unexpected={list(self.unexpected)}",
            f"reordered={self.reordered}",
        ]
        if self.datatype_mismatch:
            parts.append(f"datatype_mismatch={self.datatype_mismatch}")
        if self.version_mismatch:
            parts.append(f"version_mismatch={self.version_mismatch}")
        raise ValueError("Feature schema drift detected: " + ", ".join(parts))


def canonical_feature_schema() -> FeatureSchema:
    entries = []
    specs = {spec.name: spec for spec in FEATURE_SPECS}
    model_inputs = {_canonical_source_name(name) for name in LEGACY_MODEL_FEATURE_NAMES}
    for window in DEFAULT_WINDOWS_SECONDS:
        for spec in FEATURE_SPECS:
            canonical_name = f"{window}s.{spec.name}"
            entries.append(
                FeatureContractEntry(
                    canonical_name=canonical_name,
                    family=spec.family.upper(),
                    datatype=_datatype_for_feature(spec.name),
                    source=spec.source,
                    window=f"{window}s",
                    calculation=spec.calculation,
                    availability_policy=spec.missing_data_policy,
                    normalization_policy=_normalization_policy(spec.name),
                    model_input=window == MODEL_WINDOW_SECONDS and spec.name in model_inputs,
                    model_feature_name=_model_feature_name_for(spec.name) if window == MODEL_WINDOW_SECONDS else None,
                )
            )
    return FeatureSchema(schema_version=FEATURE_SCHEMA_VERSION, features=tuple(entries))


def legacy_model_schema() -> ModelFeatureSchema:
    return ModelFeatureSchema(
        schema_version=MODEL_FEATURE_SCHEMA_VERSION,
        feature_names=LEGACY_MODEL_FEATURE_NAMES,
        source_feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def build_model_vector(
    feature_snapshot: CanonicalFeatureSet | dict[str, Any],
    model_schema: ModelFeatureSchema | None = None,
) -> ModelVector:
    schema = model_schema or legacy_model_schema()
    values = []
    availability = []
    missing_reasons: dict[str, str] = {}

    for model_name in schema.feature_names:
        value, reason = _model_value_and_reason(feature_snapshot, model_name, schema.model_window_seconds)
        if value is None:
            values.append(schema.missing_value)
            availability.append(False)
            missing_reasons[model_name] = reason or "unavailable"
        else:
            values.append(float(value))
            availability.append(True)

    return ModelVector(
        values=np.asarray(values, dtype=np.float64),
        feature_names=schema.feature_names,
        availability_mask=tuple(availability),
        missing_reasons=missing_reasons,
        schema_version=schema.schema_version,
        feature_schema_version=_snapshot_schema_version(feature_snapshot),
    )


def validate_feature_schema(
    actual_feature_names: Iterable[str],
    expected_feature_names: Iterable[str] | None = None,
    actual_schema_version: str | None = None,
    expected_schema_version: str = MODEL_FEATURE_SCHEMA_VERSION,
    actual_datatypes: dict[str, str] | None = None,
    expected_datatypes: dict[str, str] | None = None,
) -> FeatureDriftReport:
    actual = tuple(actual_feature_names)
    expected = tuple(expected_feature_names or LEGACY_MODEL_FEATURE_NAMES)
    missing = tuple(name for name in expected if name not in actual)
    unexpected = tuple(name for name in actual if name not in expected)
    reordered = not missing and not unexpected and actual != expected
    datatype_mismatch = {}
    if actual_datatypes and expected_datatypes:
        for name in expected:
            if name in actual_datatypes and actual_datatypes[name] != expected_datatypes.get(name):
                datatype_mismatch[name] = f"expected {expected_datatypes.get(name)}, got {actual_datatypes[name]}"
    version_mismatch = None
    if actual_schema_version is not None and actual_schema_version != expected_schema_version:
        version_mismatch = f"expected {expected_schema_version}, got {actual_schema_version}"
    report = FeatureDriftReport(
        ok=not missing and not unexpected and not reordered and not datatype_mismatch and version_mismatch is None,
        missing=missing,
        unexpected=unexpected,
        reordered=reordered,
        datatype_mismatch=datatype_mismatch or None,
        version_mismatch=version_mismatch,
    )
    return report


def check_model_feature_compatibility(
    model_metadata: dict[str, Any] | None,
    model_schema: ModelFeatureSchema | None = None,
    allow_legacy_adapter: bool = True,
) -> None:
    schema = model_schema or legacy_model_schema()
    metadata = model_metadata or {}
    for required in ("model_version", "feature_schema_version", "compatibility_status"):
        if required not in metadata:
            raise ValueError(f"Model metadata missing required field: {required}")
    artifact_schema_version = metadata.get("feature_schema_version", LEGACY_MODEL_ARTIFACT_SCHEMA_VERSION)
    feature_names = tuple(metadata.get("feature_names", ()))

    if artifact_schema_version != schema.schema_version and not allow_legacy_adapter:
        raise ValueError(
            "Model feature schema version mismatch: "
            f"model={artifact_schema_version}, vector={schema.schema_version}"
        )
    if artifact_schema_version != schema.schema_version and metadata.get("compatibility_status") != "legacy_adapter_required":
        raise ValueError(
            "Model feature schema version mismatch requires compatibility_status='legacy_adapter_required': "
            f"model={artifact_schema_version}, vector={schema.schema_version}"
        )

    if feature_names:
        validate_feature_schema(feature_names, schema.feature_names).raise_for_error()


def canonical_name_for_legacy_feature(legacy_name: str) -> str:
    """Return the explicitly declared canonical source for a legacy model feature."""
    try:
        return LEGACY_TO_CANONICAL_SOURCE[legacy_name]
    except KeyError as exc:
        raise KeyError(f"Unknown legacy model feature: {legacy_name}") from exc


def _model_value_and_reason(
    feature_snapshot: CanonicalFeatureSet | dict[str, Any],
    model_name: str,
    window: int,
) -> tuple[float | int | bool | None, str | None]:
    if not isinstance(feature_snapshot, CanonicalFeatureSet) and model_name in feature_snapshot:
        _validate_legacy_dict_conflict(feature_snapshot, model_name, window)
        return feature_snapshot[model_name], _snapshot_missing_reason(feature_snapshot, model_name)
    if model_name.startswith("ja3_"):
        return _fingerprint_indicator(feature_snapshot, model_name, "ja3", window)
    if model_name.startswith("ja4_"):
        return _fingerprint_indicator(feature_snapshot, model_name, "ja4", window)
    if model_name.startswith("tls_version_"):
        return _tls_version_indicator(feature_snapshot, model_name, window)

    source = _canonical_source_name(model_name)
    key = f"{window}s.{source}"
    value = _snapshot_value(feature_snapshot, key)
    reason = _snapshot_missing_reason(feature_snapshot, key)
    if value is None and not isinstance(feature_snapshot, CanonicalFeatureSet):
        value = _snapshot_value(feature_snapshot, source)
        reason = _snapshot_missing_reason(feature_snapshot, source)
    return value, reason


def _fingerprint_indicator(
    feature_snapshot: CanonicalFeatureSet | dict[str, Any],
    model_name: str,
    canonical_name: str,
    window: int,
) -> tuple[float | None, str | None]:
    key = f"{window}s.{canonical_name}"
    value = _snapshot_value(feature_snapshot, key)
    if value is None:
        return None, _snapshot_missing_reason(feature_snapshot, key)
    expected = model_name.split("_", 1)[1]
    return (1.0 if str(value) == expected else 0.0), None


def _tls_version_indicator(
    feature_snapshot: CanonicalFeatureSet | dict[str, Any],
    model_name: str,
    window: int,
) -> tuple[float | None, str | None]:
    key = f"{window}s.tls_version"
    value = _snapshot_value(feature_snapshot, key)
    expected = model_name.removeprefix("tls_version_")
    if expected == "NONE":
        return (1.0 if value is None else 0.0), None
    if value is None:
        return None, _snapshot_missing_reason(feature_snapshot, key)
    return (1.0 if str(value) == expected else 0.0), None


def _canonical_source_name(model_name: str) -> str:
    return canonical_name_for_legacy_feature(model_name)


def _model_feature_name_for(canonical_name: str) -> str | None:
    for model_name in LEGACY_MODEL_FEATURE_NAMES:
        if _canonical_source_name(model_name) == canonical_name:
            return model_name
    return None


def _validate_legacy_dict_conflict(data: dict[str, Any], model_name: str, window: int) -> None:
    source = canonical_name_for_legacy_feature(model_name)
    canonical_keys = (f"{window}s.{source}", source)
    present_key = next((key for key in canonical_keys if key in data), None)
    if present_key is None:
        return

    direct_value = data[model_name]
    canonical_value = data[present_key]
    if direct_value is None or canonical_value is None:
        return

    if model_name.startswith(("ja3_", "ja4_", "tls_version_")):
        expected = (
            model_name.split("_", 1)[1]
            if model_name.startswith(("ja3_", "ja4_"))
            else model_name.removeprefix("tls_version_")
        )
        implied = 1.0 if str(canonical_value) == expected else 0.0
        if float(direct_value) != implied:
            raise ValueError(
                f"Conflicting legacy and canonical values for {model_name}: "
                f"{direct_value!r} vs {present_key}={canonical_value!r}"
            )
        return

    if float(direct_value) != float(canonical_value):
        raise ValueError(
            f"Conflicting legacy and canonical values for {model_name}: "
            f"{direct_value!r} vs {present_key}={canonical_value!r}"
        )


def _snapshot_schema_version(feature_snapshot: CanonicalFeatureSet | dict[str, Any]) -> str:
    if isinstance(feature_snapshot, CanonicalFeatureSet):
        return feature_snapshot.schema_version
    return str(feature_snapshot.get("schema_version", FEATURE_SCHEMA_VERSION))


def _snapshot_value(feature_snapshot: CanonicalFeatureSet | dict[str, Any], key: str) -> Any:
    if isinstance(feature_snapshot, CanonicalFeatureSet):
        item = feature_snapshot.features.get(key)
        return item.value if item is not None else None
    return feature_snapshot.get(key)


def _snapshot_missing_reason(feature_snapshot: CanonicalFeatureSet | dict[str, Any], key: str) -> str | None:
    if isinstance(feature_snapshot, CanonicalFeatureSet):
        item = feature_snapshot.features.get(key)
        return item.missing_reason if item is not None else "missing_feature"
    missing = feature_snapshot.get("missing_reasons", {})
    if isinstance(missing, dict):
        return missing.get(key)
    return None


def _datatype_for_feature(name: str) -> str:
    if name in {"tls_version", "ja3", "ja4", "sni", "alpn"}:
        return "string"
    if name == "session_resumption":
        return "boolean"
    if name.endswith("_count") or name in {"total_packets", "unique_dst_ips", "unique_dst_ports", "new_destinations", "new_ports"}:
        return "integer"
    return "float"


def _normalization_policy(name: str) -> str:
    if name in {"ja3", "ja4"}:
        return "Preserve raw fingerprint; ML uses known-category indicator plus frequency/novelty features."
    if name in {"tls_version", "sni", "alpn"}:
        return "Preserve raw string for evidence; model input uses explicit derived indicators where defined."
    return "No in-engine scaling; missing numeric model inputs use documented sentinel with availability mask."
