import os
import tempfile

import pytest

from features.feature_contract import (
    LEGACY_MODEL_ARTIFACT_SCHEMA_VERSION,
    LEGACY_MODEL_FEATURE_NAMES,
    MODEL_FEATURE_SCHEMA_VERSION,
    MODEL_MISSING_VALUE,
    build_model_vector,
    canonical_name_for_legacy_feature,
    canonical_feature_schema,
    check_model_feature_compatibility,
    legacy_model_schema,
    validate_feature_schema,
)
from features.feature_engine import FEATURE_SCHEMA_VERSION, FeatureEngine
from ingest.pcap_reader import iter_pcap
from models.inference.ml_inference import MLInferenceEngine
from models.inference.signal_adapter import FeatureVectorAdapter
from schemas.telemetry import TLSMetadata
from tests.test_feature_engine import make_flow
from tests.test_pcap_reader import (
    _dns_query_payload,
    _ethernet,
    _ipv4,
    _pcap_bytes,
    _tcp,
    _tls_client_hello_payload,
    _udp,
)


def _write_temp_pcap(frames):
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        handle.write(_pcap_bytes(frames))
        return handle.name
    finally:
        handle.close()


def _feature_snapshot_from_pcap(path, limit=None):
    engine = FeatureEngine()
    latest = None
    for index, packet in enumerate(iter_pcap(path)):
        if limit is not None and index >= limit:
            break
        latest = engine.update_packet(packet)
    assert latest is not None
    return latest


def test_canonical_feature_schema_contains_versioned_metadata_for_every_window():
    schema = canonical_feature_schema()

    assert schema.schema_version == FEATURE_SCHEMA_VERSION
    assert len(schema.features) == len(FeatureEngine().schema()) * 6
    assert {"1s", "5s", "15s", "30s", "60s", "300s"} == {feature.window for feature in schema.features}
    sample = next(feature for feature in schema.features if feature.canonical_name == "60s.dns_query_count")
    assert sample.family == "DNS"
    assert sample.datatype == "integer"
    assert sample.availability_policy
    assert sample.normalization_policy
    assert sample.schema_version == FEATURE_SCHEMA_VERSION


def test_legacy_model_schema_is_the_only_source_of_ml_feature_ordering():
    schema = legacy_model_schema()

    assert schema.schema_version == MODEL_FEATURE_SCHEMA_VERSION
    assert schema.feature_names == LEGACY_MODEL_FEATURE_NAMES
    assert len(schema.feature_names) == 52


def test_build_model_vector_preserves_order_and_missingness_from_feature_engine():
    snapshot = FeatureEngine().extract_from_events(
        [make_flow(100.0)],
        entity_id="10.0.0.1",
        as_of_event_time=100.0,
    )

    vector = build_model_vector(snapshot)

    assert vector.feature_names == LEGACY_MODEL_FEATURE_NAMES
    assert vector.values.shape == (52,)
    assert vector.values[0] == 1.0
    assert vector.values[1] == 10.0
    assert vector.values[15] == MODEL_MISSING_VALUE
    assert vector.availability_mask[15] is False
    assert vector.missing_reasons["domain_length_mean"] == "dns_metadata_unavailable"


def test_training_and_inference_wrappers_use_identical_vector_semantics():
    snapshot = FeatureEngine().extract_from_events(
        [make_flow(100.0)],
        entity_id="10.0.0.1",
        as_of_event_time=100.0,
    )

    training_vector = build_model_vector(snapshot)
    inference_vector = build_model_vector(snapshot)
    adapter_vector = FeatureVectorAdapter.dict_to_features(snapshot.values())

    assert training_vector.feature_names == inference_vector.feature_names
    assert training_vector.values.tolist() == inference_vector.values.tolist()
    assert training_vector.missing_reasons == inference_vector.missing_reasons
    assert adapter_vector.tolist()[0] == inference_vector.values.tolist()


def test_feature_drift_validation_fails_for_missing_unexpected_reordered_and_version():
    missing_report = validate_feature_schema(LEGACY_MODEL_FEATURE_NAMES[:-1])
    assert not missing_report.ok
    assert missing_report.missing == ("tls_version_TLS1.3",)

    unexpected = list(LEGACY_MODEL_FEATURE_NAMES[:-1]) + ["extra"]
    unexpected_report = validate_feature_schema(unexpected)
    assert not unexpected_report.ok
    assert unexpected_report.unexpected == ("extra",)

    reordered = list(LEGACY_MODEL_FEATURE_NAMES)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    reordered_report = validate_feature_schema(reordered)
    assert not reordered_report.ok
    assert reordered_report.reordered is True

    version_report = validate_feature_schema(
        LEGACY_MODEL_FEATURE_NAMES,
        actual_schema_version="wrong-version",
        expected_schema_version=MODEL_FEATURE_SCHEMA_VERSION,
    )
    assert not version_report.ok
    assert "wrong-version" in version_report.version_mismatch


def test_model_metadata_compatibility_marks_saved_artifacts_as_legacy_adapter_only():
    metadata = {
        "feature_schema_version": LEGACY_MODEL_ARTIFACT_SCHEMA_VERSION,
        "model_version": "m12-legacy",
        "compatibility_status": "legacy_adapter_required",
        "feature_names": list(LEGACY_MODEL_FEATURE_NAMES),
    }

    check_model_feature_compatibility(metadata, allow_legacy_adapter=True)
    with pytest.raises(ValueError, match="schema version mismatch"):
        check_model_feature_compatibility(metadata, allow_legacy_adapter=False)


def test_legacy_mapping_is_explicit_for_known_fields():
    assert canonical_name_for_legacy_feature("duration") == "duration"
    assert canonical_name_for_legacy_feature("destination_count") == "entity_unique_destinations"
    assert canonical_name_for_legacy_feature("ja3_JA3_A") == "ja3"


def test_legacy_mapping_rejects_unknown_fields():
    with pytest.raises(KeyError, match="Unknown legacy model feature"):
        canonical_name_for_legacy_feature("ja3_JA3_Z")


def test_legacy_mapping_rejects_conflicting_dict_fields():
    with pytest.raises(ValueError, match="Conflicting legacy and canonical values"):
        build_model_vector({"duration": 10.0, "60s.duration": 11.0})

    with pytest.raises(ValueError, match="Conflicting legacy and canonical values"):
        build_model_vector({"ja3_JA3_A": 1.0, "60s.ja3": "JA3_B"})


def test_missing_required_feature_schema_field_fails_validation():
    report = validate_feature_schema(
        [name for name in LEGACY_MODEL_FEATURE_NAMES if name != "total_packets"]
    )

    assert not report.ok
    assert report.missing == ("total_packets",)


def test_unknown_ja4_is_not_forced_into_known_category():
    snapshot = FeatureEngine().extract_from_events(
        [
            make_flow(
                100.0,
                tls=TLSMetadata(ja4_hash="JA4_PREVIOUSLY_UNSEEN", tls_version="TLS1.3"),
            )
        ],
        entity_id="10.0.0.1",
        as_of_event_time=100.0,
    )

    vector = build_model_vector(snapshot)
    values = dict(zip(vector.feature_names, vector.values))

    assert snapshot.values()["60s.ja4"] == "JA4_PREVIOUSLY_UNSEEN"
    assert values["ja4_JA4_A"] == 0.0
    assert values["ja4_JA4_SUS_3"] == 0.0
    assert values["tls_version_TLS1.3"] == 1.0


def test_real_observation_round_trip_dns_tls_recon_exfil_to_model_vector_and_inference_validation():
    engine = MLInferenceEngine(artifact_dir="models/artifacts")
    dns_path = _write_temp_pcap([
        _ethernet(0x0800, _ipv4(17, _udp(payload=_dns_query_payload("a1b2c3.example.test"))))
    ])
    tls_path = _write_temp_pcap([
        _ethernet(0x0800, _ipv4(6, _tcp(flags=0x18, payload=_tls_client_hello_payload())))
    ])
    try:
        snapshots = [
            _feature_snapshot_from_pcap(dns_path),
            _feature_snapshot_from_pcap(tls_path),
            _feature_snapshot_from_pcap("dataset/pcaps/recon/horizontal_vertical_port_scan.pcap", limit=40),
            _feature_snapshot_from_pcap("dataset/pcaps/exfiltration/outbound_bulk_exfil_burst.pcap", limit=80),
        ]
    finally:
        os.unlink(dns_path)
        os.unlink(tls_path)

    vectors = [build_model_vector(snapshot) for snapshot in snapshots]
    for vector in vectors:
        validated = engine.validate_features(vector)
        assert validated.shape == (1, 52)
        assert vector.feature_names == tuple(engine.feature_names)

    dns_values = dict(zip(vectors[0].feature_names, vectors[0].values))
    tls_values = dict(zip(vectors[1].feature_names, vectors[1].values))
    recon_values = dict(zip(vectors[2].feature_names, vectors[2].values))
    exfil_values = dict(zip(vectors[3].feature_names, vectors[3].values))

    assert dns_values["dns_query_count"] == 1.0
    assert dns_values["domain_entropy"] > 0
    assert tls_values["tls_version_TLS1.2"] == 1.0
    assert recon_values["unique_dst_ports"] >= 40.0
    assert exfil_values["outbound_rate"] > 0
    assert vectors[3].missing_reasons["upload_download_ratio"] == "inbound_bytes_zero"
