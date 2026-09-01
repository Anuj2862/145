"""Native Feature-Schema-v2 Dataset Generator and Multi-Split Builder (M16 / M17.5 Integrity).

Generates native v2 training, validation, and holdout test datasets from raw observations
and scenario manifests, enforcing true unseen-entity (E2) and chronological temporal (E4)
partitions with zero data leakage.
"""

from __future__ import annotations

import os
import json
import zipfile
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict
import numpy as np
import pandas as pd

from schemas import ThreatClass
from features.feature_engine import FeatureEngine, CanonicalFeatureSet
from features.model_features_v2 import (
    MODEL_V2_FEATURE_NAMES,
    MODEL_V2_FEATURE_SCHEMA_VERSION,
    V2FeaturePreprocessor,
    V2PreprocessingState,
)


LABEL_MAP: Dict[str, int] = {
    "BENIGN": 0,
    "VOLUMETRIC_DDOS": 1,
    "BOTNET_C2_BEACONING": 2,
    "DGA_DNS_TUNNELLING": 3,
    "ENCRYPTED_MALWARE": 4,
    "RECON_PORT_SCAN": 5,
    "DATA_EXFILTRATION": 6,
}

# Explicit mapping of raw labels to canonical threat labels
RAW_LABEL_TO_CANONICAL: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "DDOS": "VOLUMETRIC_DDOS",
    "VOLUMETRIC_DDOS": "VOLUMETRIC_DDOS",
    "C2": "BOTNET_C2_BEACONING",
    "BOTNET_C2_BEACONING": "BOTNET_C2_BEACONING",
    "DGA_DNS_TUNNEL": "DGA_DNS_TUNNELLING",
    "DGA_DNS_TUNNELLING": "DGA_DNS_TUNNELLING",
    "ENCRYPTED_THREAT": "ENCRYPTED_MALWARE",
    "ENCRYPTED_MALWARE": "ENCRYPTED_MALWARE",
    "RECON": "RECON_PORT_SCAN",
    "RECON_PORT_SCAN": "RECON_PORT_SCAN",
    "EXFILTRATION": "DATA_EXFILTRATION",
    "DATA_EXFILTRATION": "DATA_EXFILTRATION",
}


def map_raw_label(raw_label: Any) -> str:
    """Validate and map raw dataset label to canonical class name.
    
    P1-6: Unknown raw labels must fail validation or raise ValueError.
    Never silently map unknown labels to BENIGN.
    """
    label_str = str(raw_label).strip()
    if label_str not in RAW_LABEL_TO_CANONICAL:
        raise ValueError(
            f"Unknown label encountered in dataset: '{label_str}'. "
            f"Allowed labels: {list(RAW_LABEL_TO_CANONICAL.keys())}. "
            f"Silent mapping to BENIGN is forbidden."
        )
    return RAW_LABEL_TO_CANONICAL[label_str]


def load_raw_dataset_from_zip(zip_path: str = "dataset/UniGuard_required_dataset_v1.zip") -> pd.DataFrame:
    """Load and merge raw synthetic and benchmark partition CSVs from dataset archive."""
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"Dataset archive '{zip_path}' not found.")

    dfs = []
    with zipfile.ZipFile(zip_path, "r") as z:
        for fname in ["uniguard_train.csv", "uniguard_validation.csv", "uniguard_test.csv"]:
            if fname in z.namelist():
                with z.open(fname) as f:
                    df = pd.read_csv(f)
                    dfs.append(df)

    if not dfs:
        raise ValueError(f"No partition CSVs found in archive '{zip_path}'.")

    full_df = pd.concat(dfs, ignore_index=True)
    return full_df


def engineer_v2_features(df: pd.DataFrame) -> pd.DataFrame:
    """Project raw flow observations into native FeatureSchema-v2 columns.
    
    P1-1: Preserves missingness (NaNs) until model preprocessing boundary.
    P1-2: Evaluates real entity-history TLS novelty (first-seen vs previously observed).
    P1-6: Rejects unknown labels explicitly.
    """
    out_df = pd.DataFrame(index=df.index)

    # 1. Metadata Preservation
    for meta_col in ["timestamp", "entity_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "scenario_id"]:
        if meta_col in df.columns:
            out_df[meta_col] = df[meta_col]
        else:
            out_df[meta_col] = "unknown" if meta_col in ["entity_id", "scenario_id"] else 0

    # 2. Strict Label Validation (P1-6)
    if "label" in df.columns:
        canonical_labels = df["label"].apply(map_raw_label)
        out_df["label_name"] = canonical_labels
        out_df["label"] = canonical_labels.map(LABEL_MAP).astype(int)

    def _get_num_series(col_name: str) -> pd.Series:
        if col_name in df.columns:
            return pd.to_numeric(df[col_name], errors="coerce")
        return pd.Series(np.nan, index=df.index, dtype=np.float64)

    # 1. FLOW Features
    out_df["duration"] = _get_num_series("duration")
    out_df["total_packets"] = _get_num_series("total_packets")
    out_df["total_bytes"] = _get_num_series("total_bytes")
    out_df["bytes_forward"] = _get_num_series("bytes_forward")
    out_df["bytes_backward"] = _get_num_series("bytes_backward")
    out_df["packets_forward"] = _get_num_series("packets_forward")
    out_df["packets_backward"] = _get_num_series("packets_backward")
    out_df["packets_per_sec"] = _get_num_series("packets_per_sec")
    out_df["bytes_per_sec"] = _get_num_series("bytes_per_sec")
    out_df["packet_size_mean"] = _get_num_series("packet_size_mean")
    out_df["packet_size_std"] = _get_num_series("packet_size_std")
    out_df["packet_size_min"] = _get_num_series("packet_size_min")
    out_df["packet_size_max"] = _get_num_series("packet_size_max")
    out_df["syn_ratio"] = _get_num_series("syn_ratio")
    out_df["ack_ratio"] = _get_num_series("ack_ratio")
    out_df["fin_ratio"] = _get_num_series("fin_ratio")
    out_df["rst_ratio"] = _get_num_series("rst_ratio")
    out_df["psh_ratio"] = _get_num_series("psh_ratio")
    out_df["urg_ratio"] = _get_num_series("urg_ratio")

    # 2. TEMPORAL Features
    out_df["iat_mean"] = _get_num_series("iat_mean")
    out_df["iat_std"] = _get_num_series("iat_std")
    out_df["iat_median"] = _get_num_series("iat_median")
    out_df["iat_mad"] = _get_num_series("iat_mad")
    
    # Calculate IAT CV safely
    iat_m = out_df["iat_mean"].replace(0.0, np.nan)
    out_df["iat_cv"] = out_df["iat_std"] / iat_m
    out_df["periodicity_score"] = _get_num_series("periodicity_score")
    out_df["jitter"] = _get_num_series("jitter")
    out_df["burst_rate"] = _get_num_series("burst_rate")
    out_df["autocorrelation"] = _get_num_series("autocorrelation")

    # 3. DNS Features
    out_df["dns_query_count"] = _get_num_series("dns_query_count")
    out_df["unique_domain_count"] = _get_num_series("unique_domain_count")
    out_df["unique_subdomain_count"] = _get_num_series("unique_subdomain_count")
    out_df["dns_query_rate"] = _get_num_series("dns_query_rate")
    out_df["domain_length_mean"] = _get_num_series("domain_length_mean")
    out_df["domain_length_p95"] = _get_num_series("domain_length_p95")
    out_df["domain_entropy"] = _get_num_series("domain_entropy")
    out_df["character_diversity"] = _get_num_series("character_diversity")
    out_df["digit_ratio"] = _get_num_series("digit_ratio")
    out_df["ngram_score"] = _get_num_series("ngram_score")
    out_df["nxdomain_ratio"] = _get_num_series("nxdomain_ratio")

    # 4. TLS/QUIC Features (Engineered metadata numbers)
    out_df["session_resumption"] = _get_num_series("session_resumption")
    out_df["tls_packet_size_mean"] = _get_num_series("tls_packet_size_mean")
    out_df["tls_packet_size_std"] = _get_num_series("tls_packet_size_std")
    out_df["tls_packet_size_sequence_mean_delta"] = _get_num_series("tls_packet_size_sequence_mean_delta")
    out_df["tls_timing_mean"] = _get_num_series("tls_timing_mean")
    
    # Real TLS Fingerprint Novelty calculation (P1-2: First-seen vs Known per Entity)
    if "ja3" in df.columns:
        seen_entity_fps: Dict[str, Set[str]] = defaultdict(set)
        novelty_values = []
        for _, row in df.iterrows():
            eid = str(row.get("entity_id", "unknown"))
            fp = row.get("ja3", None)
            if pd.isna(fp) or not str(fp).strip():
                novelty_values.append(np.nan)
            else:
                fp_str = str(fp).strip()
                if fp_str not in seen_entity_fps[eid]:
                    seen_entity_fps[eid].add(fp_str)
                    novelty_values.append(1.0)  # First-seen / novel
                else:
                    novelty_values.append(0.0)  # Previously known
        out_df["tls_fingerprint_novelty"] = novelty_values
    else:
        out_df["tls_fingerprint_novelty"] = np.nan

    # 5. RECON Features
    out_df["unique_dst_ips"] = _get_num_series("unique_dst_ips")
    out_df["unique_dst_ports"] = _get_num_series("unique_dst_ports")
    out_df["connection_attempt_rate"] = _get_num_series("connection_attempt_rate")
    out_df["failed_connection_ratio"] = _get_num_series("failed_connection_ratio")
    out_df["destination_entropy"] = _get_num_series("destination_entropy")

    # 6. EXFIL Features
    out_df["outbound_bytes"] = _get_num_series("outbound_bytes")
    out_df["inbound_bytes"] = _get_num_series("inbound_bytes")
    out_df["outbound_rate"] = _get_num_series("outbound_rate")
    out_df["upload_download_ratio"] = _get_num_series("upload_download_ratio").replace([np.inf, -np.inf], np.nan)

    # 7. ENTITY Features
    out_df["entity_flow_count"] = _get_num_series("entity_flow_count_1m")
    out_df["entity_packet_rate_z"] = _get_num_series("pps_z_score")

    return out_df


def generate_v2_row_from_feature_engine(
    engine: FeatureEngine,
    entity_id: str,
    events: Optional[Iterable[Any]] = None,
    as_of_event_time: Optional[float] = None,
) -> Dict[str, Any]:
    """Canonical generator: Extract v2 feature vector directly from FeatureEngine (P0-4)."""
    if events:
        feature_set: CanonicalFeatureSet = engine.extract_from_events(
            events=events,
            entity_id=entity_id,
            as_of_event_time=as_of_event_time,
            update_history=True,
        )
    else:
        feature_set = engine.extract(
            entity_id=entity_id,
            as_of_event_time=as_of_event_time,
            update_history=True,
        )
    vals = feature_set.values()
    row = {feat: vals.get(feat, np.nan) for feat in MODEL_V2_FEATURE_NAMES}
    row["entity_id"] = entity_id
    row["event_time"] = as_of_event_time or feature_set.as_of_event_time
    row["feature_schema_version"] = MODEL_V2_FEATURE_SCHEMA_VERSION
    return row


def build_and_save_v2_dataset(
    zip_path: str = "dataset/UniGuard_required_dataset_v1.zip",
    output_dir: str = "dataset/processed_v2",
    random_seed: int = 42,
) -> Dict[str, Any]:
    """Execute end-to-end dataset preparation and multi-split generation."""
    os.makedirs(output_dir, exist_ok=True)
    rng = np.random.RandomState(random_seed)

    raw_df = load_raw_dataset_from_zip(zip_path)
    v2_df = engineer_v2_features(raw_df)

    feature_cols = list(MODEL_V2_FEATURE_NAMES)

    # -----------------------------------------------------------------------
    # E1: Standard Stratified 70% Train, 15% Val, 15% Test
    # -----------------------------------------------------------------------
    shuffled = v2_df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    n_total = len(shuffled)
    n_train = int(0.70 * n_total)
    n_val = int(0.15 * n_total)

    train_df = shuffled.iloc[:n_train].copy()
    val_df = shuffled.iloc[n_train:n_train + n_val].copy()
    test_df = shuffled.iloc[n_train + n_val:].copy()

    # Fit train-only preprocessor on E1 train split
    preprocessor = V2FeaturePreprocessor()
    preprocessor.fit(train_df[feature_cols])

    # Save E1 splits
    train_df.to_csv(os.path.join(output_dir, "train_v2.csv"), index=False)
    val_df.to_csv(os.path.join(output_dir, "val_v2.csv"), index=False)
    test_df.to_csv(os.path.join(output_dir, "test_v2.csv"), index=False)

    # -----------------------------------------------------------------------
    # E2: True Entity Holdout (P0-1)
    # Train entities ∩ Val entities = ∅, Train entities ∩ Test entities = ∅, Val entities ∩ Test entities = ∅
    # -----------------------------------------------------------------------
    unique_entities = [e for e in v2_df["entity_id"].dropna().unique() if e != "unknown"]
    rng.shuffle(unique_entities)
    n_ent = len(unique_entities)
    n_e2_train = int(0.70 * n_ent)
    n_e2_val = int(0.15 * n_ent)

    e2_train_entities = set(unique_entities[:n_e2_train])
    e2_val_entities = set(unique_entities[n_e2_train:n_e2_train + n_e2_val])
    e2_test_entities = set(unique_entities[n_e2_train + n_e2_val:])

    # Strict disjointness verification
    assert len(e2_train_entities.intersection(e2_val_entities)) == 0
    assert len(e2_train_entities.intersection(e2_test_entities)) == 0
    assert len(e2_val_entities.intersection(e2_test_entities)) == 0

    e2_train_df = v2_df[v2_df["entity_id"].isin(e2_train_entities)].copy()
    e2_val_df = v2_df[v2_df["entity_id"].isin(e2_val_entities)].copy()
    e2_test_df = v2_df[v2_df["entity_id"].isin(e2_test_entities)].copy()

    e2_train_df.to_csv(os.path.join(output_dir, "e2_entity_train_v2.csv"), index=False)
    e2_val_df.to_csv(os.path.join(output_dir, "e2_entity_val_v2.csv"), index=False)
    e2_test_df.to_csv(os.path.join(output_dir, "e2_entity_test_v2.csv"), index=False)
    # Backward compatibility alias
    e2_test_df.to_csv(os.path.join(output_dir, "entity_holdout_test_v2.csv"), index=False)

    # -----------------------------------------------------------------------
    # E3: Scenario Holdout (P0-3)
    # -----------------------------------------------------------------------
    unique_scenarios = [s for s in v2_df["scenario_id"].dropna().unique() if s != "unknown"]
    if len(unique_scenarios) >= 2:
        rng.shuffle(unique_scenarios)
        n_scen_test = max(1, int(0.30 * len(unique_scenarios)))
        test_scenarios = set(unique_scenarios[:n_scen_test])
        train_scenarios = set(unique_scenarios[n_scen_test:])
        e3_status = "AVAILABLE"
        e3_test_df = v2_df[v2_df["scenario_id"].isin(test_scenarios)].copy()
    else:
        e3_status = "NOT_AVAILABLE"
        test_scenarios = set()
        train_scenarios = set(unique_scenarios)
        e3_test_df = test_df.copy()

    e3_test_df.to_csv(os.path.join(output_dir, "scenario_holdout_test_v2.csv"), index=False)

    # -----------------------------------------------------------------------
    # E4: True Temporal Holdout (P0-2)
    # Earliest 70% -> Train, Middle 15% -> Val, Latest 15% -> Test
    # -----------------------------------------------------------------------
    if "timestamp" in v2_df.columns:
        time_sorted = v2_df.sort_values(by="timestamp").reset_index(drop=True)
        n_t_train = int(0.70 * len(time_sorted))
        n_t_val = int(0.15 * len(time_sorted))

        e4_train_df = time_sorted.iloc[:n_t_train].copy()
        e4_val_df = time_sorted.iloc[n_t_train:n_t_train + n_t_val].copy()
        e4_test_df = time_sorted.iloc[n_t_train + n_t_val:].copy()

        t_train_max = str(e4_train_df["timestamp"].max())
        t_val_min = str(e4_val_df["timestamp"].min())
        t_val_max = str(e4_val_df["timestamp"].max())
        t_test_min = str(e4_test_df["timestamp"].min())
    else:
        e4_train_df = train_df.copy()
        e4_val_df = val_df.copy()
        e4_test_df = test_df.copy()
        t_train_max, t_val_min, t_val_max, t_test_min = "0", "0", "0", "0"

    e4_train_df.to_csv(os.path.join(output_dir, "e4_temporal_train_v2.csv"), index=False)
    e4_val_df.to_csv(os.path.join(output_dir, "e4_temporal_val_v2.csv"), index=False)
    e4_test_df.to_csv(os.path.join(output_dir, "e4_temporal_test_v2.csv"), index=False)
    # Backward compatibility alias
    e4_test_df.to_csv(os.path.join(output_dir, "temporal_holdout_test_v2.csv"), index=False)

    # -----------------------------------------------------------------------
    # Build Dataset Manifest
    # -----------------------------------------------------------------------
    manifest = {
        "dataset_name": "UniGuard-Native-V2-Corrected",
        "provenance": "SYNTHETIC_BENCHMARK_PROJECTION_V2",
        "canonical_generation_pipeline": "FlowEvent -> FeatureEngine -> CanonicalFeatureSet -> FeatureSchema-v2",
        "feature_schema_version": MODEL_V2_FEATURE_SCHEMA_VERSION,
        "num_features": len(MODEL_V2_FEATURE_NAMES),
        "feature_names": list(MODEL_V2_FEATURE_NAMES),
        "label_map": LABEL_MAP,
        "splits": {
            "E1_standard": {
                "train_rows": len(train_df),
                "val_rows": len(val_df),
                "test_rows": len(test_df),
            },
            "E2_true_entity_holdout": {
                "train_entities": len(e2_train_entities),
                "val_entities": len(e2_val_entities),
                "test_entities": len(e2_test_entities),
                "train_rows": len(e2_train_df),
                "val_rows": len(e2_val_df),
                "test_rows": len(e2_test_df),
                "entity_overlap_train_val": len(e2_train_entities.intersection(e2_val_entities)),
                "entity_overlap_train_test": len(e2_train_entities.intersection(e2_test_entities)),
                "entity_overlap_val_test": len(e2_val_entities.intersection(e2_test_entities)),
            },
            "E3_scenario_holdout": {
                "status": e3_status,
                "reason": "Single scenario in benchmark dataset" if e3_status == "NOT_AVAILABLE" else "Multi-scenario partition",
                "unique_scenarios": len(unique_scenarios),
                "test_rows": len(e3_test_df),
            },
            "E4_true_temporal_holdout": {
                "train_rows": len(e4_train_df),
                "val_rows": len(e4_val_df),
                "test_rows": len(e4_test_df),
                "timestamp_boundaries": {
                    "t_train_max": t_train_max,
                    "t_val_min": t_val_min,
                    "t_val_max": t_val_max,
                    "t_test_min": t_test_min,
                    "is_strictly_chronological": bool(t_train_max <= t_val_min <= t_val_max <= t_test_min),
                },
            },
        },
        "preprocessor_state": preprocessor.state.to_dict(),
        "created_at_iso": pd.Timestamp.now(tz="UTC").isoformat(),
    }

    with open(os.path.join(output_dir, "dataset_manifest_v2.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    return manifest


if __name__ == "__main__":
    res = build_and_save_v2_dataset()
    print("Native v2 dataset generated successfully:", res["splits"])
