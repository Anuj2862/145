"""Dataset Preparation Pipeline for UniGuard Threat Detection System (Member 2).

This module processes raw dataset records (from dataset/UniGuard_required_dataset_v1.zip),
encodes categorical metadata via One-Hot Encoding, normalizes features, maps threat labels to canonical
ThreatClass enum indices, enforces zero-entity-leakage partitions, and exports clean
processed training, validation, and test datasets.
"""

import os
import json
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import pandas as pd

from schemas import ThreatClass
from features.feature_contract import LEGACY_MODEL_FEATURE_NAMES


LABEL_MAPPING: Dict[str, Tuple[int, Optional[str]]] = {
    "BENIGN": (0, None),
    "DDOS": (1, ThreatClass.VOLUMETRIC_DDOS.value),
    "C2": (2, ThreatClass.BOTNET_C2_BEACONING.value),
    "DGA_DNS_TUNNEL": (3, ThreatClass.DGA_DNS_TUNNELLING.value),
    "ENCRYPTED_THREAT": (4, ThreatClass.ENCRYPTED_MALWARE.value),
    "RECON": (5, ThreatClass.RECON_PORT_SCAN.value),
    "EXFILTRATION": (6, ThreatClass.DATA_EXFILTRATION.value),
}

LABEL_NAMES: List[str] = [
    "BENIGN",
    "VOLUMETRIC_DDOS",
    "BOTNET_C2_BEACONING",
    "DGA_DNS_TUNNELLING",
    "ENCRYPTED_MALWARE",
    "RECON_PORT_SCAN",
    "DATA_EXFILTRATION",
]

# 36 clean numerical predictive feature columns derived from UniGuard architecture.
# Note: recent_risk and baseline_deviation are explicitly EXCLUDED due to downstream risk leakage.
NUMERICAL_FEATURE_COLUMNS: List[str] = [
    name for name in LEGACY_MODEL_FEATURE_NAMES
    if not name.startswith(("ja3_", "ja4_", "tls_version_"))
]

CATEGORICAL_COLUMNS: List[str] = ["ja3", "ja4", "tls_version"]

EXCLUDED_LEAKAGE_FEATURES: List[str] = ["recent_risk", "baseline_deviation"]
EXCLUSION_REASON: str = "target/downstream risk leakage"

METADATA_COLUMNS: List[str] = [
    "timestamp",
    "entity_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "direction",
    "dataset_source",
    "scenario_id",
    "attack_stage",
    "split",
]


@dataclass
class PreprocessingState:
    """Stores feature statistics and categorical one-hot vocabulary learned strictly from TRAIN data."""
    medians: Dict[str, float] = field(default_factory=dict)
    onehot_categories: Dict[str, List[str]] = field(default_factory=dict)
    feature_names: List[str] = field(default_factory=list)


@dataclass
class DatasetSplits:
    """Encapsulates processed training, validation, and test datasets."""
    X_train: pd.DataFrame
    y_train: np.ndarray
    X_val: pd.DataFrame
    y_val: np.ndarray
    X_test: pd.DataFrame
    y_test: np.ndarray
    train_meta: pd.DataFrame
    val_meta: pd.DataFrame
    test_meta: pd.DataFrame
    feature_names: List[str]
    label_map: Dict[str, int]
    state: PreprocessingState


class UniGuardDatasetPipeline:
    """ETL, encoding, and group-splitting pipeline for UniGuard datasets."""

    def __init__(self, zip_path: str = "dataset/UniGuard_required_dataset_v1.zip"):
        self.zip_path = zip_path

    def load_partition_from_zip(self, file_name: str) -> pd.DataFrame:
        """Read a single partition CSV from the dataset ZIP file."""
        if not os.path.exists(self.zip_path):
            raise FileNotFoundError(
                f"Required dataset archive not found at '{self.zip_path}'. "
                f"Please ensure the ZIP archive is present."
            )

        with zipfile.ZipFile(self.zip_path, "r") as z:
            if file_name not in z.namelist():
                raise FileNotFoundError(
                    f"File '{file_name}' not found inside archive '{self.zip_path}'."
                )
            with z.open(file_name) as f:
                df = pd.read_csv(f)
        return df

    def verify_label_mapping(self, labels: pd.Series) -> np.ndarray:
        """Verify and map raw dataset labels to explicit integer indices."""
        unknown_labels = set(labels.unique()) - set(LABEL_MAPPING.keys())
        if unknown_labels:
            raise ValueError(f"Encountered unsupported dataset label(s): {unknown_labels}")
        return np.array([LABEL_MAPPING[lbl][0] for lbl in labels], dtype=np.int64)

    def verify_no_entity_leakage(
        self, train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame
    ) -> None:
        """Verify zero entity ID leakage across train, validation, and test sets."""
        if "entity_id" not in train_df.columns:
            return

        train_entities = set(train_df["entity_id"].dropna().unique())
        val_entities = set(val_df["entity_id"].dropna().unique())
        test_entities = set(test_df["entity_id"].dropna().unique())

        train_val_overlap = train_entities.intersection(val_entities)
        train_test_overlap = train_entities.intersection(test_entities)
        val_test_overlap = val_entities.intersection(test_entities)

        if train_val_overlap or train_test_overlap or val_test_overlap:
            raise ValueError(
                f"Data leakage detected across dataset partitions! "
                f"Train/Val overlap: {len(train_val_overlap)}, "
                f"Train/Test overlap: {len(train_test_overlap)}, "
                f"Val/Test overlap: {len(val_test_overlap)}"
            )

    def fit_transform_train(self, train_df: pd.DataFrame) -> Tuple[pd.DataFrame, PreprocessingState]:
        """Fit preprocessing parameters strictly on TRAIN data and transform it using One-Hot Encoding."""
        state = PreprocessingState()
        X_train = pd.DataFrame(index=train_df.index)

        # 1. Process numerical features
        for col in NUMERICAL_FEATURE_COLUMNS:
            if col not in train_df.columns:
                continue
            median_val = float(train_df[col].median()) if not train_df[col].dropna().empty else 0.0
            state.medians[col] = median_val
            X_train[col] = train_df[col].fillna(median_val).astype(np.float64)

        # 2. Fit and transform categorical features using One-Hot Encoding
        for col in CATEGORICAL_COLUMNS:
            if col not in train_df.columns:
                continue
            cats = sorted(train_df[col].dropna().astype(str).unique())
            state.onehot_categories[col] = cats
            col_str = train_df[col].astype(str)
            for cat in cats:
                feature_name = f"{col}_{cat}"
                X_train[feature_name] = (col_str == cat).astype(np.float64)

        state.feature_names = list(X_train.columns)
        return X_train, state

    def transform_eval(self, eval_df: pd.DataFrame, state: PreprocessingState) -> pd.DataFrame:
        """Apply learned TRAIN preprocessing parameters (medians & one-hot categories) to eval data."""
        X_eval = pd.DataFrame(index=eval_df.index)

        # 1. Transform numerical features using train medians
        for col in NUMERICAL_FEATURE_COLUMNS:
            if col in state.medians:
                fill_val = state.medians[col]
                if col in eval_df.columns:
                    X_eval[col] = eval_df[col].fillna(fill_val).astype(np.float64)
                else:
                    X_eval[col] = fill_val

        # 2. Transform categorical features using train one-hot vocabulary
        for col, cats in state.onehot_categories.items():
            if col in eval_df.columns:
                col_str = eval_df[col].astype(str)
                for cat in cats:
                    feature_name = f"{col}_{cat}"
                    X_eval[feature_name] = (col_str == cat).astype(np.float64)
            else:
                for cat in cats:
                    feature_name = f"{col}_{cat}"
                    X_eval[feature_name] = 0.0

        # Ensure column ordering matches train feature_names exactly
        X_eval = X_eval[state.feature_names]
        return X_eval

    def process(self) -> DatasetSplits:
        """Execute the full dataset preparation pipeline."""
        # 1. Load official partition files from ZIP
        train_df = self.load_partition_from_zip("uniguard_train.csv")
        val_df = self.load_partition_from_zip("uniguard_validation.csv")
        test_df = self.load_partition_from_zip("uniguard_test.csv")

        # 2. Verify zero entity leakage across splits
        self.verify_no_entity_leakage(train_df, val_df, test_df)

        # 3. Map labels to canonical threat class indices
        y_train = self.verify_label_mapping(train_df["label"])
        y_val = self.verify_label_mapping(val_df["label"])
        y_test = self.verify_label_mapping(test_df["label"])

        # 4. Learn preprocessing parameters strictly on TRAIN
        X_train, state = self.fit_transform_train(train_df)

        # 5. Transform VAL and TEST using TRAIN state
        X_val = self.transform_eval(val_df, state)
        X_test = self.transform_eval(test_df, state)

        # 6. Extract metadata dataframes
        meta_cols = [c for c in METADATA_COLUMNS if c in train_df.columns]
        train_meta = train_df[meta_cols].copy()
        val_meta = val_df[meta_cols].copy()
        test_meta = test_df[meta_cols].copy()

        simple_label_map = {k: v[0] for k, v in LABEL_MAPPING.items()}

        return DatasetSplits(
            X_train=X_train,
            y_train=y_train,
            X_val=X_val,
            y_val=y_val,
            X_test=X_test,
            y_test=y_test,
            train_meta=train_meta,
            val_meta=val_meta,
            test_meta=test_meta,
            feature_names=state.feature_names,
            label_map=simple_label_map,
            state=state,
        )

    def export(self, splits: DatasetSplits, output_dir: str = "dataset/processed") -> Dict[str, Any]:
        """Export processed feature tables and metadata summary manifest."""
        os.makedirs(output_dir, exist_ok=True)

        # Save CSV partitions
        train_export = splits.X_train.copy()
        train_export["label"] = splits.y_train
        train_export.to_csv(os.path.join(output_dir, "train.csv"), index=False)

        val_export = splits.X_val.copy()
        val_export["label"] = splits.y_val
        val_export.to_csv(os.path.join(output_dir, "val.csv"), index=False)

        test_export = splits.X_test.copy()
        test_export["label"] = splits.y_test
        test_export.to_csv(os.path.join(output_dir, "test.csv"), index=False)

        # Manifest
        manifest = {
            "num_features": len(splits.feature_names),
            "feature_names": splits.feature_names,
            "excluded_features": EXCLUDED_LEAKAGE_FEATURES,
            "exclusion_reason": EXCLUSION_REASON,
            "label_map": splits.label_map,
            "train_rows": len(splits.X_train),
            "val_rows": len(splits.X_val),
            "test_rows": len(splits.X_test),
            "output_dir": output_dir,
        }

        with open(os.path.join(output_dir, "dataset_manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)

        return manifest


def generate_mock_df(num_rows: int = 100, seed: int = 42) -> pd.DataFrame:
    """Explicit mock data generator utility for unit testing only."""
    np.random.seed(seed)
    data = {
        "timestamp": ["2026-01-01T00:00:00Z"] * num_rows,
        "entity_id": [f"HOST_{i % 10:04d}" for i in range(num_rows)],
        "src_ip": ["10.0.0.1"] * num_rows,
        "dst_ip": ["192.168.1.1"] * num_rows,
        "src_port": [443] * num_rows,
        "dst_port": [80] * num_rows,
        "protocol": ["TCP"] * num_rows,
        "direction": ["OUTBOUND"] * num_rows,
        "duration": np.random.uniform(0.1, 10.0, size=num_rows),
        "total_packets": np.random.randint(1, 100, size=num_rows),
        "total_bytes": np.random.uniform(100.0, 10000.0, size=num_rows),
        "bytes_forward": np.random.uniform(50.0, 5000.0, size=num_rows),
        "bytes_backward": np.random.uniform(50.0, 5000.0, size=num_rows),
        "packets_per_sec": np.random.uniform(1.0, 50.0, size=num_rows),
        "bytes_per_sec": np.random.uniform(100.0, 5000.0, size=num_rows),
        "packet_size_mean": np.random.uniform(64.0, 1500.0, size=num_rows),
        "iat_mean": np.random.uniform(0.1, 2.0, size=num_rows),
        "iat_std": np.random.uniform(0.01, 0.5, size=num_rows),
        "periodicity_score": np.random.uniform(0.0, 1.0, size=num_rows),
        "jitter": np.random.uniform(0.0, 0.5, size=num_rows),
        "burst_rate": np.random.uniform(1.0, 5.0, size=num_rows),
        "dns_query_count": np.random.randint(0, 10, size=num_rows),
        "unique_domain_count": np.random.randint(0, 5, size=num_rows),
        "domain_length_mean": np.random.uniform(10.0, 30.0, size=num_rows),
        "domain_entropy": np.random.uniform(2.0, 4.5, size=num_rows),
        "ngram_score": np.random.uniform(0.0, 1.0, size=num_rows),
        "dns_query_rate": np.random.uniform(0.0, 5.0, size=num_rows),
        "ja3": ["JA3_A"] * num_rows,
        "ja4": ["JA4_A"] * num_rows,
        "tls_version": ["TLS1.3"] * num_rows,
        "session_resumption": [0] * num_rows,
        "tls_packet_size_mean": np.random.uniform(100.0, 1000.0, size=num_rows),
        "unique_dst_ips": np.random.randint(1, 10, size=num_rows),
        "unique_dst_ports": np.random.randint(1, 10, size=num_rows),
        "connection_attempt_rate": np.random.uniform(0.5, 5.0, size=num_rows),
        "failed_connection_ratio": np.random.uniform(0.0, 0.5, size=num_rows),
        "fan_out": np.random.uniform(0.1, 1.0, size=num_rows),
        "outbound_bytes": np.random.uniform(100.0, 5000.0, size=num_rows),
        "outbound_rate": np.random.uniform(100.0, 5000.0, size=num_rows),
        "upload_download_ratio": np.random.uniform(0.5, 3.0, size=num_rows),
        "destination_count": np.random.randint(1, 5, size=num_rows),
        "large_transfer_score": np.random.uniform(0.0, 1.0, size=num_rows),
        "entity_flow_count_1m": np.random.randint(1, 20, size=num_rows),
        "entity_unique_destinations_1m": np.random.randint(1, 5, size=num_rows),
        "entity_new_destinations_5m": np.random.randint(0, 3, size=num_rows),
        "entity_avg_connection_interval": np.random.uniform(1.0, 10.0, size=num_rows),
        "entity_periodicity": np.random.uniform(0.0, 1.0, size=num_rows),
        "baseline_deviation": np.random.uniform(0.0, 1.0, size=num_rows),
        "recent_risk": np.random.uniform(0.0, 1.0, size=num_rows),
        "label": np.random.choice(list(LABEL_MAPPING.keys()), size=num_rows),
        "dataset_source": ["MOCK"] * num_rows,
        "scenario_id": ["TEST"] * num_rows,
        "attack_stage": ["NORMAL"] * num_rows,
        "split": ["train"] * num_rows,
    }
    return pd.DataFrame(data)


def main():
    """CLI entry point for dataset preparation."""
    pipeline = UniGuardDatasetPipeline()
    print("Running UniGuard Dataset Preparation Pipeline...")
    splits = pipeline.process()
    manifest = pipeline.export(splits)
    print("Dataset successfully processed and exported!")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
