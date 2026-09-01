"""Native Feature-Schema-v2 Model Feature Definition and Preprocessing Pipeline (M16).

Defines the native model feature schema (feature-schema-v2.1.0) derived directly from the
canonical FeatureEngine v2. Provides explicit missingness handling, zero data leakage
preprocessing, and training/inference feature projection parity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np
import pandas as pd


MODEL_V2_FEATURE_SCHEMA_VERSION = "feature-schema-v2.1.0"
MODEL_V2_WINDOW_SECONDS = 60

# ---------------------------------------------------------------------------
# Native Feature Taxonomy: 56 Predictive Model Features across 7 Families
# ---------------------------------------------------------------------------

MODEL_V2_FEATURE_NAMES: Tuple[str, ...] = (
    # 1. FLOW (19 features)
    "duration",
    "total_packets",
    "total_bytes",
    "bytes_forward",
    "bytes_backward",
    "packets_forward",
    "packets_backward",
    "packets_per_sec",
    "bytes_per_sec",
    "packet_size_mean",
    "packet_size_std",
    "packet_size_min",
    "packet_size_max",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    "psh_ratio",
    "urg_ratio",
    # 2. TEMPORAL (9 features)
    "iat_mean",
    "iat_std",
    "iat_median",
    "iat_mad",
    "iat_cv",
    "periodicity_score",
    "jitter",
    "burst_rate",
    "autocorrelation",
    # 3. DNS (11 features)
    "dns_query_count",
    "unique_domain_count",
    "unique_subdomain_count",
    "dns_query_rate",
    "domain_length_mean",
    "domain_length_p95",
    "domain_entropy",
    "character_diversity",
    "digit_ratio",
    "ngram_score",
    "nxdomain_ratio",
    # 4. TLS/QUIC (6 features - metadata-only, zero payload decryption)
    "session_resumption",
    "tls_packet_size_mean",
    "tls_packet_size_std",
    "tls_packet_size_sequence_mean_delta",
    "tls_timing_mean",
    "tls_fingerprint_novelty",
    # 5. RECON (5 features)
    "unique_dst_ips",
    "unique_dst_ports",
    "connection_attempt_rate",
    "failed_connection_ratio",
    "destination_entropy",
    # 6. EXFIL (4 features)
    "outbound_bytes",
    "inbound_bytes",
    "outbound_rate",
    "upload_download_ratio",
    # 7. ENTITY (2 features)
    "entity_flow_count",
    "entity_packet_rate_z",
)

MODEL_V2_FEATURE_COUNT = len(MODEL_V2_FEATURE_NAMES)

# ---------------------------------------------------------------------------
# Feature Family Classification
# ---------------------------------------------------------------------------

FEATURE_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "FLOW": MODEL_V2_FEATURE_NAMES[0:19],
    "TEMPORAL": MODEL_V2_FEATURE_NAMES[19:28],
    "DNS": MODEL_V2_FEATURE_NAMES[28:39],
    "TLS_QUIC": MODEL_V2_FEATURE_NAMES[39:45],
    "RECON": MODEL_V2_FEATURE_NAMES[45:50],
    "EXFIL": MODEL_V2_FEATURE_NAMES[50:54],
    "ENTITY": MODEL_V2_FEATURE_NAMES[54:56],
}

# ---------------------------------------------------------------------------
# Missingness Handling Policy Classification:
#   A: Always observed (default 0.0)
#   B: Legitimately zero (0.0 when absent)
#   C: Legitimately absent (protocol mismatch, imputed with train median/0.0)
#   D: Unavailable (imputed with train median)
#   E: Insufficient history (imputed with train median)
# ---------------------------------------------------------------------------

MISSING_POLICY_ZERO: Set[str] = {
    "duration",
    "total_packets",
    "total_bytes",
    "bytes_forward",
    "bytes_backward",
    "packets_forward",
    "packets_backward",
    "packets_per_sec",
    "bytes_per_sec",
    "burst_rate",
    "dns_query_count",
    "unique_domain_count",
    "unique_subdomain_count",
    "dns_query_rate",
    "unique_dst_ips",
    "unique_dst_ports",
    "connection_attempt_rate",
    "outbound_bytes",
    "inbound_bytes",
    "outbound_rate",
    "entity_flow_count",
    "session_resumption",
    "tls_fingerprint_novelty",
}


@dataclass
class V2PreprocessingState:
    """Stores train-only fitted medians for zero-leakage imputation."""
    medians: Dict[str, float] = field(default_factory=dict)
    feature_names: List[str] = field(default_factory=lambda: list(MODEL_V2_FEATURE_NAMES))
    schema_version: str = MODEL_V2_FEATURE_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "medians": self.medians,
            "feature_names": self.feature_names,
            "schema_version": self.schema_version,
            "num_features": len(self.feature_names),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "V2PreprocessingState":
        return cls(
            medians=data.get("medians", {}),
            feature_names=data.get("feature_names", list(MODEL_V2_FEATURE_NAMES)),
            schema_version=data.get("schema_version", MODEL_V2_FEATURE_SCHEMA_VERSION),
        )


class V2FeaturePreprocessor:
    """Zero-leakage preprocessor fitted strictly on training data."""

    def __init__(self, state: Optional[V2PreprocessingState] = None):
        self.state = state or V2PreprocessingState()

    def fit(self, df: pd.DataFrame) -> "V2FeaturePreprocessor":
        """Compute medians strictly from training dataframe."""
        medians: Dict[str, float] = {}
        for feat in MODEL_V2_FEATURE_NAMES:
            if feat in df.columns:
                series = pd.to_numeric(df[feat], errors="coerce").dropna()
                if len(series) > 0:
                    medians[feat] = float(series.median())
                else:
                    medians[feat] = 0.0
            else:
                medians[feat] = 0.0

        self.state.medians = medians
        return self

    def transform_df(self, df: pd.DataFrame) -> np.ndarray:
        """Transform dataframe to 2D numpy array using fitted train medians."""
        n_rows = len(df)
        matrix = np.zeros((n_rows, len(MODEL_V2_FEATURE_NAMES)), dtype=np.float64)

        for col_idx, feat in enumerate(MODEL_V2_FEATURE_NAMES):
            if feat in df.columns:
                series = pd.to_numeric(df[feat], errors="coerce")
                # Handle inf / -inf
                series = series.replace([np.inf, -np.inf], np.nan)
                default_val = 0.0 if feat in MISSING_POLICY_ZERO else self.state.medians.get(feat, 0.0)
                filled = series.fillna(default_val).to_numpy(dtype=np.float64)
                matrix[:, col_idx] = filled
            else:
                default_val = 0.0 if feat in MISSING_POLICY_ZERO else self.state.medians.get(feat, 0.0)
                matrix[:, col_idx] = default_val

        return matrix

    def transform_dict(self, features: Dict[str, Any]) -> np.ndarray:
        """Transform a single feature dictionary or CanonicalFeatureSet values to 1D numpy array."""
        vector = np.zeros((1, len(MODEL_V2_FEATURE_NAMES)), dtype=np.float64)

        for col_idx, feat in enumerate(MODEL_V2_FEATURE_NAMES):
            raw_val = features.get(feat, features.get(f"60s.{feat}", features.get(f"300s.{feat}", features.get(f"30s.{feat}", features.get(f"5s.{feat}", features.get(f"1s.{feat}", None))))))
            if raw_val is None or (isinstance(raw_val, float) and (np.isnan(raw_val) or np.isinf(raw_val))):
                val = 0.0 if feat in MISSING_POLICY_ZERO else self.state.medians.get(feat, 0.0)
            else:
                try:
                    val = float(raw_val)
                except (ValueError, TypeError):
                    val = 0.0 if feat in MISSING_POLICY_ZERO else self.state.medians.get(feat, 0.0)
            vector[0, col_idx] = val

        return vector
