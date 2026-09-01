"""Dataset Adapter Framework for PS 26145 Evaluation & Generalization Validation (M19).

Provides normalized cross-dataset interfaces with strict label validation,
SHA-256 cryptographic provenance tracking, and canonical evaluation records.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import hashlib
import os
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
import pandas as pd

from schemas import ThreatClass
from dataset.generate_v2_dataset import LABEL_MAP, RAW_LABEL_TO_CANONICAL


@dataclass(frozen=True)
class CanonicalEvaluationRecord:
    """Standardized record produced by any dataset adapter for evaluation."""
    dataset: str
    dataset_version: str
    capture_id: str
    event_time: float
    entity_id: str
    flow_id: str
    label: str
    raw_label: str
    scenario_id: str
    provenance: Dict[str, Any]
    features: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset": self.dataset,
            "dataset_version": self.dataset_version,
            "capture_id": self.capture_id,
            "event_time": self.event_time,
            "entity_id": self.entity_id,
            "flow_id": self.flow_id,
            "label": self.label,
            "raw_label": self.raw_label,
            "scenario_id": self.scenario_id,
            "provenance": self.provenance,
            "features": self.features,
        }


def compute_file_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file for provenance verification."""
    if not os.path.exists(file_path):
        return "FILE_NOT_FOUND"
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class DatasetAdapter(ABC):
    """Abstract Base Class for multi-dataset evaluation adapters."""

    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version

    @property
    @abstractmethod
    def raw_to_canonical(self) -> Dict[str, str]:
        """Mapping from raw dataset labels to canonical evaluation labels."""
        pass

    def map_label(self, raw_label: str) -> str:
        """Map raw dataset label to canonical label, strictly raising ValueError on unknown labels."""
        clean_raw = str(raw_label).strip()
        mapping = self.raw_to_canonical
        if clean_raw in mapping:
            return mapping[clean_raw]
        raise ValueError(
            f"[{self.name}] Unknown raw label '{raw_label}'. "
            f"Strict label validation rejects unmapped labels to prevent silent error."
        )

    def get_provenance(self, file_path: str, label_source: str = "GroundTruthManifest") -> Dict[str, Any]:
        """Generate standardized provenance metadata for a dataset source file."""
        return {
            "source": self.name,
            "version": self.version,
            "file_name": os.path.basename(file_path),
            "file_path": file_path,
            "file_sha256": compute_file_sha256(file_path),
            "feature_source": f"{self.name}Adapter:{self.version}",
            "label_source": label_source,
            "adapter_version": "1.0.0",
        }

    @abstractmethod
    def iter_records(self, source_path: str) -> Iterator[CanonicalEvaluationRecord]:
        """Yield normalized CanonicalEvaluationRecord objects from source data."""
        pass


class SyntheticBenchmarkAdapter(DatasetAdapter):
    """Adapter for the native UniGuard FeatureSchema-v2 synthetic benchmark."""

    def __init__(self):
        super().__init__(name="SyntheticBenchmark", version="v2.1.0")

    @property
    def raw_to_canonical(self) -> Dict[str, str]:
        return RAW_LABEL_TO_CANONICAL

    def iter_records(self, source_path: str) -> Iterator[CanonicalEvaluationRecord]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Benchmark file not found: {source_path}")

        provenance = self.get_provenance(source_path, label_source="SyntheticBenchmarkV2")
        df = pd.read_csv(source_path)

        for _, row in df.iterrows():
            raw_lbl = str(row.get("label", "BENIGN"))
            canonical_lbl = self.map_label(raw_lbl)
            event_time = float(row.get("event_time", 0.0))
            entity_id = str(row.get("entity_id", "unknown"))
            flow_id = str(row.get("flow_id", f"{entity_id}-{event_time}"))
            scenario_id = str(row.get("scenario_id", "SYNTHETIC_FLOW"))

            # Extract features
            features = {col: row[col] for col in df.columns if col not in {"label", "raw_label", "entity_id", "flow_id", "scenario_id"}}

            yield CanonicalEvaluationRecord(
                dataset=self.name,
                dataset_version=self.version,
                capture_id=os.path.basename(source_path),
                event_time=event_time,
                entity_id=entity_id,
                flow_id=flow_id,
                label=canonical_lbl,
                raw_label=raw_lbl,
                scenario_id=scenario_id,
                provenance=provenance,
                features=features,
            )


class CICIDS2017Adapter(DatasetAdapter):
    """Adapter for Canadian Institute for Cybersecurity CIC-IDS2017 Dataset."""

    def __init__(self):
        super().__init__(name="CIC-IDS2017", version="2017.1")

    @property
    def raw_to_canonical(self) -> Dict[str, str]:
        return {
            "BENIGN": "BENIGN",
            "Benign": "BENIGN",
            "DDoS": "VOLUMETRIC_DDOS",
            "DoS Hulk": "VOLUMETRIC_DDOS",
            "DoS GoldenEye": "VOLUMETRIC_DDOS",
            "DoS slowloris": "VOLUMETRIC_DDOS",
            "DoS Slowhttptest": "VOLUMETRIC_DDOS",
            "PortScan": "RECON_PORT_SCAN",
            "Bot": "BOTNET_C2_BEACONING",
            "Infiltration": "ENCRYPTED_MALWARE",
            "Web Attack – Brute Force": "RECON_PORT_SCAN",
            "Web Attack – XSS": "RECON_PORT_SCAN",
            "Web Attack – Sql Injection": "RECON_PORT_SCAN",
            "FTP-Patator": "RECON_PORT_SCAN",
            "SSH-Patator": "RECON_PORT_SCAN",
        }

    def iter_records(self, source_path: str) -> Iterator[CanonicalEvaluationRecord]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"CIC-IDS2017 file not found: {source_path}")

        provenance = self.get_provenance(source_path, label_source="CIC-IDS2017-GroundTruth")
        df = pd.read_csv(source_path)

        for _, row in df.iterrows():
            raw_lbl = str(row.get(" Label", row.get("Label", "BENIGN"))).strip()
            canonical_lbl = self.map_label(raw_lbl)
            entity_id = str(row.get(" Source IP", row.get("src_ip", "10.0.0.1"))).strip()
            dst_ip = str(row.get(" Destination IP", row.get("dst_ip", "192.168.1.1"))).strip()
            flow_id = f"{entity_id}->{dst_ip}"
            event_time = float(row.get(" Timestamp", row.get("timestamp", 0.0)) if isinstance(row.get(" Timestamp", 0.0), (int, float)) else 0.0)

            yield CanonicalEvaluationRecord(
                dataset=self.name,
                dataset_version=self.version,
                capture_id=os.path.basename(source_path),
                event_time=event_time,
                entity_id=entity_id,
                flow_id=flow_id,
                label=canonical_lbl,
                raw_label=raw_lbl,
                scenario_id="CIC_IDS_2017_REPLAY",
                provenance=provenance,
                features=dict(row),
            )


class CSECICIDS2018Adapter(DatasetAdapter):
    """Adapter for Communications Security Establishment & CIC CSE-CIC-IDS2018 Dataset."""

    def __init__(self):
        super().__init__(name="CSE-CIC-IDS2018", version="2018.1")

    @property
    def raw_to_canonical(self) -> Dict[str, str]:
        return {
            "Benign": "BENIGN",
            "BENIGN": "BENIGN",
            "DDOS attack-HOIC": "VOLUMETRIC_DDOS",
            "DDOS attack-LOIC-UDP": "VOLUMETRIC_DDOS",
            "DDoS attacks-LOIC-HTTP": "VOLUMETRIC_DDOS",
            "DoS attacks-Hulk": "VOLUMETRIC_DDOS",
            "DoS attacks-Slowloris": "VOLUMETRIC_DDOS",
            "DoS attacks-GoldenEye": "VOLUMETRIC_DDOS",
            "DoS attacks-SlowHTTPTest": "VOLUMETRIC_DDOS",
            "Bot": "BOTNET_C2_BEACONING",
            "Infilteration": "ENCRYPTED_MALWARE",
            "Infiltration": "ENCRYPTED_MALWARE",
            "Brute Force -Web": "RECON_PORT_SCAN",
            "Brute Force -XSS": "RECON_PORT_SCAN",
            "SQL Injection": "RECON_PORT_SCAN",
            "FTP-BruteForce": "RECON_PORT_SCAN",
            "SSH-Bruteforce": "RECON_PORT_SCAN",
        }

    def iter_records(self, source_path: str) -> Iterator[CanonicalEvaluationRecord]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"CSE-CIC-IDS2018 file not found: {source_path}")

        provenance = self.get_provenance(source_path, label_source="CSE-CIC-IDS2018-GroundTruth")
        df = pd.read_csv(source_path)

        for _, row in df.iterrows():
            raw_lbl = str(row.get("Label", "Benign")).strip()
            canonical_lbl = self.map_label(raw_lbl)
            entity_id = str(row.get("Src IP", row.get("src_ip", "10.0.0.1"))).strip()
            flow_id = str(row.get("Flow ID", f"{entity_id}-flow"))
            event_time = 0.0

            yield CanonicalEvaluationRecord(
                dataset=self.name,
                dataset_version=self.version,
                capture_id=os.path.basename(source_path),
                event_time=event_time,
                entity_id=entity_id,
                flow_id=flow_id,
                label=canonical_lbl,
                raw_label=raw_lbl,
                scenario_id="CSE_CIC_IDS_2018_REPLAY",
                provenance=provenance,
                features=dict(row),
            )


class UNSWNB15Adapter(DatasetAdapter):
    """Adapter for University of New South Wales UNSW-NB15 Dataset."""

    def __init__(self):
        super().__init__(name="UNSW-NB15", version="v1")

    @property
    def raw_to_canonical(self) -> Dict[str, str]:
        return {
            "Normal": "BENIGN",
            "normal": "BENIGN",
            "BENIGN": "BENIGN",
            "Generic": "UNKNOWN_ANOMALY",
            "Exploits": "ENCRYPTED_MALWARE",
            "Fuzzers": "RECON_PORT_SCAN",
            "DoS": "VOLUMETRIC_DDOS",
            "Reconnaissance": "RECON_PORT_SCAN",
            "Analysis": "RECON_PORT_SCAN",
            "Backdoor": "BOTNET_C2_BEACONING",
            "Backdoors": "BOTNET_C2_BEACONING",
            "Shellcode": "ENCRYPTED_MALWARE",
            "Worms": "BOTNET_C2_BEACONING",
        }

    def iter_records(self, source_path: str) -> Iterator[CanonicalEvaluationRecord]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"UNSW-NB15 file not found: {source_path}")

        provenance = self.get_provenance(source_path, label_source="UNSW-NB15-GroundTruth")
        df = pd.read_csv(source_path)

        for _, row in df.iterrows():
            raw_lbl = str(row.get("attack_cat", row.get("label", "Normal"))).strip()
            if raw_lbl in {"0", "0.0"}:
                raw_lbl = "Normal"
            canonical_lbl = self.map_label(raw_lbl)
            entity_id = str(row.get("srcip", "10.0.0.1")).strip()
            dst_ip = str(row.get("dstip", "192.168.1.1")).strip()
            flow_id = f"{entity_id}->{dst_ip}"
            event_time = float(row.get("sttl", 0.0))

            yield CanonicalEvaluationRecord(
                dataset=self.name,
                dataset_version=self.version,
                capture_id=os.path.basename(source_path),
                event_time=event_time,
                entity_id=entity_id,
                flow_id=flow_id,
                label=canonical_lbl,
                raw_label=raw_lbl,
                scenario_id="UNSW_NB15_REPLAY",
                provenance=provenance,
                features=dict(row),
            )


class UGR16Adapter(DatasetAdapter):
    """Adapter for University of Granada UGR'16 NetFlow / IPFIX Dataset."""

    def __init__(self):
        super().__init__(name="UGR16", version="v1")

    @property
    def raw_to_canonical(self) -> Dict[str, str]:
        return {
            "background": "BENIGN",
            "normal": "BENIGN",
            "BENIGN": "BENIGN",
            "dos": "VOLUMETRIC_DDOS",
            "scan": "RECON_PORT_SCAN",
            "scan11": "RECON_PORT_SCAN",
            "scan44": "RECON_PORT_SCAN",
            "botnet": "BOTNET_C2_BEACONING",
            "nerisbotnet": "BOTNET_C2_BEACONING",
            "blacklist": "BOTNET_C2_BEACONING",
            "anomaly": "UNKNOWN_ANOMALY",
        }

    def iter_records(self, source_path: str) -> Iterator[CanonicalEvaluationRecord]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"UGR'16 file not found: {source_path}")

        provenance = self.get_provenance(source_path, label_source="UGR16-GroundTruth")
        df = pd.read_csv(source_path)

        for _, row in df.iterrows():
            raw_lbl = str(row.get("label", row.get("tag", "background"))).strip()
            canonical_lbl = self.map_label(raw_lbl)
            entity_id = str(row.get("src_ip", "10.0.0.1")).strip()
            flow_id = str(row.get("flow_id", f"{entity_id}-ugr"))
            event_time = float(row.get("timestamp", 0.0))

            yield CanonicalEvaluationRecord(
                dataset=self.name,
                dataset_version=self.version,
                capture_id=os.path.basename(source_path),
                event_time=event_time,
                entity_id=entity_id,
                flow_id=flow_id,
                label=canonical_lbl,
                raw_label=raw_lbl,
                scenario_id="UGR16_REPLAY",
                provenance=provenance,
                features=dict(row),
            )
