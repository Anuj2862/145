"""Confusion Matrix and Evaluation Metrics Engine for PS 26145 Benchmarking (Phase 2B).

Computes precision, recall, macro F1-score, false positive rate (FPR),
and latency percentiles across evaluated traffic classes.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import statistics

from dataset.manifest_schema import EvaluationTrafficClass


@dataclass
class ClassMetricResult:
    """Evaluation metrics for an individual traffic class."""
    traffic_class: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    tested: bool = True
    untested_reason: Optional[str] = None

    @property
    def precision(self) -> float:
        if not self.tested or (self.true_positives + self.false_positives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        if not self.tested or (self.true_positives + self.false_negatives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        if (p + r) == 0.0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def false_positive_rate(self) -> float:
        if not self.tested or (self.false_positives + self.true_negatives) == 0:
            return 0.0
        return self.false_positives / (self.false_positives + self.true_negatives)

    def to_dict(self) -> Dict[str, Any]:
        if not self.tested:
            return {
                "traffic_class": self.traffic_class,
                "status": "NOT_TESTED",
                "reason": self.untested_reason or "Required labeled PCAP capture unavailable",
            }
        return {
            "traffic_class": self.traffic_class,
            "status": "TESTED",
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


class MultiClassConfusionMatrix:
    """Maintains empirical prediction vs ground-truth match counts and latency statistics."""

    def __init__(self, supported_classes: Optional[List[EvaluationTrafficClass]] = None):
        self.classes: List[str] = [
            c.value for c in (supported_classes or list(EvaluationTrafficClass))
        ]
        # matrix[ground_truth][predicted]
        self.matrix: Dict[str, Dict[str, int]] = {
            gt: {pred: 0 for pred in self.classes} for gt in self.classes
        }
        self.latencies_ms: List[float] = []
        self.untested_classes: Dict[str, str] = {}

    def mark_untested(self, traffic_class: EvaluationTrafficClass, reason: str) -> None:
        """Explicitly designate a threat category as untested due to missing traces."""
        self.untested_classes[traffic_class.value] = reason

    def record_match(
        self,
        ground_truth: EvaluationTrafficClass,
        predicted: EvaluationTrafficClass,
        latency_ms: Optional[float] = None,
    ) -> None:
        """Record an individual evaluation decision comparing prediction to ground truth."""
        gt_key = ground_truth.value
        pred_key = predicted.value

        if gt_key not in self.matrix:
            self.matrix[gt_key] = {c: 0 for c in self.classes}
        if pred_key not in self.matrix[gt_key]:
            self.matrix[gt_key][pred_key] = 0

        self.matrix[gt_key][pred_key] += 1

        if latency_ms is not None and latency_ms >= 0.0:
            self.latencies_ms.append(latency_ms)

    def get_class_metrics(self, traffic_class: EvaluationTrafficClass) -> ClassMetricResult:
        """Compute TP, FP, FN, TN, Precision, Recall, and F1 for a given class."""
        c_name = traffic_class.value

        if c_name in self.untested_classes:
            return ClassMetricResult(
                traffic_class=c_name,
                tested=False,
                untested_reason=self.untested_classes[c_name],
            )

        tp = self.matrix.get(c_name, {}).get(c_name, 0)
        
        # FP: ground truth != c_name, but predicted == c_name
        fp = sum(
            self.matrix[gt].get(c_name, 0)
            for gt in self.matrix
            if gt != c_name
        )

        # FN: ground truth == c_name, but predicted != c_name
        fn = sum(
            count for pred, count in self.matrix.get(c_name, {}).items()
            if pred != c_name
        )

        # TN: ground truth != c_name and predicted != c_name
        tn = sum(
            count for gt in self.matrix if gt != c_name
            for pred, count in self.matrix[gt].items()
            if pred != c_name
        )

        # If zero instances occurred for this class, mark tested based on whether any evaluations took place
        total_class_instances = tp + fn
        if total_class_instances == 0 and fp == 0:
            return ClassMetricResult(
                traffic_class=c_name,
                tested=False,
                untested_reason="Zero instances observed in evaluated captures",
            )

        return ClassMetricResult(
            traffic_class=c_name,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            tested=True,
        )

    def compute_summary(self) -> Dict[str, Any]:
        """Compute aggregate macro metrics across all tested classes."""
        per_class = {}
        tested_f1_scores = []
        tested_precisions = []
        tested_recalls = []

        for c_enum in EvaluationTrafficClass:
            res = self.get_class_metrics(c_enum)
            per_class[c_enum.value] = res.to_dict()
            if res.tested and c_enum != EvaluationTrafficClass.BENIGN:
                tested_f1_scores.append(res.f1_score)
                tested_precisions.append(res.precision)
                tested_recalls.append(res.recall)

        macro_f1 = statistics.mean(tested_f1_scores) if tested_f1_scores else 0.0
        macro_prec = statistics.mean(tested_precisions) if tested_precisions else 0.0
        macro_rec = statistics.mean(tested_recalls) if tested_recalls else 0.0

        # Latency statistics
        median_lat = statistics.median(self.latencies_ms) if self.latencies_ms else 0.0
        p95_lat = 0.0
        if self.latencies_ms:
            sorted_lat = sorted(self.latencies_ms)
            p95_idx = int(len(sorted_lat) * 0.95)
            p95_lat = sorted_lat[min(p95_idx, len(sorted_lat) - 1)]

        # Benign FPR
        benign_res = self.get_class_metrics(EvaluationTrafficClass.BENIGN)
        benign_fpr = benign_res.false_positive_rate if benign_res.tested else 0.0

        return {
            "macro_precision": round(macro_prec, 4),
            "macro_recall": round(macro_rec, 4),
            "macro_f1": round(macro_f1, 4),
            "benign_false_positive_rate": round(benign_fpr, 4),
            "latency_median_ms": round(median_lat, 2),
            "latency_p95_ms": round(p95_lat, 2),
            "total_evaluations": sum(sum(row.values()) for row in self.matrix.values()),
            "per_class_breakdown": per_class,
            "raw_confusion_matrix": self.matrix,
        }
