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
    def support(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def precision(self) -> Optional[float]:
        if not self.tested or (self.true_positives + self.false_positives) == 0:
            return None
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> Optional[float]:
        if not self.tested or (self.true_positives + self.false_negatives) == 0:
            return None
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1_score(self) -> Optional[float]:
        p = self.precision
        r = self.recall
        if p is None or r is None or (p + r) == 0.0:
            return None
        return 2 * (p * r) / (p + r)

    @property
    def false_positive_rate(self) -> Optional[float]:
        if not self.tested or (self.false_positives + self.true_negatives) == 0:
            return None
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
            "support": self.support,
            "precision": round(self.precision, 4) if self.precision is not None else "N/A",
            "recall": round(self.recall, 4) if self.recall is not None else "N/A",
            "f1_score": round(self.f1_score, 4) if self.f1_score is not None else "N/A",
            "false_positive_rate": round(self.false_positive_rate, 4) if self.false_positive_rate is not None else "N/A",
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
                if res.f1_score is not None:
                    tested_f1_scores.append(res.f1_score)
                if res.precision is not None:
                    tested_precisions.append(res.precision)
                if res.recall is not None:
                    tested_recalls.append(res.recall)

        macro_f1 = round(statistics.mean(tested_f1_scores), 4) if tested_f1_scores else None
        macro_prec = round(statistics.mean(tested_precisions), 4) if tested_precisions else None
        macro_rec = round(statistics.mean(tested_recalls), 4) if tested_recalls else None

        # Latency statistics
        median_lat = round(statistics.median(self.latencies_ms), 2) if self.latencies_ms else None
        p95_lat = None
        if self.latencies_ms:
            sorted_lat = sorted(self.latencies_ms)
            p95_idx = int(len(sorted_lat) * 0.95)
            p95_lat = round(sorted_lat[min(p95_idx, len(sorted_lat) - 1)], 2)

        # Benign False Alarm Rate and Threat Miss Rate
        benign_res = self.get_class_metrics(EvaluationTrafficClass.BENIGN)
        threat_miss_rate = round(benign_res.false_positive_rate, 4) if (benign_res.tested and benign_res.false_positive_rate is not None) else None
        
        # Benign False Alarm Rate: Benign windows predicted as any threat / Total Benign windows
        benign_far = None
        if benign_res.tested and benign_res.support > 0:
            benign_far = round(benign_res.false_negatives / benign_res.support, 4)

        # Binary Anomaly Evaluation: Ground Truth (BENIGN vs ATTACK) -> Prediction (NORMAL vs ANOMALY)
        # Normal = Predicted BENIGN, Anomalous = Predicted ANY ATTACK / UNKNOWN_ANOMALY
        ano_tp = sum(
            self.matrix[gt][pred]
            for gt in self.matrix if gt != EvaluationTrafficClass.BENIGN.value
            for pred in self.matrix[gt] if pred != EvaluationTrafficClass.BENIGN.value
        )
        ano_fn = sum(
            self.matrix[gt].get(EvaluationTrafficClass.BENIGN.value, 0)
            for gt in self.matrix if gt != EvaluationTrafficClass.BENIGN.value
        )
        ano_fp = sum(
            self.matrix.get(EvaluationTrafficClass.BENIGN.value, {}).get(pred, 0)
            for pred in self.classes if pred != EvaluationTrafficClass.BENIGN.value
        )
        ano_tn = self.matrix.get(EvaluationTrafficClass.BENIGN.value, {}).get(EvaluationTrafficClass.BENIGN.value, 0)

        ano_prec = (ano_tp / (ano_tp + ano_fp)) if (ano_tp + ano_fp) > 0 else None
        ano_rec = (ano_tp / (ano_tp + ano_fn)) if (ano_tp + ano_fn) > 0 else None
        ano_f1 = (2 * ano_prec * ano_rec / (ano_prec + ano_rec)) if (ano_prec and ano_rec and (ano_prec + ano_rec) > 0) else None
        ano_far = (ano_fp / (ano_fp + ano_tn)) if (ano_fp + ano_tn) > 0 else None

        binary_anomaly = {
            "true_positives": ano_tp,
            "false_positives": ano_fp,
            "false_negatives": ano_fn,
            "true_negatives": ano_tn,
            "precision": round(ano_prec, 4) if ano_prec is not None else "N/A",
            "recall": round(ano_rec, 4) if ano_rec is not None else "N/A",
            "f1_score": round(ano_f1, 4) if ano_f1 is not None else "N/A",
            "false_alarm_rate": round(ano_far, 4) if ano_far is not None else "N/A",
        }

        total_decisions = sum(sum(row.values()) for row in self.matrix.values())

        return {
            "evaluation_status": "COMPLETED" if total_decisions > 0 else "NO_CAPTURES_EVALUATED",
            "macro_precision": macro_prec if macro_prec is not None else "N/A",
            "macro_recall": macro_rec if macro_rec is not None else "N/A",
            "macro_f1": macro_f1 if macro_f1 is not None else "N/A",
            "benign_false_alarm_rate": benign_far if benign_far is not None else "N/A",
            "threat_miss_rate": threat_miss_rate if threat_miss_rate is not None else "N/A",
            "benign_false_positive_rate": threat_miss_rate if threat_miss_rate is not None else "N/A",
            "binary_anomaly_evaluation": binary_anomaly,
            "latency_median_ms": median_lat if median_lat is not None else "N/A",
            "latency_p95_ms": p95_lat if p95_lat is not None else "N/A",
            "total_evaluations": total_decisions,
            "per_class_breakdown": per_class,
            "raw_confusion_matrix": self.matrix,
        }
