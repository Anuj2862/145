"""Classification Evaluation Metrics for UniGuard Threat Detection System.

Computes accuracy, precision, recall, F1 (macro, weighted, per-class), and confusion matrix
for multi-class threat detectors and produces JSON-serializable metric dicts.
"""

from typing import Dict, List, Optional, Any
import numpy as np

DEFAULT_LABEL_NAMES = [
    "BENIGN",
    "VOLUMETRIC_DDOS",
    "BOTNET_C2_BEACONING",
    "DGA_DNS_TUNNELLING",
    "ENCRYPTED_MALWARE",
    "RECON_PORT_SCAN",
    "DATA_EXFILTRATION",
]


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    label_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Compute comprehensive multiclass classification metrics.
    
    Returns a clean, JSON-serializable dictionary.
    Lazy-imports sklearn.metrics to avoid Windows DLL initialization order conflicts
    when loaded alongside LightGBM C extensions.
    """
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        confusion_matrix,
    )
    if label_names is None:
        label_names = DEFAULT_LABEL_NAMES

    acc = float(accuracy_score(y_true, y_pred))

    prec_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    prec_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    # Per-class metrics
    prec_per_class = precision_score(y_true, y_pred, average=None, zero_division=0)
    rec_per_class = recall_score(y_true, y_pred, average=None, zero_division=0)
    f1_per_class = f1_score(y_true, y_pred, average=None, zero_division=0)

    per_class_dict = {}
    for idx, name in enumerate(label_names):
        p_val = float(prec_per_class[idx]) if idx < len(prec_per_class) else 0.0
        r_val = float(rec_per_class[idx]) if idx < len(rec_per_class) else 0.0
        f_val = float(f1_per_class[idx]) if idx < len(f1_per_class) else 0.0
        per_class_dict[name] = {
            "precision": p_val,
            "recall": r_val,
            "f1": f_val,
        }

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    cm_list = cm.tolist()

    return {
        "accuracy": acc,
        "macro_precision": prec_macro,
        "macro_recall": rec_macro,
        "macro_f1": f1_macro,
        "weighted_precision": prec_weighted,
        "weighted_recall": rec_weighted,
        "weighted_f1": f1_weighted,
        "per_class_metrics": per_class_dict,
        "confusion_matrix": cm_list,
    }
