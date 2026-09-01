"""Validation-Only Multi-Class Probability Calibration Engine (M16).

Provides isotonic multi-class probability calibration fitted strictly on validation split
predictions with zero data leakage into training or test evaluation.
"""

from __future__ import annotations

from typing import List
import numpy as np
from sklearn.isotonic import IsotonicRegression


class ValidationProbabilityCalibrator:
    """Multi-class probability calibration fitted strictly on validation split."""

    def __init__(self):
        self.calibrators: List[IsotonicRegression] = []

    def fit(self, raw_probs: np.ndarray, y_true: np.ndarray) -> "ValidationProbabilityCalibrator":
        """Fit one isotonic calibrator per class against binary one-vs-rest ground truth."""
        n_classes = raw_probs.shape[1]
        self.calibrators = []
        for c in range(n_classes):
            ir = IsotonicRegression(out_of_bounds="clip", y_min=1e-5, y_max=1.0)
            target = (y_true == c).astype(float)
            ir.fit(raw_probs[:, c], target)
            self.calibrators.append(ir)
        return self

    def calibrate(self, raw_probs: np.ndarray) -> np.ndarray:
        """Apply fitted calibrators and row-normalize probabilities."""
        n_samples, n_classes = raw_probs.shape
        cal_probs = np.zeros_like(raw_probs)
        for c in range(n_classes):
            if c < len(self.calibrators):
                cal_probs[:, c] = self.calibrators[c].predict(raw_probs[:, c])
            else:
                cal_probs[:, c] = raw_probs[:, c]

        sums = np.sum(cal_probs, axis=1, keepdims=True)
        sums = np.where(sums == 0, 1.0, sums)
        return cal_probs / sums


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    """Compute Expected Calibration Error across multi-class predictions."""
    confidences = np.max(y_prob, axis=1)
    predictions = np.argmax(y_prob, axis=1)
    accuracies = (predictions == y_true)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
        prop_in_bin = float(np.mean(in_bin))

        if prop_in_bin > 0:
            accuracy_in_bin = float(np.mean(accuracies[in_bin]))
            avg_confidence_in_bin = float(np.mean(confidences[in_bin]))
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

    return float(ece)
