"""
Model training: pick the better of two small models with cross-validation,
then calibrate its probabilities.

Why two candidates?
* Logistic regression: a weighted sum of features. Simple, fast, easy to
  reason about, but cannot learn "A matters only when B is present".
* Histogram gradient boosting: many small decision trees, each correcting
  the last. Learns interactions between features; still tiny and fast.

Why calibrate? A raw model score of 0.9 does not necessarily mean "90% of
pages like this are malicious". Calibration re-maps scores so that it does,
which makes our thresholds (and the number shown to the user) meaningful.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import numpy as np
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from preflight.features import FEATURE_NAMES
from preflight.ml.model import ModelBundle, RiskModel


def candidate_models(seed: int) -> dict[str, Any]:
    return {
        "logistic_regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=3000, C=0.5, class_weight="balanced"),
        ),
        "gradient_boosting": HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_leaf_nodes=24,
            l2_regularization=1.0, min_samples_leaf=20, class_weight="balanced",
            random_state=seed,
        ),
    }


@dataclass
class TrainingReport:
    chosen: str
    cv_scores: dict[str, tuple[float, float]]   # name -> (mean, std) average precision
    n_samples: int
    n_malicious: int
    seconds: float


def train_model(X: np.ndarray, y: np.ndarray, *, seed: int = 7,
                data_description: str = "unspecified",
                extra_metadata: dict[str, Any] | None = None
                ) -> tuple[RiskModel, TrainingReport]:
    """Select, calibrate and package a model trained on (X, y)."""
    started = time.perf_counter()
    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)

    cv_scores: dict[str, tuple[float, float]] = {}
    for name, estimator in candidate_models(seed).items():
        scores = cross_val_score(estimator, X, y, cv=folds, scoring="average_precision")
        cv_scores[name] = (float(scores.mean()), float(scores.std()))
    chosen = max(cv_scores, key=lambda n: cv_scores[n][0])

    calibrated = CalibratedClassifierCV(
        candidate_models(seed)[chosen],
        method="isotonic" if len(y) >= 2000 else "sigmoid",
        cv=folds,
    )
    calibrated.fit(X, y)

    benign = X[y == 0] if np.any(y == 0) else X
    bundle = ModelBundle(
        estimator=calibrated,
        feature_names=FEATURE_NAMES,
        reference=np.median(benign, axis=0),
        low=np.percentile(X, 1, axis=0),
        high=np.percentile(X, 99, axis=0),
        metadata={
            "algorithm": f"{chosen} (calibrated)",
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "training_data": data_description,
            "n_samples": int(len(y)),
            "n_malicious": int(y.sum()),
            "cv_average_precision": cv_scores,
            "seed": seed,
            "sklearn_version": sklearn.__version__,
            **(extra_metadata or {}),
        },
    )
    report = TrainingReport(chosen=chosen, cv_scores=cv_scores, n_samples=int(len(y)),
                            n_malicious=int(y.sum()),
                            seconds=time.perf_counter() - started)
    return RiskModel(bundle), report
