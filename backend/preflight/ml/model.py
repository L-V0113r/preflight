"""
The trained model, packaged with everything needed to use it honestly:

* the classifier itself (a calibrated scikit-learn model),
* the exact feature order it was trained with,
* a "typical safe page" reference vector, used to explain decisions,
* the normal range of every feature, used to notice unfamiliar pages,
* metadata (when, on what data, with what results) shown to the user.

SECURITY NOTE: joblib files are Python pickles. Loading a pickle can run
code, so only ever load model files you trained yourself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from preflight.features import FEATURE_DESCRIPTIONS, FEATURE_NAMES
from preflight.schema import MLFactor

BUNDLE_FORMAT_VERSION = 1


class ModelMismatchError(Exception):
    """The saved model was trained with a different feature list."""


@dataclass
class ModelBundle:
    estimator: Any
    feature_names: tuple[str, ...]
    reference: np.ndarray        # median feature values of safe training pages
    low: np.ndarray              # 1st percentile of each feature in training data
    high: np.ndarray             # 99th percentile of each feature in training data
    metadata: dict[str, Any] = field(default_factory=dict)
    format_version: int = BUNDLE_FORMAT_VERSION


class RiskModel:
    def __init__(self, bundle: ModelBundle) -> None:
        if tuple(bundle.feature_names) != FEATURE_NAMES:
            raise ModelMismatchError(
                "model features do not match this version of PreFlight; retrain with "
                "`python train_model.py`")
        self.bundle = bundle
        # Allow a margin around the training range before calling a value unusual.
        span = np.maximum(bundle.high - bundle.low, 1e-9)
        self._lower = bundle.low - 0.25 * span - 1e-6
        self._upper = bundle.high + 0.25 * span + 1e-6

    # ----------------------------------------------------------- persistence
    @classmethod
    def load(cls, path: Path) -> "RiskModel":
        bundle = joblib.load(path)
        if not isinstance(bundle, ModelBundle):
            raise ModelMismatchError("file is not a PreFlight model bundle")
        return cls(bundle)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.bundle, path, compress=3)

    # ------------------------------------------------------------ prediction
    def predict(self, vector: np.ndarray) -> float:
        """Probability (0..1) that the page is malicious."""
        return float(self.bundle.estimator.predict_proba(vector.reshape(1, -1))[0, 1])

    def predict_many(self, matrix: np.ndarray) -> np.ndarray:
        return self.bundle.estimator.predict_proba(matrix)[:, 1]

    def explain(self, vector: np.ndarray, top_k: int = 3, min_effect: float = 0.03,
                only: frozenset[str] | None = None) -> list[MLFactor]:
        """
        Occlusion explanation: for each unusual feature, put it back to the
        value of a typical safe page and see how much the probability drops.
        Big drops = features that drove the decision. Model-agnostic and cheap
        (one batched prediction).
        """
        reference = self.bundle.reference
        differs = ~np.isclose(vector, reference)
        if only is not None:
            differs &= np.array([name in only for name in FEATURE_NAMES])
        changed = np.flatnonzero(differs)
        if changed.size == 0:
            return []
        base = self.predict(vector)
        variants = np.repeat(vector.reshape(1, -1), changed.size, axis=0)
        variants[np.arange(changed.size), changed] = reference[changed]
        effects = base - self.predict_many(variants)
        order = np.argsort(effects)[::-1]
        factors = []
        for idx in order[:top_k]:
            if effects[idx] < min_effect:
                break
            name = FEATURE_NAMES[changed[idx]]
            factors.append(MLFactor(name, FEATURE_DESCRIPTIONS[name], float(effects[idx])))
        return factors

    def unusual_features(self, vector: np.ndarray) -> list[str]:
        """Features outside the range seen in training (the model is guessing there)."""
        outside = (vector < self._lower) | (vector > self._upper)
        return [FEATURE_NAMES[i] for i in np.flatnonzero(outside)]

    # -------------------------------------------------------------- metadata
    @property
    def info(self) -> dict[str, Any]:
        meta = self.bundle.metadata
        return {
            "algorithm": meta.get("algorithm"),
            "trained_at": meta.get("trained_at"),
            "training_data": meta.get("training_data"),
            "n_training_samples": meta.get("n_samples"),
        }
