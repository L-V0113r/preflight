"""Turn labelled pages into the (X, y) matrices scikit-learn expects."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from preflight.context import ScanContext
from preflight.data import LabelledPage
from preflight.features import extract_feature_dict, to_vector


@dataclass
class Dataset:
    X: np.ndarray            # one row of features per page
    y: np.ndarray            # 1 = malicious, 0 = benign
    families: np.ndarray     # attack family / page type, for per-family reporting
    samples: list[LabelledPage]

    def subset(self, mask: np.ndarray) -> "Dataset":
        idx = np.flatnonzero(mask)
        return Dataset(self.X[idx], self.y[idx], self.families[idx],
                       [self.samples[i] for i in idx])

    def __len__(self) -> int:
        return len(self.y)


def featurise(samples: list[LabelledPage], protected_domains: frozenset[str]) -> Dataset:
    rows = []
    for sample in samples:
        page = sample.page
        context = ScanContext.build(page.requested_url, page, protected_domains, "full")
        rows.append(to_vector(extract_feature_dict(context)))
    return Dataset(
        X=np.vstack(rows) if rows else np.empty((0, 0)),
        y=np.array([s.label for s in samples], dtype=int),
        families=np.array([s.family for s in samples]),
        samples=list(samples),
    )
