"""
Evaluation: how good is PreFlight, compared with simpler alternatives?

We compare four systems on the SAME held-out test pages (never used for
training or tuning):

1. Keyword baseline   - flag a page if it contains any "scary" keyword.
                        This is what the hackathon brief calls a simple baseline.
2. Rules only         - PreFlight's hand-written detectors, no model.
3. Model only         - the ML model alone (probability >= 0.5).
4. PreFlight (hybrid) - rules + model + uncertainty handling, i.e. what users get.

We also run a leave-one-family-out study: train the model WITHOUT one attack
family and test on it, to measure how well it generalises to attack types it
has never seen. This is the closest a synthetic study can get to "new attacks".
"""

from __future__ import annotations

import statistics
import time
from dataclasses import asdict, dataclass

import numpy as np
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.model_selection import train_test_split

from preflight.config import AppConfig
from preflight.data import LabelledPage, SyntheticWebFactory
from preflight.detectors import ThreatIntel
from preflight.ml.dataset import Dataset, featurise
from preflight.ml.model import RiskModel
from preflight.ml.trainer import train_model
from preflight.scanner import Scanner
from preflight.schema import FetchedPage, Verdict

# The naive keyword list a quick hackathon prototype might use.
BASELINE_KEYWORDS = (
    "eval(", "atob(", "unescape(", "fromcharcode", "powershell", "coinhive", "cryptonight",
    "verify your account", "suspended", "password", "<iframe", ".exe", "call microsoft",
    "requestpermission", "clipboard",
)

FLAGGED = (Verdict.CAUTION, Verdict.DANGER)


def keyword_baseline(page: FetchedPage) -> bool:
    text = (page.body + " ".join(page.external_scripts.values()) + page.requested_url).lower()
    return any(keyword in text for keyword in BASELINE_KEYWORDS)


@dataclass
class BinaryMetrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @classmethod
    def from_predictions(cls, y_true: np.ndarray, y_pred: np.ndarray) -> "BinaryMetrics":
        y_true, y_pred = np.asarray(y_true, bool), np.asarray(y_pred, bool)
        return cls(tp=int(np.sum(y_true & y_pred)), fp=int(np.sum(~y_true & y_pred)),
                   tn=int(np.sum(~y_true & ~y_pred)), fn=int(np.sum(y_true & ~y_pred)))

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def recall(self) -> float:
        """Share of malicious pages caught (a.k.a. detection rate)."""
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def false_positive_rate(self) -> float:
        """Share of safe pages wrongly warned about."""
        return self.fp / max(self.fp + self.tn, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    def to_dict(self) -> dict:
        return {**asdict(self), "n": self.tp + self.fp + self.tn + self.fn,
                "precision": round(self.precision, 3), "recall": round(self.recall, 3),
                "false_positive_rate": round(self.false_positive_rate, 3), "f1": round(self.f1, 3)}


def _scanner(config: AppConfig, intel: ThreatIntel, model: RiskModel | None) -> Scanner:
    # The fetcher is never used: evaluation runs offline on pages we already have.
    return Scanner(config, model, intel)


def _verdicts(scanner: Scanner, samples: list[LabelledPage], strictness: str = "balanced"
              ) -> tuple[list[Verdict], list[float]]:
    verdicts, seconds = [], []
    for sample in samples:
        t0 = time.perf_counter()
        result = scanner.analyse(sample.page.requested_url, sample.page, strictness=strictness)
        seconds.append(time.perf_counter() - t0)
        verdicts.append(result.verdict)
    return verdicts, seconds


def run_evaluation(config: AppConfig, *, seed: int = 7, n_benign: int = 3000,
                   n_malicious: int = 2000, test_fraction: float = 0.3,
                   leave_one_out: bool = True, log=print) -> dict:
    intel = ThreatIntel.load(config.threat_data_dir)
    protected = intel.protected_domains

    log(f"Generating {n_benign} benign + {n_malicious} malicious synthetic pages (seed {seed})...")
    samples = SyntheticWebFactory(seed).generate(n_benign, n_malicious)
    data = featurise(samples, protected)

    idx_train, idx_test = train_test_split(
        np.arange(len(data)), test_size=test_fraction, random_state=seed, stratify=data.families)
    train, test = data.subset(np.isin(np.arange(len(data)), idx_train)), \
        data.subset(np.isin(np.arange(len(data)), idx_test))
    log(f"Train: {len(train)} pages, test: {len(test)} pages (held out, never trained on).")

    log("Training model on the training split...")
    model, training = train_model(train.X, train.y, seed=seed,
                                  data_description="synthetic (evaluation split)")

    log("Scoring the test split with all four systems...")
    y = test.y
    keyword_pred = np.array([keyword_baseline(s.page) for s in test.samples])
    rules_verdicts, _ = _verdicts(_scanner(config, intel, None), test.samples)
    ml_prob = model.predict_many(test.X)
    hybrid_verdicts, seconds = _verdicts(_scanner(config, intel, model), test.samples)
    strict_verdicts, _ = _verdicts(_scanner(config, intel, model), test.samples, "strict")
    strict_flag = np.array([v in FLAGGED for v in strict_verdicts])
    strict_safe = np.array([v == Verdict.SAFE for v in strict_verdicts])

    hybrid_flag = np.array([v in FLAGGED for v in hybrid_verdicts])
    hybrid_unsure = np.array([v == Verdict.UNSURE for v in hybrid_verdicts])
    systems = {
        "keyword_baseline": BinaryMetrics.from_predictions(y, keyword_pred),
        "rules_only": BinaryMetrics.from_predictions(y, [v in FLAGGED for v in rules_verdicts]),
        "model_only": BinaryMetrics.from_predictions(y, ml_prob >= 0.5),
        "preflight_hybrid": BinaryMetrics.from_predictions(y, hybrid_flag),
        "preflight_strict": BinaryMetrics.from_predictions(y, strict_flag),
    }

    per_family = {}
    for family in sorted(set(test.families)):
        mask = test.families == family
        is_bad = bool(test.y[mask][0])
        flagged = hybrid_flag[mask]
        per_family[family] = {
            "n": int(mask.sum()),
            "malicious": is_bad,
            # For malicious families this is the detection rate; for benign
            # families it is the false-alarm rate.
            "flagged_rate": round(float(flagged.mean()), 3),
            "unsure_rate": round(float(hybrid_unsure[mask].mean()), 3),
            "keyword_flagged_rate": round(float(keyword_pred[mask].mean()), 3),
        }

    url_only_mask = np.array([s.url_only for s in test.samples])
    readable = ~url_only_mask
    systems_readable = {
        "keyword_baseline": BinaryMetrics.from_predictions(y[readable], keyword_pred[readable]),
        "rules_only": BinaryMetrics.from_predictions(
            y[readable], np.array([v in FLAGGED for v in rules_verdicts])[readable]),
        "model_only": BinaryMetrics.from_predictions(y[readable], (ml_prob >= 0.5)[readable]),
        "preflight_hybrid": BinaryMetrics.from_predictions(y[readable], hybrid_flag[readable]),
        "preflight_strict": BinaryMetrics.from_predictions(y[readable], strict_flag[readable]),
    }
    hybrid_safe = np.array([v == Verdict.SAFE for v in hybrid_verdicts])

    def experience(mask: np.ndarray) -> dict:
        """What the user actually sees: silent load, a question, or a warning."""
        return {
            "n": int(mask.sum()),
            "opened_silently": round(float(hybrid_safe[mask].mean()), 3),
            "asked_unsure": round(float(hybrid_unsure[mask].mean()), 3),
            "warned": round(float(hybrid_flag[mask].mean()), 3),
            "strict_opened_silently": round(float(strict_safe[mask].mean()), 3),
            "strict_interrupted": round(float((~strict_safe[mask]).mean()), 3),
        }

    report = {
        "data": {
            "kind": "SYNTHETIC (labelled, generated by preflight/data/synthetic.py)",
            "seed": seed, "n_total": len(data), "n_train": len(train), "n_test": len(test),
            "n_test_malicious": int(test.y.sum()), "n_test_benign": int((test.y == 0).sum()),
            "n_test_url_only": int(url_only_mask.sum()),
        },
        "training": {"chosen_algorithm": training.chosen,
                     "cv_average_precision": training.cv_scores,
                     "seconds": round(training.seconds, 1)},
        "systems": {name: m.to_dict() for name, m in systems.items()},
        "systems_content_readable": {name: m.to_dict() for name, m in systems_readable.items()},
        "user_experience": {
            "malicious": experience(y == 1),
            "benign": experience(y == 0),
            "malicious_content_readable": experience((y == 1) & readable),
            "benign_content_readable": experience((y == 0) & readable),
        },
        "model_quality": {
            "roc_auc": round(float(roc_auc_score(y, ml_prob)), 4),
            "brier_score": round(float(brier_score_loss(y, ml_prob)), 4),
        },
        "uncertainty": {
            "unsure_rate_benign": round(float(hybrid_unsure[y == 0].mean()), 3),
            "unsure_rate_benign_with_content": round(
                float(hybrid_unsure[(y == 0) & ~url_only_mask].mean()), 3),
            "unsure_rate_malicious": round(float(hybrid_unsure[y == 1].mean()), 3),
            "unsure_rate_url_only_pages": round(float(hybrid_unsure[url_only_mask].mean()), 3)
            if url_only_mask.any() else None,
        },
        "per_family": per_family,
        "latency_ms_offline": {
            "median": round(1000 * statistics.median(seconds), 2),
            "p95": round(1000 * float(np.percentile(seconds, 95)), 2),
            "note": "analysis only; a live scan adds network time to fetch the page",
        },
    }
    if leave_one_out:
        report["leave_one_family_out"] = _leave_one_family_out(
            config, intel, train, test, seed, log)
    return report


def _leave_one_family_out(config: AppConfig, intel: ThreatIntel, train: Dataset,
                          test: Dataset, seed: int, log) -> dict:
    """Train without each attack family in turn, then test on that family."""
    results = {}
    rules_scanner = _scanner(config, intel, None)
    for family in sorted(SyntheticWebFactory.MALICIOUS_FAMILIES):
        held_out = test.subset(test.families == family)
        if len(held_out) == 0:
            continue
        log(f"  leave-one-out: training without '{family}'...")
        reduced = train.subset(train.families != family)
        model, _ = train_model(reduced.X, reduced.y, seed=seed,
                               data_description=f"synthetic without {family}")
        ml_recall = float((model.predict_many(held_out.X) >= 0.5).mean())
        hybrid, _ = _verdicts(_scanner(config, intel, model), held_out.samples)
        rules, _ = _verdicts(rules_scanner, held_out.samples)
        results[family] = {
            "n": len(held_out),
            "model_only_recall_unseen": round(ml_recall, 3),
            "rules_only_recall": round(float(np.mean([v in FLAGGED for v in rules])), 3),
            "hybrid_recall_unseen": round(float(np.mean([v in FLAGGED for v in hybrid])), 3),
        }
    return results


def evaluate_real_folder(config: AppConfig, samples: list[LabelledPage], log=print) -> dict:
    """
    Evaluate the SAVED model (plus rules) on real labelled pages you collected,
    e.g. with `scan_cli.py URL --save-html dataset/benign`. Nothing is trained
    here, so every page is unseen by the model.
    """
    intel = ThreatIntel.load(config.threat_data_dir)
    model = RiskModel.load(config.model_path) if config.model_path.exists() else None
    if not samples:
        raise ValueError("no samples found (expected benign/ and malicious/ sub-folders)")
    y = np.array([s.label for s in samples])
    log(f"Scoring {len(samples)} real pages ({int(y.sum())} malicious)...")
    keyword = np.array([keyword_baseline(s.page) for s in samples])
    rules, _ = _verdicts(_scanner(config, intel, None), samples)
    hybrid, seconds = _verdicts(_scanner(config, intel, model), samples)
    flagged = np.array([v in FLAGGED for v in hybrid])
    unsure = np.array([v == Verdict.UNSURE for v in hybrid])
    return {
        "data": {"kind": "REAL (your labelled folder)", "n": len(samples),
                 "n_malicious": int(y.sum()), "n_benign": int((y == 0).sum())},
        "systems": {
            "keyword_baseline": BinaryMetrics.from_predictions(y, keyword).to_dict(),
            "rules_only": BinaryMetrics.from_predictions(y, [v in FLAGGED for v in rules]).to_dict(),
            "preflight_hybrid": BinaryMetrics.from_predictions(y, flagged).to_dict(),
        },
        "malicious_opened_silently": round(float(np.mean([v == Verdict.SAFE for v, t in zip(hybrid, y) if t])), 3)
        if y.any() else None,
        "benign_interrupted": round(float((flagged | unsure)[y == 0].mean()), 3) if (y == 0).any() else None,
        "latency_ms_offline_median": round(1000 * statistics.median(seconds), 2),
        "model": model.info if model else None,
    }
