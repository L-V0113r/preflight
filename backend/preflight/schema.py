"""
Shared data types used across the whole package.

Keeping these in one module means every other module agrees on the shape of
the data it passes around, and nothing has to import a "big" module just to
get a type.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Severity(IntEnum):
    """How bad a single finding is. Ordered, so findings can be sorted."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# How much each severity contributes to the overall risk score.
# These are combined with a "noisy-OR" in preflight.scoring, so two MEDIUM
# findings add up to more than one, but nothing ever exceeds 1.0.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.08,
    Severity.MEDIUM: 0.25,
    Severity.HIGH: 0.55,
    Severity.CRITICAL: 0.95,
}


class Verdict(str, Enum):
    """The single answer the browser extension acts on."""

    SAFE = "safe"          # Load the page without interrupting the user.
    CAUTION = "caution"    # Show a warning; the user decides.
    DANGER = "danger"      # Show a strong warning; "Go back" is the default.
    UNSURE = "unsure"      # The scanner could not reach a confident answer.
    ERROR = "error"        # The scan itself failed (bad URL, internal error).


@dataclass(frozen=True)
class Finding:
    """One human-readable reason a page looks risky."""

    detector_id: str
    title: str
    explanation: str
    severity: Severity
    category: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        return data


@dataclass
class FetchedPage:
    """
    Everything the scanner learned by downloading a URL (without running it).

    The same type is produced by the real fetcher, by the synthetic data
    generator and by the real-data loaders, so training and live scanning go
    through exactly the same feature extraction code.
    """

    requested_url: str
    final_url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)  # keys lower-case
    body: str = ""
    content_type: str = ""
    # Every URL requested, in order, INCLUDING the final one. Empty if the
    # fetch never started. len(redirect_chain) - 1 == number of redirects.
    redirect_chain: list[str] = field(default_factory=list)
    external_scripts: dict[str, str] = field(default_factory=dict)  # src -> code
    # For non-HTML responses: what the first bytes say the file really is
    # (e.g. "windows-executable"), regardless of what the server claims.
    binary_signature: str = ""
    truncated: bool = False
    fetch_error: str | None = None
    tls_error: bool = False
    elapsed_ms: float = 0.0
    is_synthetic: bool = False

    @property
    def fetched_ok(self) -> bool:
        return self.fetch_error is None and self.status is not None

    @property
    def is_html(self) -> bool:
        ctype = self.content_type.lower()
        return (not ctype) or "html" in ctype or "xml" in ctype


@dataclass(frozen=True)
class MLFactor:
    """A feature that pushed the model towards 'malicious', for explanations."""

    feature: str
    description: str
    contribution: float  # drop in probability when the feature is neutralised

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "description": self.description,
            "contribution": round(self.contribution, 3),
        }


@dataclass
class ScanResult:
    """The full answer returned to the extension (and printed by the CLI)."""

    url: str
    verdict: Verdict
    risk_score: float
    ml_probability: float | None
    findings: list[Finding] = field(default_factory=list)
    ml_factors: list[MLFactor] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    mode: str = "full"
    out_of_distribution: bool = False
    timings_ms: dict[str, float] = field(default_factory=dict)
    model_info: dict[str, Any] = field(default_factory=dict)
    scanned_at: float = field(default_factory=time.time)
    from_cache: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "verdict": self.verdict.value,
            "risk_score": round(self.risk_score, 3),
            "ml_probability": (
                None if self.ml_probability is None else round(self.ml_probability, 3)
            ),
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda f: f.severity, reverse=True)],
            "ml_factors": [m.to_dict() for m in self.ml_factors],
            "notes": list(self.notes),
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "mode": self.mode,
            "out_of_distribution": self.out_of_distribution,
            "timings_ms": {k: round(v, 1) for k, v in self.timings_ms.items()},
            "model_info": dict(self.model_info),
            "scanned_at": self.scanned_at,
            "from_cache": self.from_cache,
        }
