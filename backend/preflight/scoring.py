"""
Turn rule findings and the model's probability into ONE verdict.

The combination is a "noisy-OR": treat each piece of evidence as an
independent chance that the page is bad, and ask "what is the chance that
at least one of them is right?"

    risk = 1 - (1 - w1) * (1 - w2) * ... * (1 - ml_weight * p_model)

Properties that make this a good fit:
* it never exceeds 1.0, however many findings there are;
* adding evidence can only raise the risk, never lower it;
* a single CRITICAL finding (w = 0.95) dominates on its own.

Then honest uncertainty is layered on top: if we could not read the page,
or the model is on the fence, or the page is unlike anything the model has
seen, the answer is UNSURE rather than a confident SAFE.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from preflight.config import ScoringSettings
from preflight.schema import SEVERITY_WEIGHT, Finding, Severity, Verdict


@dataclass
class ScoreOutcome:
    verdict: Verdict
    risk: float
    rule_risk: float
    notes: list[str] = field(default_factory=list)


def noisy_or(probabilities: list[float]) -> float:
    remaining = 1.0
    for p in probabilities:
        remaining *= 1.0 - max(0.0, min(1.0, p))
    return 1.0 - remaining


def decide(findings: list[Finding], ml_probability: float | None, *,
           content_analysed: bool, out_of_distribution: bool,
           settings: ScoringSettings, mode: str = "full") -> ScoreOutcome:
    """
    `content_analysed` is False when only the URL could be judged: either the
    user chose URL-only mode, or (in full mode) the page could not be fetched.
    """
    rule_risk = noisy_or([SEVERITY_WEIGHT[f.severity] for f in findings])
    evidence = [SEVERITY_WEIGHT[f.severity] for f in findings]
    if ml_probability is not None:
        weight = settings.ml_weight if content_analysed else settings.ml_weight_url_only
        evidence.append(weight * ml_probability)
    risk = noisy_or(evidence)
    notes: list[str] = []

    # The page should have been read but couldn't be. Unless a rule found
    # something concrete in the link itself, a guess from the link alone is
    # not enough to call it either safe or dangerous.
    fetch_failed = mode == "full" and not content_analysed
    concrete = any(f.severity >= Severity.MEDIUM for f in findings)
    if fetch_failed and not concrete:
        notes.append("The page could not be loaded, so only the link itself was checked.")
        if ml_probability is not None:
            notes.append(f"Judging from the link alone, the model rates it "
                         f"{ml_probability:.0%} likely to be malicious; treat that as a hint only.")
        return ScoreOutcome(Verdict.UNSURE, risk, rule_risk, notes)

    if any(f.severity == Severity.CRITICAL for f in findings) or risk >= settings.danger_threshold:
        return ScoreOutcome(Verdict.DANGER, risk, rule_risk, notes)
    if risk >= settings.caution_threshold:
        return ScoreOutcome(Verdict.CAUTION, risk, rule_risk, notes)

    # Nothing alarming was found. Is that because the page is fine, or because
    # we could not really look? Say so instead of claiming it is safe.
    if fetch_failed:
        notes.append("The page could not be loaded, so only the link itself was checked.")
    on_the_fence = (ml_probability is not None and
                    settings.uncertain_low <= ml_probability < settings.uncertain_high)
    if on_the_fence:
        notes.append("The model is undecided about this page.")
    if out_of_distribution:
        notes.append("This page is unlike the pages the model was trained on, so its "
                     "opinion is less reliable.")
    if ml_probability is None:
        notes.append("No trained model is loaded; only rule checks ran.")

    if fetch_failed or on_the_fence or out_of_distribution:
        return ScoreOutcome(Verdict.UNSURE, risk, rule_risk, notes)
    return ScoreOutcome(Verdict.SAFE, risk, rule_risk, notes)
