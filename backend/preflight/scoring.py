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

Then honest uncertainty is layered on top. A model on the fence gives
UNSURE. A page that could not be read, or is unlike the training data, gives
UNSURE under the "strict" profile; under "balanced" only when some other
evidence (a finding, or a model score above the profile's floor) backs it.
Profiles are in config.StrictnessProfile.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from preflight.config import ScoringSettings, StrictnessProfile
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
           settings: ScoringSettings, mode: str = "full",
           profile: StrictnessProfile | None = None) -> ScoreOutcome:
    """
    `ml_probability` is the model's probability already adjusted for the
    profile's base rate. `content_analysed` is False when only the URL could
    be judged: the user chose URL-only mode, or (in full mode) the page could
    not be fetched or answered with an error.
    """
    profile = profile or settings.balanced
    rule_risk = noisy_or([SEVERITY_WEIGHT[f.severity] for f in findings])
    evidence = [SEVERITY_WEIGHT[f.severity] for f in findings]
    if ml_probability is not None:
        weight = settings.ml_weight if content_analysed else settings.ml_weight_url_only
        evidence.append(weight * ml_probability)
    risk = noisy_or(evidence)
    notes: list[str] = []

    any_finding = any(f.severity >= Severity.LOW for f in findings)
    concrete = any(f.severity >= Severity.MEDIUM for f in findings)
    suspicious_score = (ml_probability is not None
                        and ml_probability >= profile.suspicious_probability)
    # Whether an otherwise-unsure page has anything pointing at a problem.
    has_reason = any_finding or suspicious_score or not profile.unsure_needs_evidence

    # Page should have been read but couldn't be: judge the link alone.
    fetch_failed = mode == "full" and not content_analysed
    if fetch_failed and not concrete:
        notes.append("The page could not be loaded, so only the link itself was checked.")
        if not has_reason:
            notes.append("Nothing about the link itself looks suspicious.")
            return ScoreOutcome(Verdict.SAFE, risk, rule_risk, notes)
        if ml_probability is not None:
            notes.append(f"Judging from the link alone, the model rates it "
                         f"{ml_probability:.0%} likely to be malicious; treat that as a hint only.")
        return ScoreOutcome(Verdict.UNSURE, risk, rule_risk, notes)

    if any(f.severity == Severity.CRITICAL for f in findings) or risk >= settings.danger_threshold:
        return ScoreOutcome(Verdict.DANGER, risk, rule_risk, notes)
    if risk >= settings.caution_threshold:
        return ScoreOutcome(Verdict.CAUTION, risk, rule_risk, notes)

    # Nothing alarming. Is that because the page is fine, or because we could
    # not really look?
    if fetch_failed:
        notes.append("The page could not be loaded, so only the link itself was checked.")
    on_the_fence = (ml_probability is not None and
                    profile.undecided_from <= ml_probability < settings.uncertain_high)
    if on_the_fence:
        notes.append("The model is undecided about this page.")
    if out_of_distribution:
        notes.append("This page is unlike the pages the model was trained on, so its "
                     "opinion is less reliable.")
    if ml_probability is None:
        notes.append("No trained model is loaded; only rule checks ran.")

    # On the fence is a genuine risk (after base-rate adjustment), so it
    # always asks. An unfamiliar or unreadable page only asks if something else
    # looks off, unless the profile is strict.
    if on_the_fence:
        return ScoreOutcome(Verdict.UNSURE, risk, rule_risk, notes)
    if (fetch_failed or out_of_distribution) and has_reason:
        return ScoreOutcome(Verdict.UNSURE, risk, rule_risk, notes)
    return ScoreOutcome(Verdict.SAFE, risk, rule_risk, notes)
