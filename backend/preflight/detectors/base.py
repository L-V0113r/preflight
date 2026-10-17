"""
The tiny "framework" every rule detector plugs into.

A detector is just a function that takes a ScanContext and yields Findings.
Decorating it with @register adds it to the registry, so adding a new rule
never requires editing the scanner.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from preflight.context import ScanContext
from preflight.schema import Finding, Severity

DetectorFn = Callable[[ScanContext], Iterable[Finding]]

_REGISTRY: list[DetectorFn] = []


def register(fn: DetectorFn) -> DetectorFn:
    """Decorator: add a detector function to the registry."""
    _REGISTRY.append(fn)
    return fn


def registered_detectors() -> tuple[DetectorFn, ...]:
    return tuple(_REGISTRY)


def finding(detector_id: str, title: str, explanation: str, severity: Severity,
            category: str, evidence: str = "") -> Finding:
    """Small factory so detectors read cleanly and evidence is always trimmed."""
    evidence = " ".join(str(evidence).split())[:160]
    return Finding(detector_id=detector_id, title=title, explanation=explanation,
                   severity=severity, category=category, evidence=evidence)


def run_detectors(context: ScanContext, detectors: Iterable[DetectorFn] | None = None
                  ) -> tuple[list[Finding], list[str]]:
    """
    Run every detector. A detector that crashes must not crash the scan, so
    errors are collected as notes (and shown to the user as "partial scan").
    """
    findings: list[Finding] = []
    errors: list[str] = []
    for detector in detectors or registered_detectors():
        try:
            findings.extend(detector(context))
        except Exception as exc:  # noqa: BLE001 - one bad rule must not stop the others
            errors.append(f"check '{detector.__name__}' failed: {type(exc).__name__}")
    return findings, errors
