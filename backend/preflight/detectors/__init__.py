"""
Rule-based detectors for known attack classes.

Importing the modules below registers their detectors (see base.register).
The rules give PreFlight precise, explainable answers for attacks we already
understand; the ML model (preflight.ml) covers the grey areas in between.
"""

# Imported for their side effect of registering detectors.
from preflight.detectors import (  # noqa: F401
    content_detectors,
    form_detectors,
    script_detectors,
    transport_detectors,
    url_detectors,
)
from preflight.detectors.base import finding, register, registered_detectors, run_detectors
from preflight.detectors.threat_intel import ThreatIntel

__all__ = ["ThreatIntel", "finding", "register", "registered_detectors", "run_detectors"]
