"""
PreFlight: a small local AI that checks a web page for attacks on the visitor
*before* the browser loads it.

Package layout (each sub-package is a small home-made library):

    preflight.schema       Shared data types (findings, fetched pages, results).
    preflight.config       All tunable settings in one place.
    preflight.net          Safe fetching: SSRF guard, pinned connections, limits.
    preflight.parsing      URL helpers and a tolerant HTML parser.
    preflight.features     Turns a page into numbers the model can learn from.
    preflight.detectors    Hand-written rules for known attack classes.
    preflight.ml           The machine-learning model, training and evaluation.
    preflight.data         Labelled synthetic data and loaders for real data.
    preflight.scoring      Combines rule findings and model output into a verdict.
    preflight.scanner      Orchestrates the whole pipeline for one URL.
    preflight.server       The localhost API the browser extension talks to.
"""

__version__ = "0.1.0"
