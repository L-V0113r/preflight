"""Feature extraction: turns a page into numbers (and profiles detectors reuse)."""

from preflight.features.script_analysis import ScriptProfile, analyse_scripts
from preflight.features.text_analysis import TextProfile, analyse_text
from preflight.features.vectoriser import (
    FEATURE_DESCRIPTIONS,
    FEATURE_NAMES,
    URL_FEATURE_NAMES,
    extract_feature_dict,
    to_vector,
)

__all__ = [
    "FEATURE_DESCRIPTIONS",
    "FEATURE_NAMES",
    "URL_FEATURE_NAMES",
    "ScriptProfile",
    "TextProfile",
    "analyse_scripts",
    "analyse_text",
    "extract_feature_dict",
    "to_vector",
]
