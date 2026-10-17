"""
Turn a ScanContext into a fixed-length list of numbers (a "feature vector").

Machine-learning models need every example described by the same numbers in
the same order. FEATURE_DESCRIPTIONS is the single source of truth for that
order, and also supplies the plain-English text used when the model explains
itself to the user.
"""

from __future__ import annotations

import numpy as np

from preflight.features.page_features import page_features, script_features, text_features
from preflight.features.url_features import url_features

FEATURE_DESCRIPTIONS: dict[str, str] = {
    # URL and redirects
    "url_length_log": "very long link",
    "host_length": "long host name",
    "subdomain_depth": "many sub-domains in front of the real domain",
    "host_digit_count": "digits in the host name",
    "host_hyphen_count": "hyphens in the host name",
    "host_entropy": "random-looking domain name",
    "path_depth": "deep link path",
    "query_param_count": "many link parameters",
    "has_userinfo_at": "an '@' that hides the real destination",
    "host_is_ip": "a raw IP address instead of a name",
    "is_https": "encrypted connection (https)",
    "uses_punycode": "international (punycode) characters in the domain",
    "suspicious_tld": "a frequently abused domain ending",
    "is_shortener": "a link shortener hiding the destination",
    "brand_lookalike": "a domain that looks like a well-known brand",
    "brand_in_unrelated_url": "a brand name inside someone else's link",
    "sensitive_path_words": "words like 'login' or 'verify' in the link",
    "redirect_count": "several redirects",
    "cross_site_redirects": "redirects that jump between different sites",
    "final_site_differs": "landing on a different site from the one clicked",
    # Page structure
    "content_available": "page content was analysed",
    "text_length_log": "amount of visible text",
    "link_count_log": "number of links",
    "external_link_ratio": "most links point to other sites",
    "form_count": "number of forms",
    "password_inputs": "password boxes",
    "password_form_external_action": "a password form that sends to another site",
    "password_form_insecure_action": "a password form sent without encryption",
    "card_fields": "payment card boxes",
    "title_brand_mismatch": "page presents itself as a brand it is not hosted by",
    "iframe_count": "embedded frames",
    "hidden_iframes": "hidden embedded frames",
    "hidden_cross_site_iframes": "hidden frames loading another site",
    "iframe_in_overlay": "a frame inside a floating pop-up",
    "fixed_overlays": "floating full-screen layers",
    "external_script_count": "external scripts",
    "third_party_script_domains": "scripts from many other sites",
    "inline_event_handlers_log": "inline event-handler code",
    "meta_refresh_external": "an automatic redirect to another site",
    "executable_links": "links to program files",
    "attachment_download": "the link downloads a file",
    "binary_executable_response": "the link returns a program file",
    "tls_error": "an invalid security certificate",
    "embeds": "embedded plug-in objects",
    # Text
    "text_urgency": "pressure language ('account suspended', 'within 24 hours')",
    "text_paste_and_run": "instructions to open Run and paste something",
    "text_human_check": "a 'verify you are human' check",
    "text_tech_support": "fake virus / support warnings",
    "text_phone_numbers": "phone numbers",
    "text_fake_update": "a fake 'update your browser' message",
    "text_push_bait": "'click Allow to continue' bait",
    # JavaScript
    "js_chars_log": "amount of JavaScript",
    "js_eval": "code that runs other code (eval)",
    "js_decoders": "code-decoding functions",
    "js_decode_and_run": "decode-then-run code (packed loader)",
    "js_document_write": "code that writes into the page",
    "js_hex_escape_density": "heavily escaped code",
    "js_long_strings": "long encoded strings",
    "js_max_string_entropy": "random-looking encoded data",
    "js_clipboard_write": "code that writes to your clipboard",
    "js_lolbin_terms": "Windows command-line tool names in code",
    "js_clipboard_with_command": "a command placed on your clipboard",
    "js_keylogger_blocks": "code that records typing and sends it away",
    "js_miner_terms": "cryptocurrency-mining code",
    "js_wasm": "WebAssembly",
    "js_workers": "background worker threads",
    "js_websockets": "live socket connections",
    "js_fullscreen": "forcing full-screen mode",
    "js_alert_loops": "endless pop-up alerts",
    "js_before_unload": "blocking you from leaving",
    "js_notification_requests": "notification permission requests",
    "js_window_opens": "opening new windows",
    "js_location_changes": "script-driven redirects",
    "js_executable_strings": "program file names in code",
}

FEATURE_NAMES: tuple[str, ...] = tuple(FEATURE_DESCRIPTIONS)

# Features that come from the link and redirect chain only (no page content).
URL_FEATURE_NAMES: frozenset[str] = frozenset(FEATURE_NAMES[:FEATURE_NAMES.index("content_available")])


def extract_feature_dict(context) -> dict[str, float]:
    """All features for one context, as a name -> value dictionary."""
    features: dict[str, float] = {}
    features.update(url_features(context))
    features.update(page_features(context))
    features.update(text_features(context))
    features.update(script_features(context))
    missing = set(FEATURE_NAMES) - features.keys()
    extra = features.keys() - set(FEATURE_NAMES)
    if missing or extra:  # catches drift between extractors and the spec
        raise RuntimeError(f"feature mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    return features


def to_vector(features: dict[str, float]) -> np.ndarray:
    """Dictionary -> 1-D numpy array in FEATURE_NAMES order."""
    return np.array([features[name] for name in FEATURE_NAMES], dtype=np.float64)
