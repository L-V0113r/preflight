"""Numeric features computed from the URL and the redirect chain alone."""

from __future__ import annotations

import math
import re
from urllib.parse import parse_qsl, urlsplit

from preflight.parsing import url_tools as ut

_SENSITIVE_PATH_WORDS = re.compile(
    r"login|log-in|signin|sign-in|verify|verification|secure|account|update|"
    r"banking|wallet|password|confirm|webscr|billing|unlock|recover",
    re.IGNORECASE)


def url_features(context) -> dict[str, float]:
    """`context` is a preflight.context.ScanContext (not imported to avoid a cycle)."""
    url = context.url
    parts = urlsplit(url)
    host = context.host
    protected = context.protected_domains
    chain = context.page.redirect_chain

    cross_site_hops = 0
    for previous, nxt in zip(chain, chain[1:]):
        if not ut.same_site(previous, nxt):
            cross_site_hops += 1

    return {
        "url_length_log": math.log1p(len(url)),
        "host_length": float(len(host)),
        "subdomain_depth": float(ut.subdomain_depth(host)),
        "host_digit_count": float(sum(ch.isdigit() for ch in host)),
        "host_hyphen_count": float(host.count("-")),
        "host_entropy": ut.shannon_entropy(ut.brand_label(ut.registrable_domain(host))),
        "path_depth": float(parts.path.count("/")),
        "query_param_count": float(len(parse_qsl(parts.query, keep_blank_values=True))),
        "has_userinfo_at": float("@" in parts.netloc),
        "host_is_ip": float(ut.is_ip_address(host)),
        "is_https": float(parts.scheme == "https"),
        "uses_punycode": float(ut.uses_punycode(host)),
        "suspicious_tld": float(ut.tld_of(host) in ut.SUSPICIOUS_TLDS),
        "is_shortener": float(ut.registrable_domain(host) in ut.URL_SHORTENERS),
        "brand_lookalike": float(ut.find_lookalike(host, protected) is not None),
        "brand_in_unrelated_url": float(ut.brand_mentioned_elsewhere(url, protected) is not None),
        "sensitive_path_words": float(len(_SENSITIVE_PATH_WORDS.findall(parts.path + parts.query))),
        "redirect_count": float(max(len(chain) - 1, 0)),
        "cross_site_redirects": float(cross_site_hops),
        "final_site_differs": float(bool(chain) and not ut.same_site(url, context.final_url)),
    }
