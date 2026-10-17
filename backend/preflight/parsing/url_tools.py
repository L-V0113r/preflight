"""
Home-made URL and domain helpers.

Nothing here touches the network. These functions answer questions such as
"what is the real domain behind this link?" and "does this domain look like
a well-known brand?".
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Public suffixes that have two labels. A complete solution uses the Public
# Suffix List (https://publicsuffix.org); this short list covers the common
# cases without adding a dependency. Extend it if you scan other countries.
_MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "nhs.uk", "police.uk", "sch.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.in", "org.in", "gov.in",
    "com.br", "com.mx", "com.cn", "com.tr", "co.za", "com.sg", "com.hk",
    "github.io", "pages.dev", "netlify.app", "vercel.app", "web.app",
    "firebaseapp.com", "herokuapp.com", "blogspot.com", "azurewebsites.net",
    "cloudfront.net", "workers.dev", "r2.dev", "glitch.me", "repl.co",
})

# Free hosting platforms above are treated as suffixes on purpose: each
# customer sub-domain (evil.github.io) is a different owner.

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc",
    "s.id", "v.gd", "bl.ink",
})

# Top-level domains that are cheap and often abused. This is a WEAK signal:
# plenty of honest sites use them, so it only ever adds a LOW finding.
SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf",
    "ga", "work", "support", "rest", "cam", "icu", "buzz", "monster", "cfd",
    "sbs", "quest", "lol",
})

# Characters that look like Latin letters. Used to build a "skeleton" of a
# domain so that pаypal (Cyrillic a) and paypal compare equal. This is a
# small hand-picked subset of Unicode's confusables data (UTS #39).
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i",
    "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q",
    "ԝ": "w",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # Latin look-alikes and digits commonly swapped in typosquats
    "ı": "i", "ɡ": "g", "ł": "l", "0": "o", "1": "l", "3": "e", "5": "s",
    "@": "a", "$": "s",
}
# Multi-character tricks ("rn" looks like "m", "vv" like "w").
_MULTI_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def normalise_url(raw_url: str) -> str:
    """
    Validate and tidy a URL. Raises ValueError for anything we will not scan.

    * Only http and https are accepted (no javascript:, data:, file:, ...).
    * The fragment (#...) is dropped because the server never sees it.
    * The host is lower-cased.
    """
    if not isinstance(raw_url, str):
        raise ValueError("URL must be a string")
    url = raw_url.strip()
    if len(url) > 8_192:
        raise ValueError("URL is too long")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Only http and https links are scanned (got '{scheme}')")
    if not parts.hostname:
        raise ValueError("URL has no host name")
    netloc = parts.netloc
    host = parts.hostname
    # Rebuild netloc with a lower-case host but keep userinfo and port.
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        netloc = f"{userinfo}@{hostport.lower()}"
    else:
        netloc = netloc.lower()
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def get_host(url: str) -> str:
    """Return the lower-case host name of a URL ('' if there is none)."""
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str:
    """
    Approximate the "registrable domain" (what a person actually buys).

        login.secure.example.co.uk -> example.co.uk
        paypal.com.account-check.xyz -> account-check.xyz

    This is the part of a host name that identifies the owner, so comparing
    registrable domains tells us whether two URLs belong to the same site.
    """
    host = host.lower().rstrip(".")
    if not host or is_ip_address(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def same_site(url_a: str, url_b: str) -> bool:
    """True if both URLs share a registrable domain."""
    host_a, host_b = get_host(url_a), get_host(url_b)
    if not host_a or not host_b:
        return False
    return registrable_domain(host_a) == registrable_domain(host_b)


def subdomain_depth(host: str) -> int:
    """Number of labels in front of the registrable domain."""
    if not host or is_ip_address(host):
        return 0
    base = registrable_domain(host)
    extra = host[: -len(base)].rstrip(".") if host != base else ""
    return 0 if not extra else extra.count(".") + 1


def tld_of(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else host


def shannon_entropy(text: str) -> float:
    """
    Bits of randomness per character. Random strings (generated domains,
    packed code) score high; normal words score low.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def decode_idn(host: str) -> str:
    """Turn xn--pypal-4ve.com back into the Unicode the user would see."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def uses_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def skeleton(text: str) -> str:
    """Map look-alike characters to plain Latin so look-alikes compare equal."""
    mapped = "".join(_CONFUSABLES.get(ch, ch) for ch in text.lower())
    for fake, real in _MULTI_CONFUSABLES:
        mapped = mapped.replace(fake, real)
    return mapped


def levenshtein(a: str, b: str, limit: int | None = None) -> int:
    """
    Edit distance: the number of single-character insertions, deletions or
    substitutions to turn `a` into `b`. Classic dynamic programming, keeping
    only one previous row to save memory. If `limit` is given we stop early
    once the distance is certainly larger than it.
    """
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if limit is not None and len(a) - len(b) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current.append(min(previous[j] + 1,        # deletion
                               current[j - 1] + 1,     # insertion
                               previous[j - 1] + cost))  # substitution
        if limit is not None and min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def brand_label(domain: str) -> str:
    """The distinctive word of a registrable domain: paypal.com -> paypal."""
    return domain.split(".", 1)[0]


def find_lookalike(host: str, protected_domains: frozenset[str]) -> str | None:
    """
    Return the protected domain that `host` imitates, or None.

    A host imitates a protected domain when its registrable domain is NOT that
    domain but its distinctive label is the same after removing look-alike
    characters, or within a small edit distance (typosquatting).
    """
    if not host or is_ip_address(host):
        return None
    candidate = registrable_domain(decode_idn(host))
    if candidate in protected_domains:
        return None
    candidate_label = skeleton(brand_label(candidate))
    for protected in protected_domains:
        label = brand_label(protected)
        if len(label) < 4:
            continue  # very short brand names cause too many false alarms
        if candidate_label == label:
            return protected
        allowed = 1 if len(label) <= 6 else 2
        if levenshtein(candidate_label, label, limit=allowed) <= allowed:
            return protected
    return None


def brand_mentioned_elsewhere(url: str, protected_domains: frozenset[str]) -> str | None:
    """
    Detect "paypal.com.secure-check.xyz" or "evil.xyz/paypal/login": a brand's
    name appears in a URL whose registrable domain belongs to someone else.
    """
    host = get_host(url)
    if not host:
        return None
    owner = registrable_domain(host)
    if owner in protected_domains:
        return None
    parts = urlsplit(url)
    in_front = host[: -len(owner)] if host.endswith(owner) else host
    haystack = f"{in_front} {parts.path} {parts.query}".lower()
    for protected in protected_domains:
        label = brand_label(protected)
        if len(label) >= 5 and label in haystack:
            return protected
    return None
