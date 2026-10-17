"""Rules that only need the link itself (they run even if the page can't be fetched)."""

from __future__ import annotations

from urllib.parse import urlsplit

from preflight.context import ScanContext
from preflight.detectors.base import finding, register
from preflight.parsing import url_tools as ut
from preflight.schema import Severity

PHISHING = "phishing"
DECEPTION = "deceptive-link"


@register
def ip_address_host(ctx: ScanContext):
    if ut.is_ip_address(ctx.host):
        yield finding(
            "url.ip_host", "Link goes to a raw IP address",
            "Real organisations almost always use a domain name. Raw IP addresses are "
            "common in phishing and malware links because they are cheap and disposable.",
            Severity.MEDIUM, DECEPTION, ctx.host)


@register
def userinfo_trick(ctx: ScanContext):
    netloc = urlsplit(ctx.url).netloc
    if "@" in netloc:
        shown, _, real = netloc.rpartition("@")
        yield finding(
            "url.userinfo_at", "The link hides its real destination behind an '@'",
            f"Everything before the '@' is ignored by the browser. The link looks like it "
            f"goes to '{shown[:40]}' but actually goes to '{real[:60]}'.",
            Severity.HIGH, DECEPTION, netloc)


@register
def lookalike_domain(ctx: ScanContext):
    imitated = ut.find_lookalike(ctx.host, ctx.protected_domains)
    if not imitated:
        return
    shown = ut.decode_idn(ctx.host)
    if ut.uses_punycode(ctx.host):
        explanation = (f"'{shown}' uses look-alike international characters to imitate "
                       f"'{imitated}'. It is a different website.")
    else:
        explanation = (f"'{ctx.host}' is spelled almost exactly like '{imitated}' "
                       "(a typo-squatting domain). It is a different website.")
    yield finding("url.lookalike", f"Domain imitates {imitated}", explanation,
                  Severity.HIGH, PHISHING, shown)


@register
def brand_in_unrelated_url(ctx: ScanContext):
    brand = ut.brand_mentioned_elsewhere(ctx.url, ctx.protected_domains)
    if brand:
        owner = ut.registrable_domain(ctx.host)
        yield finding(
            "url.brand_elsewhere", f"Link uses the name '{ut.brand_label(brand)}' but belongs to {owner}",
            f"The brand's name appears in the link, but the site is actually owned by "
            f"'{owner}', not '{brand}'. Phishing links do this to look trustworthy.",
            Severity.MEDIUM, PHISHING, ctx.url[:120])


@register
def punycode_domain(ctx: ScanContext):
    # Only a weak signal on its own: many legitimate non-English domains use it.
    if ut.uses_punycode(ctx.host) and not ut.find_lookalike(ctx.host, ctx.protected_domains):
        yield finding(
            "url.punycode", "Domain uses international characters",
            f"The domain is displayed as '{ut.decode_idn(ctx.host)}'. That is normal for many "
            "non-English sites, but check it is the site you expect.",
            Severity.LOW, DECEPTION, ctx.host)


@register
def suspicious_tld(ctx: ScanContext):
    tld = ut.tld_of(ctx.host)
    if tld in ut.SUSPICIOUS_TLDS:
        yield finding(
            "url.tld", f"Domain ending '.{tld}' is frequently abused",
            "Cheap domain endings are disproportionately used for scams. Many honest sites "
            "use them too, so this only slightly raises the risk.",
            Severity.LOW, DECEPTION, ctx.host)


@register
def url_shortener(ctx: ScanContext):
    if ut.registrable_domain(ctx.host) in ut.URL_SHORTENERS:
        final = ctx.final_host or "unknown (could not follow it)"
        yield finding(
            "url.shortener", "Shortened link",
            f"Short links hide where they go. PreFlight followed it to: {final}.",
            Severity.LOW, DECEPTION, ctx.host)


@register
def excessive_subdomains(ctx: ScanContext):
    depth = ut.subdomain_depth(ctx.host)
    if depth >= 4:
        yield finding(
            "url.subdomains", "Unusually long chain of sub-domains",
            f"The host has {depth} parts in front of the real domain "
            f"'{ut.registrable_domain(ctx.host)}', a trick used to push the real owner "
            "out of view on small screens.",
            Severity.LOW, DECEPTION, ctx.host)


@register
def plain_http(ctx: ScanContext):
    if urlsplit(ctx.final_url).scheme == "http":
        has_password = any(i.input_type == "password" for i in ctx.doc.all_inputs)
        yield finding(
            "url.http", "Connection is not encrypted",
            "Anything you type on this page could be read or changed by others on the network."
            + (" This page asks for a password." if has_password else ""),
            Severity.MEDIUM if has_password else Severity.LOW, "transport", ctx.final_url[:120])
