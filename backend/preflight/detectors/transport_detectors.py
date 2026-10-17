"""Rules about how the page was delivered: redirects, certificates and downloads."""

from __future__ import annotations

from preflight.context import ScanContext
from preflight.detectors.base import finding, register
from preflight.features.page_features import is_executable_url
from preflight.parsing import url_tools as ut
from preflight.schema import Severity

MALWARE = "malware-delivery"


@register
def certificate_problem(ctx: ScanContext):
    if ctx.page.tls_error:
        yield finding(
            "transport.tls", "The site's security certificate is not valid",
            "Your browser would show a certificate warning. Either the site is misconfigured "
            "or someone is impersonating it.",
            Severity.HIGH, "transport", ctx.page.fetch_error or "")


@register
def cross_site_redirects(ctx: ScanContext):
    chain = ctx.page.redirect_chain
    hops = [(a, b) for a, b in zip(chain, chain[1:]) if not ut.same_site(a, b)]
    if len(hops) >= 2:
        sites = " → ".join(dict.fromkeys(ut.registrable_domain(ut.get_host(u)) for u in chain))
        yield finding(
            "transport.redirects", f"Link bounced through {len(hops)} different sites",
            "Malicious ad and scam links often pass through several unrelated sites to "
            "hide where they really end up.",
            Severity.MEDIUM, "malvertising", sites)


@register
def direct_executable_download(ctx: ScanContext):
    page = ctx.page
    disposition = page.headers.get("content-disposition", "")
    is_program = page.binary_signature.endswith("executable") or is_executable_url(ctx.final_url)
    if not (is_program or ("attachment" in disposition.lower() and
                           is_executable_url(disposition.split("=")[-1].strip("\"' ")))):
        return
    surprise = not ut.same_site(ctx.url, ctx.final_url)
    yield finding(
        "transport.executable", "This link downloads a program",
        "Clicking will download software that can run on your computer"
        + (", from a different site than the one you clicked." if surprise else ".")
        + " Only continue if you meant to install something from this publisher.",
        Severity.HIGH if surprise else Severity.MEDIUM, MALWARE,
        page.binary_signature or disposition or ctx.final_url[:120])
