"""Rules about the page's HTML structure and visible content."""

from __future__ import annotations

import re

from preflight.context import ScanContext
from preflight.detectors.base import finding, register
from preflight.features.page_features import is_executable_url
from preflight.parsing import url_tools as ut
from preflight.schema import Severity

MALWARE = "malware-delivery"
PHISHING = "phishing"


@register
def hidden_iframes(ctx: ScanContext):
    cross_site = [f for f in ctx.doc.iframes
                  if f.hidden and f.src and not ctx.is_same_site(f.src)]
    if cross_site:
        target = ut.registrable_domain(ut.get_host(cross_site[0].src))
        # Exactly one tiny tracking frame is common on honest sites; several are not.
        severity = Severity.MEDIUM if len(cross_site) == 1 else Severity.HIGH
        yield finding(
            "html.hidden_iframe", "Invisible frame loads another website",
            f"The page contains {len(cross_site)} hidden frame(s) loading '{target}'. "
            "Drive-by attacks use invisible frames to load exploit code or force downloads. "
            "Some advertising and tracking also uses them, which is why this alone is not decisive.",
            severity, MALWARE, cross_site[0].src[:120])


@register
def automatic_redirect(ctx: ScanContext):
    for delay, target in ctx.doc.meta_refresh:
        if not target or ctx.is_same_site(target):
            continue
        if is_executable_url(target):
            yield finding(
                "html.auto_download", "Page automatically downloads a program",
                f"After {delay}s the page sends your browser to a program file on another site. "
                "Downloads you didn't ask for are a common malware delivery method.",
                Severity.HIGH, MALWARE, target[:120])
        elif delay <= 3:
            yield finding(
                "html.meta_redirect", "Page instantly redirects you to another site",
                f"The page forwards you to '{ut.get_host(target)}' after {delay}s.",
                Severity.LOW, "malvertising", target[:120])
        return


@register
def script_triggered_download(ctx: ScanContext):
    s = ctx.scripts
    if s.executable_strings and s.location_changes and ctx.text.fake_update:
        yield finding(
            "page.fake_update", "Fake 'update your browser' download",
            "The page says your browser or player is out of date and its code points to a "
            "program file. Real browser updates never come from web pages like this.",
            Severity.HIGH, MALWARE, ctx.text.evidence.get("fake_update", ""))


_FAKE_ADDRESS_BAR = re.compile(r"https://[a-z0-9.\-]+\.[a-z]{2,}/\S*", re.IGNORECASE)


@register
def browser_in_the_browser(ctx: ScanContext):
    """
    A fake pop-up 'window' drawn with HTML: a floating layer that shows a
    fake address bar (as plain text, not a link) and an iframe login form.
    """
    overlay_frames = [f for f in ctx.doc.iframes if f.inside_fixed_overlay]
    if not overlay_frames:
        return
    fake_bars = _FAKE_ADDRESS_BAR.findall(ctx.doc.text)
    impersonated = [u for u in fake_bars
                    if ut.registrable_domain(ut.get_host(u)) in ctx.protected_domains
                    and not ctx.is_same_site(u)]
    if impersonated:
        yield finding(
            "html.browser_in_browser", "Fake sign-in window drawn inside the page",
            f"The page draws something that looks like a pop-up showing '{impersonated[0][:60]}', "
            "but it is part of this page, not a real browser window. This 'browser-in-the-"
            "browser' trick is used to steal logins.",
            Severity.HIGH, PHISHING, impersonated[0][:120])


@register
def urgency_language(ctx: ScanContext):
    if ctx.text.urgency >= 1 and any(i.input_type == "password" or i.describes("card", "otp", "code")
                                     for i in ctx.doc.all_inputs):
        yield finding(
            "text.urgency", "Pressure language next to a form",
            "Phrases like 'your account will be suspended' push you to act before thinking.",
            Severity.LOW, PHISHING, ctx.text.evidence.get("urgency", ""))
