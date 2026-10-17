"""Rules about forms: where your passwords and card numbers would be sent."""

from __future__ import annotations

from preflight.context import ScanContext
from preflight.detectors.base import finding, register
from preflight.parsing import url_tools as ut
from preflight.schema import Severity

PHISHING = "phishing"
DATA_THEFT = "data-theft"

# Large identity providers that legitimately receive passwords from other
# sites' login pages (single sign-on). Extend for your organisation.
KNOWN_IDENTITY_PROVIDERS = frozenset({
    "microsoftonline.com", "live.com", "google.com", "okta.com", "auth0.com",
    "onelogin.com", "duosecurity.com", "pingidentity.com", "apple.com",
})


def _first_token(domain: str) -> str:
    return domain.split(".")[0].split("-")[0]


@register
def password_sent_elsewhere(ctx: ScanContext):
    for form in ctx.doc.forms:
        if form.has_password and not ctx.is_same_site(form.action):
            target = ut.registrable_domain(ut.get_host(form.action)) or form.action[:60]
            if target in KNOWN_IDENTITY_PROVIDERS:
                return
            if _first_token(target) == _first_token(ctx.site) and len(_first_token(target)) >= 4:
                # e.g. acme-intranet.com -> acme-identity.com: probably the
                # organisation's own single sign-on, but still worth a mention.
                yield finding(
                    "form.password_cross_site_related",
                    "Login form sends your password to a related domain",
                    f"The form on '{ctx.site}' submits to '{target}'. The names match, which is "
                    "typical of company single sign-on, but check you expected this.",
                    Severity.LOW, PHISHING, form.action[:120])
                return
            yield finding(
                "form.password_cross_site", "Password form sends your login to another site",
                f"This page is on '{ctx.site}' but the login form submits to '{target}'. "
                "Genuine sign-in pages almost never do this; phishing kits usually do.",
                Severity.HIGH, PHISHING, form.action[:120])
            return  # one finding is enough


@register
def password_sent_unencrypted(ctx: ScanContext):
    for form in ctx.doc.forms:
        if form.has_password and form.action.startswith("http://"):
            yield finding(
                "form.password_http", "Password would be sent without encryption",
                "The login form submits over plain http, so the password could be read in transit.",
                Severity.HIGH, DATA_THEFT, form.action[:120])
            return


@register
def brand_login_on_wrong_site(ctx: ScanContext):
    has_password = any(i.input_type == "password" for i in ctx.doc.all_inputs)
    if not has_password:
        return
    brands = ctx.brands_claimed()
    if brands and ctx.site not in brands:
        brand = sorted(brands)[0]
        yield finding(
            "form.brand_mismatch", f"Login page claims to be {ut.brand_label(brand)} but isn't on {brand}",
            f"The page asks for a password and presents itself as '{ut.brand_label(brand)}', "
            f"but it is hosted on '{ctx.site}'. This is the classic shape of a phishing page.",
            Severity.HIGH, PHISHING, ctx.doc.title or ctx.site)


@register
def card_form_with_risky_scripts(ctx: ScanContext):
    card_fields = sum(f.card_field_count for f in ctx.doc.forms)
    if card_fields == 0:
        return
    s = ctx.scripts
    if s.keylogger_blocks or s.decode_and_run:
        yield finding(
            "form.card_skimmer", "Payment form with script that can copy what you type",
            "This checkout page collects card details and also runs hidden or obfuscated code "
            "that reads form fields and sends data out. That is how card-skimming "
            "('Magecart') attacks steal payment details.",
            Severity.CRITICAL if s.keylogger_blocks else Severity.HIGH, DATA_THEFT,
            s.evidence.get("keylogger") or s.evidence.get("eval", ""))
