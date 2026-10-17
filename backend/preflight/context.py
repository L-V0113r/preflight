"""
ScanContext: everything known about one scan, computed lazily and once.

Both the rule detectors and the feature extractor read from the same context,
so expensive work (parsing, script analysis) happens a single time per scan
and both halves of the system always see identical evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property

from preflight.features.script_analysis import ScriptProfile, analyse_scripts
from preflight.features.text_analysis import TextProfile, analyse_text
from preflight.parsing import PageDocument, parse_html
from preflight.parsing import url_tools as ut
from preflight.schema import FetchedPage


@dataclass
class ScanContext:
    url: str                              # normalised URL the user clicked
    page: FetchedPage
    doc: PageDocument
    protected_domains: frozenset[str]
    mode: str = "full"                    # "full" or "url_only"

    @classmethod
    def build(cls, url: str, page: FetchedPage, protected_domains: frozenset[str],
              mode: str = "full") -> "ScanContext":
        """Parse the page (if there is HTML to parse) and wrap it in a context."""
        base = page.final_url or url
        html = page.body if (mode == "full" and page.is_html) else ""
        return cls(url=url, page=page, doc=parse_html(html, base),
                   protected_domains=protected_domains, mode=mode)

    # ----------------------------------------------------------- identities
    @cached_property
    def final_url(self) -> str:
        return self.page.final_url or self.url

    @cached_property
    def host(self) -> str:
        return ut.get_host(self.url)

    @cached_property
    def final_host(self) -> str:
        return ut.get_host(self.final_url)

    @cached_property
    def site(self) -> str:
        """Registrable domain of the page that was finally loaded."""
        return ut.registrable_domain(self.final_host)

    @property
    def content_analysed(self) -> bool:
        """True if we actually have page content to judge (not just the URL)."""
        return self.mode == "full" and self.page.fetched_ok

    # ------------------------------------------------------------- analysis
    @cached_property
    def scripts(self) -> ScriptProfile:
        blocks = self.doc.inline_code_blocks + list(self.page.external_scripts.values())
        return analyse_scripts(blocks, self.is_same_site)

    @cached_property
    def text(self) -> TextProfile:
        return analyse_text(f"{self.doc.title} {self.doc.text}")

    def is_same_site(self, other_url: str) -> bool:
        host = ut.get_host(other_url)
        return bool(host) and ut.registrable_domain(host) == self.site

    def brands_claimed(self) -> set[str]:
        """
        Protected brands the page presents itself as: named in the <title> or
        a main heading. (A brand merely mentioned elsewhere, such as a "We
        accept PayPal" footer, is not a claim of identity.)
        """
        squash = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())  # noqa: E731
        blob = squash(" ".join([self.doc.title, *self.doc.headings]))
        found = set()
        for domain in self.protected_domains:
            name = squash(ut.brand_label(domain))
            if len(name) >= 5 and name in blob:
                found.add(domain)
        return found
