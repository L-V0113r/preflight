"""Shared helpers for the tests."""

from __future__ import annotations

from preflight.config import default_config
from preflight.context import ScanContext
from preflight.detectors import ThreatIntel
from preflight.schema import FetchedPage

CONFIG = default_config()
INTEL = ThreatIntel.load(CONFIG.threat_data_dir)


def page_from_html(html: str, url: str = "https://example-site.com/") -> FetchedPage:
    return FetchedPage(requested_url=url, final_url=url, status=200, body=html,
                       content_type="text/html", redirect_chain=[url])


def context_for(html: str, url: str = "https://example-site.com/") -> ScanContext:
    return ScanContext.build(url, page_from_html(html, url), INTEL.protected_domains)


def detector_ids(findings) -> set[str]:
    return {f.detector_id for f in findings}
