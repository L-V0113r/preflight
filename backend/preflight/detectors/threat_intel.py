"""
Offline reputation lookups.

Known-bad URLs and domains are downloaded ahead of time by
update_threat_feeds.py and checked locally, so the URLs you visit are never
sent to a third-party reputation service. The trade-off: the list is only as
fresh as your last update, and every result says how old it is.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from preflight.parsing import url_tools as ut
from preflight.schema import Finding, Severity

FEEDS_SUBDIR = "feeds"
METADATA_FILE = "feeds_metadata.json"


def _clean_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _append_domain(path: Path, domain: str) -> None:
    """Add one domain to a list file, unless it is already there."""
    existing = {line.lower() for line in _clean_lines(path)}
    if domain.lower() in existing:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{domain}\n")


def _url_key(url: str) -> str:
    """Normalise a URL for matching: no scheme, no fragment, no trailing slash."""
    try:
        url = ut.normalise_url(url)
    except ValueError:
        return url.strip().lower()
    return url.split("://", 1)[-1].rstrip("/")


@dataclass
class ThreatIntel:
    bad_urls: set[str] = field(default_factory=set)
    bad_domains: set[str] = field(default_factory=set)
    trusted_domains: set[str] = field(default_factory=set)   # user's "Ignore" list
    protected_domains: frozenset[str] = frozenset()
    updated_at: float | None = None       # unix time of the newest feed download
    sources: list[str] = field(default_factory=list)
    data_dir: Path | None = None          # so we can append back to the list files

    BLOCKLIST_FILE = "blocklist_domains.txt"
    ALLOWLIST_FILE = "allowlist_domains.txt"

    @classmethod
    def load(cls, data_dir: Path) -> "ThreatIntel":
        """Load the hand-maintained lists plus any downloaded feeds."""
        intel = cls()
        intel.data_dir = data_dir
        intel.protected_domains = frozenset(
            d.lower() for d in _clean_lines(data_dir / "protected_domains.txt"))
        intel.bad_domains.update(d.lower() for d in _clean_lines(data_dir / cls.BLOCKLIST_FILE))
        intel.trusted_domains.update(d.lower() for d in _clean_lines(data_dir / cls.ALLOWLIST_FILE))
        intel.bad_urls.update(_url_key(u) for u in _clean_lines(data_dir / "blocklist_urls.txt"))

        feeds_dir = data_dir / FEEDS_SUBDIR
        for feed_file in sorted(feeds_dir.glob("*_urls.txt")) if feeds_dir.exists() else []:
            intel.bad_urls.update(_url_key(u) for u in _clean_lines(feed_file))
        for feed_file in sorted(feeds_dir.glob("*_domains.txt")) if feeds_dir.exists() else []:
            intel.bad_domains.update(d.lower() for d in _clean_lines(feed_file))

        meta_path = feeds_dir / METADATA_FILE
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                times = [entry["fetched_at"] for entry in meta.get("feeds", [])]
                intel.updated_at = max(times) if times else None
                intel.sources = [entry["name"] for entry in meta.get("feeds", [])]
            except (ValueError, KeyError, TypeError):
                pass
        return intel

    @property
    def size(self) -> int:
        return len(self.bad_urls) + len(self.bad_domains)

    def age_days(self) -> float | None:
        if self.updated_at is None:
            return None
        return (time.time() - self.updated_at) / 86_400

    def check(self, urls: list[str]) -> list[Finding]:
        """Check every URL in a redirect chain against the lists."""
        for url in urls:
            if _url_key(url) in self.bad_urls:
                return [self._hit(url, "This exact link")]
            host = ut.get_host(url)
            labels = host.split(".")
            # Check the host and each parent domain (a.b.evil.com -> b.evil.com -> evil.com).
            for i in range(len(labels) - 1):
                candidate = ".".join(labels[i:])
                if candidate in self.bad_domains:
                    return [self._hit(url, f"The domain '{candidate}'")]
        return []

    def is_trusted(self, urls: list[str]) -> bool:
        """True if any URL's registrable domain is in the trust-list."""
        for url in urls:
            host = ut.get_host(url)
            if host and ut.registrable_domain(host) in self.trusted_domains:
                return True
        return False

    def add_domain(self, url: str, *, block: bool) -> str:
        """Add the site's registrable domain to the block-list (block=True) or
        trust-list (block=False). Updates the in-memory set and appends to the
        list file. Returns the domain."""
        domain = ut.registrable_domain(ut.get_host(url))
        if not domain:
            raise ValueError("could not work out the site's domain")
        target_set = self.bad_domains if block else self.trusted_domains
        other_set = self.trusted_domains if block else self.bad_domains
        other_set.discard(domain)          # block-list and trust-list are mutually exclusive
        target_set.add(domain)
        if self.data_dir is not None:
            filename = self.BLOCKLIST_FILE if block else self.ALLOWLIST_FILE
            _append_domain(self.data_dir / filename, domain)
        return domain

    @staticmethod
    def _hit(url: str, what: str) -> Finding:
        return Finding(
            detector_id="intel.blocklist",
            title="Listed as malicious by a threat feed",
            explanation=f"{what} appears on a downloaded list of known phishing or malware "
                        "sites. Lists can occasionally be wrong, but this is strong evidence.",
            severity=Severity.CRITICAL,
            category="reputation",
            evidence=url[:160],
        )
