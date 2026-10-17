"""
Download public threat feeds into threat_data/feeds/ for OFFLINE lookups.

    python update_threat_feeds.py
    URLHAUS_AUTH_KEY=xxxx python update_threat_feeds.py     # also fetch URLhaus

Feeds (check each source's terms before use; both are free for
non-commercial use at the time of writing):

* OpenPhish community feed - phishing URLs, updated about every 12 hours,
  non-commercial use only. https://github.com/openphish/public_feed
* URLhaus (abuse.ch) - malware distribution URLs. Requires a free Auth-Key
  from https://auth.abuse.ch/ (set URLHAUS_AUTH_KEY). Fair-use terms apply.

Because lookups happen on your machine, the sites you visit are never sent
to these services. Run this daily (e.g. with cron or Task Scheduler).
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
import urllib.request

from preflight.config import THREAT_DATA_DIR
from preflight.detectors.threat_intel import FEEDS_SUBDIR, METADATA_FILE

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
MAX_FEED_BYTES = 50_000_000
USER_AGENT = "PreFlight-feed-updater/0.1 (+local, non-commercial)"


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https URLs
        data = response.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("feed is larger than expected; refusing")
    return data


def parse_openphish(raw: bytes) -> list[str]:
    return [line.strip() for line in raw.decode("utf-8", "replace").splitlines()
            if line.strip().startswith(("http://", "https://"))]


def parse_urlhaus_csv(raw: bytes) -> list[str]:
    text = "\n".join(line for line in raw.decode("utf-8", "replace").splitlines()
                     if not line.startswith("#"))
    urls = []
    for row in csv.reader(io.StringIO(text)):
        # Columns: id, dateadded, url, url_status, ... (we only need the url)
        if len(row) > 2 and row[2].startswith(("http://", "https://")):
            urls.append(row[2])
    return urls


def main() -> None:
    feeds_dir = THREAT_DATA_DIR / FEEDS_SUBDIR
    feeds_dir.mkdir(parents=True, exist_ok=True)
    plan = [("openphish", OPENPHISH_URL, parse_openphish, "OpenPhish community feed (non-commercial)")]
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if key:
        plan.append(("urlhaus", URLHAUS_URL.format(key=key), parse_urlhaus_csv,
                     "URLhaus by abuse.ch (fair use)"))
    else:
        print("URLHAUS_AUTH_KEY not set: skipping URLhaus (get a free key at https://auth.abuse.ch/).")

    metadata = []
    for name, url, parser, licence in plan:
        try:
            urls = parser(download(url))
        except Exception as exc:  # noqa: BLE001 - report and continue with other feeds
            print(f"{name}: FAILED ({type(exc).__name__}: {exc}). Previous copy kept.")
            continue
        out = feeds_dir / f"{name}_urls.txt"
        out.write_text("\n".join(urls) + "\n", encoding="utf-8")
        metadata.append({"name": name, "source": url.split("/exports/")[0], "licence": licence,
                         "entries": len(urls), "fetched_at": time.time()})
        print(f"{name}: {len(urls)} URLs -> {out}")

    if metadata:
        meta_path = feeds_dir / METADATA_FILE
        previous = {}
        if meta_path.exists():
            previous = {e["name"]: e for e in json.loads(meta_path.read_text()).get("feeds", [])}
        previous.update({e["name"]: e for e in metadata})
        meta_path.write_text(json.dumps({"feeds": list(previous.values())}, indent=2))
        print("Restart run_server.py to load the new lists.")


if __name__ == "__main__":
    main()
