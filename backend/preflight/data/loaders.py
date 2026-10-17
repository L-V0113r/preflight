"""
Loaders for REAL labelled data, so you can move beyond synthetic pages.

Two formats are supported:

1. A folder of saved HTML pages:

       my_dataset/
         benign/      page1.html   page1.url   (optional .url file = original URL)
         malicious/   phish1.html  phish1.url

   Collect benign pages from sites you trust (e.g. the Tranco top list) and
   malicious pages from feeds such as OpenPhish, using `scan_cli.py --save-html`
   which fetches WITHOUT running any code. Respect each source's terms.

2. A CSV of URLs with labels (columns: url,label where label is 0 or 1).
   These become URL-only samples (no page content), which is how a link
   behaves when it cannot be fetched.

Real data must never include anyone's private browsing or personal data.
"""

from __future__ import annotations

import csv
from pathlib import Path

from preflight.data.synthetic import LabelledPage
from preflight.schema import FetchedPage

_PLACEHOLDER_URL = "https://unknown-origin.invalid/"


def load_html_folder(root: Path) -> list[LabelledPage]:
    samples: list[LabelledPage] = []
    for label_name, label in (("benign", 0), ("malicious", 1)):
        folder = root / label_name
        if not folder.is_dir():
            continue
        for html_file in sorted(folder.glob("*.html")):
            url_file = html_file.with_suffix(".url")
            url = url_file.read_text(encoding="utf-8").strip() if url_file.exists() else _PLACEHOLDER_URL
            page = FetchedPage(
                requested_url=url, final_url=url, status=200,
                body=html_file.read_text(encoding="utf-8", errors="replace"),
                content_type="text/html", redirect_chain=[url],
            )
            samples.append(LabelledPage(page, label, f"real_{label_name}"))
    return samples


def load_url_csv(path: Path) -> list[LabelledPage]:
    samples: list[LabelledPage] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            url = (row.get("url") or "").strip()
            if not url:
                continue
            label = int(row.get("label", 0))
            page = FetchedPage(requested_url=url, final_url=url, redirect_chain=[url],
                               fetch_error="url-only sample")
            samples.append(LabelledPage(page, label, f"real_url_{label}", url_only=True))
    return samples
