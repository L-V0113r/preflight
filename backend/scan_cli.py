"""
Scan from the terminal, without the browser.

    python scan_cli.py https://example.com
    python scan_cli.py --file samples/malicious_clickfix.html --as-url https://verify-check.example/
    python scan_cli.py https://example.com --json
    python scan_cli.py https://example.com --save-html dataset/benign   # collect training data
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from preflight.config import default_config
from preflight.parsing import url_tools as ut
from preflight.scanner import Scanner
from preflight.schema import FetchedPage, ScanResult, Verdict

_COLOURS = {Verdict.SAFE: "\033[32m", Verdict.CAUTION: "\033[33m", Verdict.DANGER: "\033[31m",
            Verdict.UNSURE: "\033[36m", Verdict.ERROR: "\033[35m"}
_RESET = "\033[0m"


def print_result(result: ScanResult) -> None:
    colour = _COLOURS.get(result.verdict, "")
    ml = "n/a" if result.ml_probability is None else (
        f"{result.ml_probability:.2f}, raw {result.ml_probability_raw:.2f}")
    print(f"\n{colour}{result.verdict.value.upper()}{_RESET}  risk {result.risk_score:.2f}  "
          f"(model {ml})  {result.url}")
    if result.redirect_chain and len(result.redirect_chain) > 1:
        print("  redirects: " + " -> ".join(result.redirect_chain))
    for f in sorted(result.findings, key=lambda f: f.severity, reverse=True):
        print(f"  [{f.severity.name:8s}] {f.title}")
        print(f"             {f.explanation}")
        if f.evidence:
            print(f"             evidence: {f.evidence}")
    for factor in result.ml_factors:
        print(f"  [MODEL   ] {factor.description} (+{factor.contribution:.2f})")
    for note in result.notes:
        print(f"  note: {note}")
    timing = ", ".join(f"{k} {v:.0f}" for k, v in result.timings_ms.items())
    print(f"  timings (ms): {timing}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("--file", type=Path, help="analyse a saved HTML file instead of fetching")
    parser.add_argument("--as-url", default="https://local-file.invalid/",
                        help="the URL to pretend --file came from")
    parser.add_argument("--mode", choices=("full", "url_only"), default="full")
    parser.add_argument("--strictness", choices=("balanced", "strict"), default="balanced")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    parser.add_argument("--save-html", type=Path,
                        help="also save the fetched HTML (+ .url) into this folder")
    parser.add_argument("--allow-private-targets", action="store_true")
    args = parser.parse_args()

    config = default_config()
    if args.allow_private_targets:
        config = config.with_fetch(allow_private_targets=True)
    scanner = Scanner.from_config(config)

    if args.file:
        url = ut.normalise_url(args.as_url)
        html = args.file.read_text(encoding="utf-8", errors="replace")
        page = FetchedPage(requested_url=url, final_url=url, status=200, body=html,
                           content_type="text/html", redirect_chain=[url])
        result = scanner.analyse(url, page, strictness=args.strictness)
    elif args.url and args.save_html:
        # Fetch once, analyse that same copy, and save it for training.
        url = ut.normalise_url(args.url)
        page = scanner.fetcher.fetch(url)
        result = scanner.analyse(url, page, strictness=args.strictness)
        if page.content_usable and page.body:
            args.save_html.mkdir(parents=True, exist_ok=True)
            stem = re.sub(r"[^a-z0-9]+", "_", ut.get_host(args.url))[:60] or "page"
            (args.save_html / f"{stem}.html").write_text(page.body, encoding="utf-8")
            (args.save_html / f"{stem}.url").write_text(page.final_url, encoding="utf-8")
        else:
            # An error or bot-check page is not the site, so it would be a mislabelled example.
            print(f"Not saved: the site did not return its real content "
                  f"({page.fetch_error or f'HTTP {page.status}'}).")
    elif args.url:
        result = scanner.scan(args.url, mode=args.mode, strictness=args.strictness)
    else:
        parser.error("give a URL or --file")
        return

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_result(result)


if __name__ == "__main__":
    main()
