"""
Start the local PreFlight scanner that the browser extension talks to.

    python run_server.py                       # normal use
    python run_server.py --verbose             # also log scanned domains
    python run_server.py --allow-private-targets   # ONLY for the local demo site

On first run a secret token is created. It is written into the extension
folder (extension/token.json) so the extension connects by itself; it is
also printed in case you need to paste it into the extension settings.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from preflight.auth import load_or_create_token
from preflight.config import default_config
from preflight.scanner import Scanner
from preflight.server import PreFlightServer


# The unpacked extension folder sits next to backend/. Writing the token there
# lets the extension pick it up by itself, so nobody has to copy and paste it.
# The file is private to the extension (it is not web-accessible).
EXTENSION_DIR = Path(__file__).resolve().parent.parent / "extension"


def share_token_with_extension(token: str, port: int) -> None:
    if not EXTENSION_DIR.is_dir():
        return
    payload = {"token": token, "serverUrl": f"http://127.0.0.1:{port}"}
    try:
        (EXTENSION_DIR / "token.json").write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass  # read-only folder: the user can still paste the token in settings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--verbose", action="store_true", help="log the domain of each scan")
    parser.add_argument("--allow-private-targets", action="store_true",
                        help="allow scanning localhost/private addresses (demo and tests only)")
    parser.add_argument("--show-token", action="store_true", help="print the token and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = default_config().with_server(port=args.port, verbose=args.verbose)
    if args.allow_private_targets:
        config = config.with_fetch(allow_private_targets=True)

    token = load_or_create_token(config.server.token_path)
    if args.show_token:
        print(token)
        return
    share_token_with_extension(token, config.server.port)

    scanner = Scanner.from_config(config)
    server = PreFlightServer(scanner, token)
    provenance = scanner.provenance()

    print("=" * 64)
    print(f" PreFlight scanner listening on http://127.0.0.1:{config.server.port}")
    print(f" Model: {provenance.get('algorithm') or 'NOT LOADED (rules only)'}"
          f"  trained {provenance.get('trained_at') or '-'}")
    age = provenance["threat_list_age_days"]
    print(f" Threat list: {provenance['threat_list_entries']} entries, "
          + ("never updated" if age is None else f"{age} days old"))
    print(f" Extension token (paste into the extension options once):\n   {token}")
    if args.allow_private_targets:
        print(" WARNING: private/local addresses can be scanned (demo mode).")
    print(" Press Ctrl+C to stop.")
    print("=" * 64)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
