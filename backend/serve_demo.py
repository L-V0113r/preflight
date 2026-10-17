"""
Serve the labelled sample pages locally so you can demo the extension safely.

    python serve_demo.py
    # in another terminal (demo mode lets the scanner reach localhost):
    python run_server.py --allow-private-targets

Then open http://127.0.0.1:8000/ in the browser with the extension loaded and
click the links. The index is served from 127.0.0.1 and the samples from
localhost:8001; the extension skips same-host links, so using two host names
makes every sample link a "new site" that gets scanned.

All samples are synthetic and inert: commands only print a test message and
no real malware or real brand is involved.
"""

from __future__ import annotations

import argparse
import functools
import html
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from preflight.config import SAMPLES_DIR


def build_index(sample_port: int) -> bytes:
    rows = []
    for path in sorted(SAMPLES_DIR.glob("*.html")):
        label = "malicious" if path.name.startswith("malicious_") else "benign"
        title = path.stem.split("_", 1)[1].replace("_", " ")
        rows.append(f"<li class='{label}'><a href='http://localhost:{sample_port}/{path.name}'>"
                    f"{html.escape(title)}</a> <small>({label}, synthetic)</small></li>")
    rows.append("<li class='failure'><a href='http://does-not-exist.invalid/'>"
                "a site that cannot be reached</a> <small>(failure case)</small></li>")
    rows.append("<li class='failure'><a href='http://known-bad-demo.invalid/login'>"
                "a domain on the local block list</a> <small>(threat-list demo)</small></li>")
    page = f"""<!doctype html><html><head><meta charset='utf-8'><title>PreFlight demo</title>
<style>body{{font:16px system-ui;max-width:720px;margin:40px auto;padding:0 16px}}
li{{margin:.5em 0}} .malicious a{{color:#b42318}} .benign a{{color:#067647}}
.failure a{{color:#6941c6}} small{{color:#667085}}</style></head><body>
<h1>PreFlight demo links</h1>
<p>Click a link. With the extension and <code>run_server.py --allow-private-targets</code>
running, PreFlight checks the page before it opens.</p><ul>{''.join(rows)}</ul></body></html>"""
    return page.encode("utf-8")


class IndexHandler(SimpleHTTPRequestHandler):
    index_bytes = b""

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.index_bytes)))
        self.end_headers()
        self.wfile.write(self.index_bytes)

    def log_message(self, *args) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--index-port", type=int, default=8000)
    parser.add_argument("--sample-port", type=int, default=8001)
    args = parser.parse_args()

    IndexHandler.index_bytes = build_index(args.sample_port)
    index_server = ThreadingHTTPServer(("127.0.0.1", args.index_port), IndexHandler)
    samples_handler = functools.partial(SimpleHTTPRequestHandler, directory=str(SAMPLES_DIR))
    sample_server = ThreadingHTTPServer(("127.0.0.1", args.sample_port), samples_handler)

    threading.Thread(target=sample_server.serve_forever, daemon=True).start()
    print(f"Demo index:   http://127.0.0.1:{args.index_port}/")
    print(f"Sample pages: http://localhost:{args.sample_port}/")
    try:
        index_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        index_server.server_close()
        sample_server.server_close()


if __name__ == "__main__":
    main()
