"""
The localhost API the browser extension calls.

    GET  /health  -> is the scanner up, which model is loaded
    POST /scan    -> {"url": "...", "mode": "full" | "url_only"}  => ScanResult JSON
    POST /report  -> {"url": "..."}  block this site's domain from now on
    POST /ignore  -> {"url": "..."}  trust this site's domain from now on

The pop-up's "Report this site" and "Ignore" buttons call /report and /ignore.
See the "REPORT / IGNORE ENDPOINTS" banner further down for that code.

Only the Python standard library is used. Defences, in order:

1. Bind to 127.0.0.1 only, so other machines cannot reach it.
2. Check the Host header, so DNS-rebinding pages cannot talk to it.
3. Reject requests from web-page origins (only extensions or tools with no
   Origin are allowed), so a website cannot use your scanner as a proxy.
4. Require the secret token on every request (see preflight/auth.py).
5. Cap request size, and never log full URLs unless verbose mode is on.
"""

from __future__ import annotations

import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from preflight import __version__
from preflight.auth import tokens_match
from preflight.parsing import url_tools as ut
from preflight.scanner import Scanner

log = logging.getLogger("preflight.server")

ALLOWED_ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://", "safari-web-extension://")


class PreFlightServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scanner: Scanner, token: str) -> None:
        settings = scanner.config.server
        self.scanner = scanner
        self.token = token
        self.allowed_hosts = {f"127.0.0.1:{settings.port}", f"localhost:{settings.port}"}
        super().__init__((settings.host, settings.port), PreFlightHandler)


class PreFlightHandler(BaseHTTPRequestHandler):
    server: PreFlightServer
    server_version = f"PreFlight/{__version__}"
    sys_version = ""

    # -------------------------------------------------------------- routing
    def do_OPTIONS(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
        # CORS preflight. Extensions with host permissions don't need CORS, and
        # web pages must not get it, so we only answer allowed origins.
        if not self._origin_allowed():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "origin not allowed"})
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if not self._guard():
            return
        if urlsplit(self.path).path == "/health":
            scanner = self.server.scanner
            self._send_json(HTTPStatus.OK, {
                "status": "ok",
                "version": __version__,
                "model_loaded": scanner.model is not None,
                "provenance": scanner.provenance(),
            })
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard():
            return
        path = urlsplit(self.path).path
        body = self._read_json()
        if body is None:
            return
        if path == "/scan":
            self._handle_scan(body)
        elif path in ("/report", "/ignore"):
            self._handle_feedback(body, block=(path == "/report"))
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def _handle_scan(self, body: dict) -> None:
        url = body.get("url")
        if not isinstance(url, str):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "'url' must be a string"})
            return
        mode = body.get("mode", "full")
        result = self.server.scanner.scan(url, mode=mode if isinstance(mode, str) else "full")
        if self.server.scanner.config.server.verbose:
            log.info("%s %s (%.0f ms)", result.verdict.value.upper(), ut.get_host(url),
                     result.timings_ms.get("total_ms", 0))
        self._send_json(HTTPStatus.OK, result.to_dict())

    # ===================================================================
    #   REPORT / IGNORE ENDPOINTS  <-- the pop-up buttons land here
    # ===================================================================
    # "Report this site" POSTs to /report  -> block=True  -> blocklist_domains.txt
    # "Ignore"           POSTs to /ignore  -> block=False -> allowlist_domains.txt
    # Both just add the site's domain to a list the scanner already reads, then
    # the next visit uses the new verdict. Change _handle_feedback (or the
    # scanner.remember_site / ThreatIntel.add_domain it calls) to do more.
    def _handle_feedback(self, body: dict, *, block: bool) -> None:
        url = body.get("url")
        if not isinstance(url, str):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "'url' must be a string"})
            return
        try:
            domain = self.server.scanner.remember_site(url, block=block)
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        action = "blocked" if block else "trusted"
        if self.server.scanner.config.server.verbose:
            log.info("%s domain %s", action, domain)
        self._send_json(HTTPStatus.OK, {"status": "ok", "action": action, "domain": domain,
                                        "message": f"{domain} {action}"})

    # ---------------------------------------------------------- protection
    def _guard(self) -> bool:
        """Run every check; send an error response and return False on failure."""
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "bad host header"})
            return False
        if not self._origin_allowed():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "origin not allowed"})
            return False
        if not tokens_match(self.headers.get("X-PreFlight-Token"), self.server.token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "missing or wrong token"})
            return False
        return True

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        # No Origin: command-line tools and extension service workers in some
        # browsers. Web pages always send an Origin on cross-origin POSTs.
        return origin is None or origin.startswith(ALLOWED_ORIGIN_PREFIXES)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > self.server.scanner.config.server.max_request_bytes:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "bad request size"})
            return None
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, UnicodeDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "body must be JSON"})
            return None
        if not isinstance(data, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
            return None
        return data

    # ------------------------------------------------------------- output
    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin.startswith(ALLOWED_ORIGIN_PREFIXES):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-PreFlight-Token")
            self.send_header("Vary", "Origin")

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - signature fixed by base class
        # The default logs every request line, which would include URLs in
        # query strings. We log nothing here; scans are logged above if verbose.
        return
