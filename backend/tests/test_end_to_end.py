"""
End-to-end: a real HTTP server on localhost serves the sample pages, the
real fetcher downloads them, and the real API server answers requests.
"""

import functools
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from preflight.config import SAMPLES_DIR, default_config
from preflight.net import AddressGuard, BlockedAddressError, SafeFetcher
from preflight.scanner import Scanner
from preflight.schema import FetchedPage, Verdict
from preflight.server import PreFlightServer


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        return


def start_sample_site() -> tuple[ThreadingHTTPServer, str]:
    handler = functools.partial(_QuietHandler, directory=str(SAMPLES_DIR))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://localhost:{server.server_address[1]}"


class AddressGuardTests(unittest.TestCase):
    def test_private_addresses_are_blocked_by_default(self):
        guard = AddressGuard(allow_private=False)
        for host in ("127.0.0.1", "localhost", "10.1.2.3", "192.168.0.1", "169.254.169.254", "::1"):
            with self.assertRaises(BlockedAddressError, msg=host):
                guard.resolve_and_check(host, 80)

    def test_ipv4_mapped_ipv6_cannot_sneak_past(self):
        self.assertFalse(AddressGuard.is_public("::ffff:10.0.0.1"))
        self.assertTrue(AddressGuard.is_public("8.8.8.8"))

    def test_default_fetcher_refuses_localhost(self):
        page = SafeFetcher(default_config().fetch).fetch("http://127.0.0.1:9/")
        self.assertIn("private or local", page.fetch_error or "")


class LiveScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site, cls.base = start_sample_site()
        config = default_config().with_fetch(allow_private_targets=True)
        cls.scanner = Scanner.from_config(config)

    @classmethod
    def tearDownClass(cls):
        cls.site.shutdown()
        cls.site.server_close()

    def test_benign_samples_are_not_flagged(self):
        for path in sorted(SAMPLES_DIR.glob("benign_*.html")):
            result = self.scanner.scan(f"{self.base}/{path.name}")
            self.assertNotIn(result.verdict, (Verdict.CAUTION, Verdict.DANGER), path.name)

    def test_malicious_samples_are_flagged(self):
        for path in sorted(SAMPLES_DIR.glob("malicious_*.html")):
            result = self.scanner.scan(f"{self.base}/{path.name}")
            self.assertIn(result.verdict, (Verdict.CAUTION, Verdict.DANGER), path.name)

    def test_unreachable_site_is_unsure_when_strict(self):
        result = self.scanner.scan("http://does-not-exist.invalid/", strictness="strict")
        self.assertEqual(result.verdict, Verdict.UNSURE)
        self.assertTrue(any("could not" in n.lower() for n in result.notes))

    def test_unreachable_site_is_never_flagged_as_dangerous_when_balanced(self):
        result = self.scanner.scan("http://does-not-exist.invalid/", strictness="balanced")
        self.assertIn(result.verdict, (Verdict.SAFE, Verdict.UNSURE))
        self.assertTrue(any("could not" in n.lower() for n in result.notes))

    def test_error_page_is_not_judged_as_the_site(self):
        # A bot-protection page answering 403 must not be analysed as content.
        html = ("<title>Just a moment...</title><h1>Verify you are human</h1>"
                "<script>eval(atob('Y29uc29sZS5sb2coMSk='))</script>")
        page = FetchedPage(requested_url="https://shop.example/", final_url="https://shop.example/",
                           status=403, body=html, content_type="text/html",
                           redirect_chain=["https://shop.example/"])
        result = self.scanner.analyse("https://shop.example/", page)
        self.assertFalse(any(f.detector_id == "js.decode_and_run" for f in result.findings))
        self.assertTrue(any("HTTP 403" in n for n in result.notes))

    def test_blocklisted_domain_is_danger_even_offline(self):
        result = self.scanner.scan("http://known-bad-demo.invalid/login")
        self.assertEqual(result.verdict, Verdict.DANGER)

    def test_second_scan_comes_from_cache(self):
        url = f"{self.base}/benign_recipe_blog.html"
        self.scanner.scan(url)
        self.assertTrue(self.scanner.scan(url).from_cache)


class ApiServerTests(unittest.TestCase):
    TOKEN = "t" * 43

    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        config = default_config().with_server(port=0, token_path=Path(cls.tmp.name) / "token")
        # port=0 lets the OS pick a free port; fix up the allowed Host values after binding.
        cls.server = PreFlightServer(Scanner.from_config(config), cls.TOKEN)
        port = cls.server.server_address[1]
        cls.server.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        cls.base = f"http://127.0.0.1:{port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def call(self, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, headers=headers or {},
                                         method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_rejects_missing_token(self):
        status, _ = self.call("/health")
        self.assertEqual(status, 401)

    def test_rejects_web_page_origin(self):
        status, _ = self.call("/health", headers={"X-PreFlight-Token": self.TOKEN,
                                                  "Origin": "https://evil.example"})
        self.assertEqual(status, 403)

    def test_health_and_scan_with_token(self):
        headers = {"X-PreFlight-Token": self.TOKEN, "Content-Type": "application/json",
                   "Origin": "chrome-extension://abcdefghijklmnop"}
        status, health = self.call("/health", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")
        status, result = self.call("/scan", {"url": "javascript:alert(1)"}, headers)
        self.assertEqual(status, 200)
        self.assertEqual(result["verdict"], "error")

    def test_strictness_reaches_the_scanner(self):
        headers = {"X-PreFlight-Token": self.TOKEN, "Content-Type": "application/json"}
        for level in ("balanced", "strict"):
            status, result = self.call("/scan", {"url": "http://does-not-exist.invalid/",
                                                 "strictness": level}, headers)
            self.assertEqual(status, 200)
            self.assertEqual(result["strictness"], level)
        status, result = self.call("/scan", {"url": "http://does-not-exist.invalid/",
                                             "strictness": "nonsense"}, headers)
        self.assertEqual(result["strictness"], "balanced")


if __name__ == "__main__":
    unittest.main()
