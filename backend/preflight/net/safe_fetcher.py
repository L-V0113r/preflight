"""
Download a page safely, without running any of it.

Safety properties (each one is a lesson in itself, see LEARN_TO_BUILD_IT.md):

* No JavaScript is executed and no cookies are sent: the site learns only
  that *something* at your IP address asked for the page.
* Every hop of a redirect chain is re-checked by the AddressGuard, and the
  TCP connection goes to the exact IP address that was checked ("pinning").
* TLS certificates are verified with the system trust store.
* Bodies are capped, and compressed bodies are decompressed with a cap too,
  so a "zip bomb" cannot exhaust memory.
* Redirects are followed manually so the full chain can be reported.
"""

from __future__ import annotations

import codecs
import http.client
import re
import socket
import ssl
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

from preflight.config import FetchSettings
from preflight.net.address_guard import AddressGuard, BlockedAddressError
from preflight.schema import FetchedPage

_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_CHARSET_HEADER = re.compile(r"charset=([\w\-]+)", re.IGNORECASE)
_CHARSET_META = re.compile(rb"<meta[^>]+charset=['\"]?([\w\-]+)", re.IGNORECASE)
_READ_CHUNK = 64 * 1024
_BINARY_SNIFF_BYTES = 4096

# First bytes ("magic numbers") of file types that can harm a computer.
_MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "windows-executable"),
    (b"\x7fELF", "linux-executable"),
    (b"\xcf\xfa\xed\xfe", "macos-executable"),
    (b"\xca\xfe\xba\xbe", "macos-executable"),
    (b"PK\x03\x04", "zip-archive"),          # also .apk, .jar, .docm
    (b"Rar!", "rar-archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z-archive"),
    (b"\xd0\xcf\x11\xe0", "ole-document"),   # old Office files, .msi
)


class FetchError(Exception):
    """A fetch failed in a way the caller should report to the user."""

    def __init__(self, message: str, *, tls_error: bool = False) -> None:
        super().__init__(message)
        self.tls_error = tls_error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that connects to a pre-checked IP, not a fresh DNS answer."""

    def __init__(self, host: str, pinned_ip: str, port: int, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS version: TCP to the pinned IP, but TLS checks the real host name."""

    def __init__(self, host: str, pinned_ip: str, port: int, timeout: float,
                 context: ssl.SSLContext) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._tls_context = context

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # server_hostname drives both SNI and certificate host-name checking.
        self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)


def sniff_binary(prefix: bytes) -> str:
    """Identify dangerous file types from their first bytes."""
    for magic, label in _MAGIC_SIGNATURES:
        if prefix.startswith(magic):
            return label
    return ""


def _decode_body(raw: bytes, content_type: str) -> str:
    """Pick the right text encoding: header first, then <meta charset>, then UTF-8."""
    charset = None
    match = _CHARSET_HEADER.search(content_type or "")
    if match:
        charset = match.group(1)
    else:
        meta = _CHARSET_META.search(raw[:4096])
        if meta:
            charset = meta.group(1).decode("ascii", "ignore")
    try:
        codecs.lookup(charset or "utf-8")
    except LookupError:
        charset = "utf-8"
    return raw.decode(charset or "utf-8", errors="replace")


def _decompress(raw: bytes, encoding: str, limit: int) -> tuple[bytes, bool]:
    """Decompress gzip/deflate with an output cap. Returns (data, truncated)."""
    encoding = (encoding or "").lower().strip()
    if encoding in ("", "identity"):
        return raw, False
    if encoding == "gzip":
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decoder = zlib.decompressobj()
    else:
        raise FetchError(f"unsupported content encoding '{encoding}'")
    try:
        out = decoder.decompress(raw, limit + 1)
    except zlib.error:
        if encoding != "deflate":
            raise FetchError("could not decompress response") from None
        # Some servers send raw deflate without the zlib header.
        out = zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw, limit + 1)
    return out[:limit], len(out) > limit


class SafeFetcher:
    def __init__(self, settings: FetchSettings, guard: AddressGuard | None = None) -> None:
        self.settings = settings
        self.guard = guard or AddressGuard(allow_private=settings.allow_private_targets)
        self._tls = ssl.create_default_context()

    # ------------------------------------------------------------------ public
    def fetch(self, url: str) -> FetchedPage:
        """
        Fetch `url`, following redirects. Never raises: errors go in fetch_error.

        External scripts are NOT fetched here; the scanner calls
        fetch_scripts() after parsing, so the HTML is only parsed once.
        """
        started = time.perf_counter()
        page = FetchedPage(requested_url=url, final_url=url)
        current = url
        try:
            for _ in range(self.settings.max_redirects + 1):
                page.redirect_chain.append(current)
                status, headers, body, truncated = self._request(
                    current, self.settings.max_bytes, self.settings.timeout_s)
                if status in _REDIRECT_CODES and headers.get("location"):
                    nxt = urljoin(current, headers["location"])
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        raise FetchError(f"redirect to unsupported scheme: {nxt[:80]}")
                    current = nxt
                    continue
                page.final_url = current
                page.status = status
                page.headers = headers
                page.content_type = headers.get("content-type", "")
                page.truncated = truncated
                page.binary_signature = sniff_binary(body[:_BINARY_SNIFF_BYTES])
                if page.is_html or page.content_type.startswith("text/"):
                    page.body = _decode_body(body, page.content_type)
                break
            else:
                raise FetchError(f"more than {self.settings.max_redirects} redirects")
        except FetchError as exc:
            page.fetch_error = str(exc)
            page.tls_error = exc.tls_error
        except BlockedAddressError as exc:
            page.fetch_error = str(exc)

        page.elapsed_ms = (time.perf_counter() - started) * 1000
        return page

    def fetch_scripts(self, srcs: list[str]) -> dict[str, str]:
        """Fetch a few external JavaScript files in parallel (best effort)."""
        chosen = [s for s in dict.fromkeys(srcs) if urlsplit(s).scheme in ("http", "https")]
        chosen = chosen[: self.settings.max_external_scripts]
        if not chosen:
            return {}

        def grab(src: str) -> tuple[str, str | None]:
            try:
                status, headers, body, _ = self._request(
                    src, self.settings.max_script_bytes, self.settings.script_timeout_s)
                if status == 200:
                    return src, _decode_body(body, headers.get("content-type", ""))
            except (FetchError, BlockedAddressError):
                pass
            return src, None

        with ThreadPoolExecutor(max_workers=len(chosen)) as pool:
            results = dict(pool.map(grab, chosen))
        return {src: code for src, code in results.items() if code}

    # ----------------------------------------------------------------- private
    def _request(self, url: str, max_bytes: int, timeout: float
                 ) -> tuple[int, dict[str, str], bytes, bool]:
        parts = urlsplit(url)
        host = parts.hostname or ""
        is_https = parts.scheme == "https"
        port = parts.port or (443 if is_https else 80)
        pinned_ip = self.guard.resolve_and_check(host, port)

        if is_https:
            conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
                host, pinned_ip, port, timeout, self._tls)
        else:
            conn = _PinnedHTTPConnection(host, pinned_ip, port, timeout)

        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        headers = {
            "User-Agent": self.settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        try:
            conn.request("GET", target, headers=headers)
            response = conn.getresponse()
            resp_headers = {k.lower(): v for k, v in response.getheaders()}
            if response.status in _REDIRECT_CODES:
                return response.status, resp_headers, b"", False

            ctype = resp_headers.get("content-type", "").lower()
            looks_textual = (not ctype) or "html" in ctype or "text" in ctype \
                or "javascript" in ctype or "json" in ctype or "xml" in ctype
            # For binaries we only need the first bytes to identify the file.
            read_cap = max_bytes if looks_textual else _BINARY_SNIFF_BYTES
            raw, raw_truncated = self._read_capped(response, read_cap)
            body, inflated_truncated = _decompress(
                raw, resp_headers.get("content-encoding", ""), read_cap)
            return response.status, resp_headers, body, raw_truncated or inflated_truncated
        except ssl.SSLCertVerificationError as exc:
            raise FetchError(f"TLS certificate could not be verified ({exc.verify_message})",
                             tls_error=True) from None
        except ssl.SSLError as exc:
            raise FetchError(f"TLS handshake failed ({exc.reason})", tls_error=True) from None
        except (socket.timeout, TimeoutError):
            raise FetchError(f"timed out after {timeout:.0f}s") from None
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"connection failed ({type(exc).__name__})") from None
        finally:
            conn.close()

    @staticmethod
    def _read_capped(response: http.client.HTTPResponse, cap: int) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        while total <= cap:
            chunk = response.read(min(_READ_CHUNK, cap + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        return data[:cap], total > cap

