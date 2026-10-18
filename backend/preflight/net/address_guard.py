"""
Server-Side Request Forgery (SSRF) protection for the local scanner.

The scanner downloads whatever URL it is given. Without this guard, a
malicious web page could make your scanner fetch http://192.168.1.1/ (your
router) or http://127.0.0.1:XXXX/ (other local services) and learn about
your network. So before every connection we:

1. resolve the host name to IP addresses ourselves,
2. refuse if ANY resolved address is not a public internet address,
3. return the checked IP so the fetcher connects to exactly that address
   (this "pinning" stops DNS-rebinding tricks where the second lookup
   returns a different, private address).
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as LookupTimeout

# RFC 6761: names under .invalid never exist, so they're answered without a
# lookup. Windows otherwise spends seconds asking the local network first.
NEVER_RESOLVES = (".invalid",)

# getaddrinfo has no timeout of its own; lookups run here so a slow DNS
# server can't hold up a scan. A stuck lookup finishes in the background.
_LOOKUPS = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns")


class BlockedAddressError(Exception):
    """Raised when a URL points at an address we refuse to contact."""


class AddressGuard:
    def __init__(self, allow_private: bool = False, lookup_timeout: float = 5.0) -> None:
        # allow_private is ONLY for automated tests and the local demo site.
        self.allow_private = allow_private
        self.lookup_timeout = lookup_timeout

    @staticmethod
    def is_public(ip_text: str) -> bool:
        """True for globally routable unicast addresses only."""
        ip = ipaddress.ip_address(ip_text)
        # Unwrap IPv4-mapped IPv6 (::ffff:10.0.0.1) so it cannot sneak past.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return ip.is_global and not ip.is_multicast

    def resolve_and_check(self, host: str, port: int) -> str:
        """
        Resolve `host` and return one IP address that is safe to connect to.

        Raises BlockedAddressError if the host does not resolve or if any of
        its addresses is private, loopback, link-local or otherwise reserved.
        """
        host = host.strip("[]")
        if host.lower().rstrip(".").endswith(NEVER_RESOLVES):
            raise BlockedAddressError(f"could not resolve '{host}' (reserved name that never exists)")
        lookup = _LOOKUPS.submit(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
        try:
            infos = lookup.result(timeout=self.lookup_timeout)
        except LookupTimeout:
            raise BlockedAddressError(
                f"could not resolve '{host}' (no answer within {self.lookup_timeout:.0f}s)") from None
        except socket.gaierror as exc:
            raise BlockedAddressError(f"could not resolve '{host}' ({exc.strerror})") from exc

        addresses = sorted({info[4][0] for info in infos})
        if not addresses:
            raise BlockedAddressError(f"'{host}' has no addresses")

        if not self.allow_private:
            private = [a for a in addresses if not self.is_public(a)]
            if private:
                raise BlockedAddressError(
                    f"'{host}' points to a private or local address ({private[0]}); "
                    "PreFlight never contacts these"
                )
        # Prefer IPv4 for predictability, otherwise the first address.
        ipv4 = [a for a in addresses if ":" not in a]
        return (ipv4 or addresses)[0]
