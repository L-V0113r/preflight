"""Network layer: SSRF guard and a safe, size-limited page fetcher."""

from preflight.net.address_guard import AddressGuard, BlockedAddressError
from preflight.net.safe_fetcher import SafeFetcher, sniff_binary

__all__ = ["AddressGuard", "BlockedAddressError", "SafeFetcher", "sniff_binary"]
