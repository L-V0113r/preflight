"""
A shared secret between the browser extension and the local scanner.

Any web page you visit can send requests to http://127.0.0.1. Without a
secret, a malicious page could use your scanner as a proxy. So the server
creates a random token on first run, stores it in a file only you can read,
and refuses every request that does not carry it.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path


def load_or_create_token(path: Path) -> str:
    """Return the existing token, or create a new random one."""
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if len(token) >= 32:
            return token
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)  # 256 bits of randomness
    path.write_text(token, encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # owner read/write only (no effect on Windows)
    except OSError:
        pass
    return token


def tokens_match(provided: str | None, expected: str) -> bool:
    """Constant-time comparison, so timing cannot reveal the token."""
    if not provided:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
