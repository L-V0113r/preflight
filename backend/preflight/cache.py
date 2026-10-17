"""
A small thread-safe cache with expiry (TTL) and a size limit (LRU).

Clicking the same link twice within a few minutes should not cost a second
scan. Entries expire so a site that turns malicious is not trusted forever.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Generic, TypeVar

V = TypeVar("V")


class TTLCache(Generic[V]):
    def __init__(self, ttl_s: float, max_entries: int) -> None:
        self.ttl_s = ttl_s
        self.max_entries = max_entries
        self._items: OrderedDict[str, tuple[float, V]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> V | None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            expires, value = item
            if expires < time.monotonic():
                del self._items[key]
                return None
            self._items.move_to_end(key)  # mark as recently used
            return value

    def put(self, key: str, value: V) -> None:
        with self._lock:
            self._items[key] = (time.monotonic() + self.ttl_s, value)
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)  # evict least recently used

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
