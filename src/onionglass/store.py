# SPDX-License-Identifier: AGPL-3.0-only
"""Short-lived key-value storage for sessions, labels and ticket replay protection.

The interface is asynchronous so a Redis-compatible store can replace the in-memory one
without changing callers. The in-memory store is the default for a single node.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

_PURGE_INTERVAL_SECONDS = 1.0


class StoreFullError(RuntimeError):
    """The store is at capacity. Callers must fail closed."""


class SessionStore(Protocol):
    """Strings in, strings out, every value with a time to live in seconds."""

    async def put(self, key: str, value: str, ttl: float) -> None: ...

    async def get(self, key: str) -> str | None: ...

    async def delete(self, key: str) -> None: ...

    async def add_if_absent(self, key: str, value: str, ttl: float) -> bool:
        """Store the value only if the key is free. Returns True if it was stored."""
        ...


class InMemoryStore:
    """A bounded in-memory store. Not shared between processes.

    It is bounded in the number of entries and in the total size of keys and values, so neither
    many small entries nor a few huge ones can use up the machine's memory.

    All operations are free of awaits, so each runs atomically on the event loop.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 100_000,
        max_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._data: dict[str, tuple[str, float]] = {}
        self._bytes = 0
        self._last_purge = float("-inf")

    @staticmethod
    def _size(key: str, value: str) -> int:
        return len(key) + len(value)

    def _remove(self, key: str) -> None:
        entry = self._data.pop(key, None)
        if entry is not None:
            self._bytes -= self._size(key, entry[0])

    def _purge_expired(self) -> None:
        """Drop expired entries. Scanning is limited to once a second so a full store cannot be
        used to make every request expensive."""
        now = self._clock()
        if now - self._last_purge < _PURGE_INTERVAL_SECONDS:
            return
        self._last_purge = now
        for key in [k for k, (_, expires) in self._data.items() if expires <= now]:
            self._remove(key)

    def _live(self, key: str) -> str | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        value, expires = entry
        if expires <= self._clock():
            self._remove(key)
            return None
        return value

    def _store(self, key: str, value: str, ttl: float) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        existing = self._data.get(key)
        added = self._size(key, value) - (self._size(key, existing[0]) if existing else 0)
        over_entries = existing is None and len(self._data) >= self._max_entries
        if over_entries or self._bytes + added > self._max_bytes:
            self._purge_expired()
            existing = self._data.get(key)
            added = self._size(key, value) - (self._size(key, existing[0]) if existing else 0)
            over_entries = existing is None and len(self._data) >= self._max_entries
            if over_entries or self._bytes + added > self._max_bytes:
                raise StoreFullError("session store is full")
        self._bytes += added
        self._data[key] = (value, self._clock() + ttl)

    async def put(self, key: str, value: str, ttl: float) -> None:
        self._store(key, value, ttl)

    async def get(self, key: str) -> str | None:
        return self._live(key)

    async def delete(self, key: str) -> None:
        self._remove(key)

    async def add_if_absent(self, key: str, value: str, ttl: float) -> bool:
        if self._live(key) is not None:
            return False
        self._store(key, value, ttl)
        return True
