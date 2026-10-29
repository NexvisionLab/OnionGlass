# SPDX-License-Identifier: AGPL-3.0-only
"""Short-lived key-value storage for sessions, labels and ticket replay protection.

The interface is asynchronous so a Redis-compatible store can replace the in-memory one
without changing callers. The in-memory store is the default for a single node.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol


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

    All operations are free of awaits, so each runs atomically on the event loop.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 100_000,
    ) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._data: dict[str, tuple[str, float]] = {}

    def _purge_expired(self) -> None:
        now = self._clock()
        for key in [k for k, (_, expires) in self._data.items() if expires <= now]:
            del self._data[key]

    def _live(self, key: str) -> str | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        value, expires = entry
        if expires <= self._clock():
            del self._data[key]
            return None
        return value

    def _store(self, key: str, value: str, ttl: float) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if key not in self._data and len(self._data) >= self._max_entries:
            self._purge_expired()
            if len(self._data) >= self._max_entries:
                raise StoreFullError("session store is full")
        self._data[key] = (value, self._clock() + ttl)

    async def put(self, key: str, value: str, ttl: float) -> None:
        self._store(key, value, ttl)

    async def get(self, key: str) -> str | None:
        return self._live(key)

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def add_if_absent(self, key: str, value: str, ttl: float) -> bool:
        if self._live(key) is not None:
            return False
        self._store(key, value, ttl)
        return True
