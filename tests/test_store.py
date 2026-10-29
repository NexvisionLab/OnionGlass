# SPDX-License-Identifier: AGPL-3.0-only
"""The in-memory session store."""

from __future__ import annotations

import asyncio

import pytest

from onionglass.store import InMemoryStore, StoreFullError


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_put_get_delete() -> None:
    async def scenario() -> None:
        store = InMemoryStore()
        await store.put("k", "v", 10)
        assert await store.get("k") == "v"
        await store.delete("k")
        assert await store.get("k") is None
        await store.delete("k")  # deleting a missing key is not an error

    asyncio.run(scenario())


def test_values_expire() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        store = InMemoryStore(clock=clock)
        await store.put("k", "v", 10)
        clock.now += 9.9
        assert await store.get("k") == "v"
        clock.now += 0.2
        assert await store.get("k") is None

    asyncio.run(scenario())


def test_add_if_absent_only_stores_once_until_expiry() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        store = InMemoryStore(clock=clock)
        assert await store.add_if_absent("k", "first", 5)
        assert not await store.add_if_absent("k", "second", 5)
        assert await store.get("k") == "first"
        clock.now += 6
        assert await store.add_if_absent("k", "third", 5)
        assert await store.get("k") == "third"

    asyncio.run(scenario())


def test_non_positive_ttl_is_rejected() -> None:
    async def scenario() -> None:
        store = InMemoryStore()
        with pytest.raises(ValueError, match="ttl"):
            await store.put("k", "v", 0)
        with pytest.raises(ValueError, match="ttl"):
            await store.add_if_absent("k", "v", -1)

    asyncio.run(scenario())


def test_store_refuses_new_keys_when_full_but_reclaims_expired_ones() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        store = InMemoryStore(clock=clock, max_entries=2)
        await store.put("a", "1", 5)
        await store.put("b", "1", 100)
        await store.put("a", "2", 5)  # replacing an existing key needs no room
        with pytest.raises(StoreFullError):
            await store.put("c", "1", 5)
        clock.now += 10  # "a" has expired and can be reclaimed
        await store.put("c", "1", 5)
        assert await store.get("c") == "1"
        assert await store.get("b") == "1"

    asyncio.run(scenario())
