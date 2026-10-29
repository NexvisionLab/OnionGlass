# SPDX-License-Identifier: AGPL-3.0-only
"""Property P11: the onion address never appears in the host name the browser uses."""

from __future__ import annotations

import asyncio

import pytest

from onionglass.hosts import GatewayHosts
from onionglass.labels import (
    LABEL_LENGTH,
    LabelBook,
    LabelError,
    LabelTarget,
    is_valid_label,
    is_valid_session_id,
    new_label,
)
from onionglass.store import InMemoryStore

TOR_PROJECT = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"
DUCKDUCKGO = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
SESSION = "session-aaaaaaaa"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_new_labels_have_the_right_shape_and_are_unique() -> None:
    labels = {new_label() for _ in range(2000)}
    assert len(labels) == 2000
    assert all(len(label) == LABEL_LENGTH and is_valid_label(label) for label in labels)


def test_label_is_stable_for_a_session_and_onion_and_resolves_back() -> None:
    async def scenario() -> None:
        book = LabelBook(InMemoryStore(), ttl=600)
        first = await book.label_for(SESSION, TOR_PROJECT)
        again = await book.label_for(SESSION, TOR_PROJECT.upper())
        assert first == again
        assert await book.resolve(first) == LabelTarget(session_id=SESSION, address=TOR_PROJECT)

    asyncio.run(scenario())


def test_different_sessions_and_onions_get_different_labels() -> None:
    async def scenario() -> None:
        book = LabelBook(InMemoryStore(), ttl=600)
        a = await book.label_for(SESSION, TOR_PROJECT)
        b = await book.label_for(SESSION, DUCKDUCKGO)
        c = await book.label_for("session-bbbbbbbb", TOR_PROJECT)
        assert len({a, b, c}) == 3

    asyncio.run(scenario())


def test_the_onion_address_is_not_visible_in_the_host_name() -> None:
    async def scenario() -> None:
        book = LabelBook(InMemoryStore(), ttl=600)
        hosts = GatewayHosts("gateway.example")
        label = await book.label_for(SESSION, TOR_PROJECT)
        host = hosts.host_for(label)
        assert TOR_PROJECT not in host
        assert TOR_PROJECT[:12] not in host
        assert "onion" not in host
        assert hosts.label_from_host(host) == label

    asyncio.run(scenario())


def test_concurrent_requests_for_the_same_pair_get_one_label() -> None:
    async def scenario() -> None:
        book = LabelBook(InMemoryStore(), ttl=600)
        labels = await asyncio.gather(*(book.label_for(SESSION, TOR_PROJECT) for _ in range(25)))
        assert len(set(labels)) == 1
        assert await book.resolve(labels[0]) is not None

    asyncio.run(scenario())


def test_unknown_malformed_and_expired_labels_do_not_resolve() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        book = LabelBook(InMemoryStore(clock=clock), ttl=60)
        label = await book.label_for(SESSION, TOR_PROJECT)
        assert await book.resolve(new_label()) is None
        for bad in (
            "",
            "short",
            label.upper(),
            label + "a",
            label[:-1],
            "../" + label[3:],
            "a" * 26 + "\n",
        ):
            assert await book.resolve(bad) is None
        clock.now += 61
        assert await book.resolve(label) is None

    asyncio.run(scenario())


def test_invalid_inputs_are_refused() -> None:
    async def scenario() -> None:
        book = LabelBook(InMemoryStore(), ttl=60)
        for session in ("", "short", "has:colon-1", "has space 1", "x" * 65, "new\nline-1"):
            with pytest.raises(LabelError):
                await book.label_for(session, TOR_PROJECT)
        with pytest.raises(LabelError):
            await book.label_for(SESSION, "not-an-onion")

    asyncio.run(scenario())


def test_session_id_alphabet() -> None:
    assert is_valid_session_id("abcDEF12-_xyz")
    assert not is_valid_session_id("abc:defgh")
    assert not is_valid_session_id("abc")


class CollidingStore(InMemoryStore):
    """Pretends the first random label was already taken."""

    def __init__(self) -> None:
        super().__init__()
        self.collisions_left = 1

    async def add_if_absent(self, key: str, value: str, ttl: float) -> bool:
        if key.startswith("rev:") and self.collisions_left:
            self.collisions_left -= 1
            return False
        return await super().add_if_absent(key, value, ttl)


class RacingStore(InMemoryStore):
    """Lets another request claim the pair's label between our two writes."""

    WINNER = "winnerwinnerwinnerwinner22"

    def __init__(self) -> None:
        super().__init__()
        self.raced = False

    async def add_if_absent(self, key: str, value: str, ttl: float) -> bool:
        if key.startswith("lbl:") and not self.raced:
            self.raced = True
            await self.put(key, self.WINNER, ttl)
            return False
        return await super().add_if_absent(key, value, ttl)


def test_a_label_collision_is_retried() -> None:
    async def scenario() -> None:
        store = CollidingStore()
        label = await LabelBook(store, ttl=60).label_for(SESSION, TOR_PROJECT)
        assert store.collisions_left == 0
        assert is_valid_label(label)

    asyncio.run(scenario())


def test_losing_a_race_uses_the_winner_and_leaves_no_stray_entry() -> None:
    async def scenario() -> None:
        store = RacingStore()
        label = await LabelBook(store, ttl=60).label_for(SESSION, TOR_PROJECT)
        assert label == RacingStore.WINNER
        # Only the forward entry written by the "winner" remains: the loser's reverse entry
        # was removed again.
        assert len(store._data) == 1

    asyncio.run(scenario())


def test_corrupt_stored_values_do_not_resolve() -> None:
    async def scenario() -> None:
        store = InMemoryStore()
        book = LabelBook(store, ttl=60)
        label_a, label_b, label_c = new_label(), new_label(), new_label()
        await store.put(f"rev:{label_a}", "not json", 60)
        await store.put(f"rev:{label_b}", '["a-session-id", "not-an-onion"]', 60)
        await store.put(f"rev:{label_c}", '"just a string"', 60)
        for label in (label_a, label_b, label_c):
            assert await book.resolve(label) is None

    asyncio.run(scenario())
