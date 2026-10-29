# SPDX-License-Identifier: AGPL-3.0-only
"""Server-side cookies: P4 (nothing reaches the visitor) and P3 (nothing crosses between onions)."""

from __future__ import annotations

import asyncio

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.cookies import (
    MAX_COOKIES_PER_ORIGIN,
    Cookie,
    CookieJar,
    parse_set_cookie,
)
from onionglass.onion import OnionHost, OnionOrigin
from onionglass.store import InMemoryStore

ORIGIN = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
OTHER = OnionOrigin("http", OnionHost(DUCKDUCKGO), 80)
SUBDOMAIN = OnionOrigin("http", OnionHost(TOR_PROJECT, ("www",)), 80)
SESSION = "session-aaaaaaaa"
NOW = 1_800_000_000.0


class FakeClock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


def jar(clock: FakeClock | None = None) -> tuple[CookieJar, FakeClock]:
    clock = clock or FakeClock()
    return CookieJar(InMemoryStore(clock=clock), ttl=3600, clock=clock), clock


def run(coro: object) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def test_a_cookie_is_stored_and_sent_back_to_the_same_origin() -> None:
    async def scenario() -> None:
        store, _ = jar()
        assert (
            await store.store_from_response(
                SESSION, ORIGIN, "/login", ["sid=abc123; Path=/; HttpOnly; Secure"]
            )
            == 1
        )
        assert await store.header_for(SESSION, ORIGIN, "/account?x=1") == "sid=abc123"
        assert await store.header_for(SESSION, ORIGIN, "/") == "sid=abc123"

    run(scenario())


def test_cookies_never_cross_between_sessions_or_origins() -> None:
    async def scenario() -> None:
        store, _ = jar()
        await store.store_from_response(SESSION, ORIGIN, "/", ["sid=abc"])
        assert await store.header_for("session-bbbbbbbb", ORIGIN, "/") is None
        assert await store.header_for(SESSION, OTHER, "/") is None
        assert await store.header_for(SESSION, SUBDOMAIN, "/") is None
        secure = OnionOrigin("https", OnionHost(TOR_PROJECT), 443)
        assert await store.header_for(SESSION, secure, "/") is None

    run(scenario())


def test_path_rules() -> None:
    async def scenario() -> None:
        store, _ = jar()
        await store.store_from_response(
            SESSION, ORIGIN, "/", ["a=1; Path=/", "b=2; Path=/admin", "c=3; Path=/admin/panel"]
        )
        assert await store.header_for(SESSION, ORIGIN, "/") == "a=1"
        assert await store.header_for(SESSION, ORIGIN, "/admin") == "b=2; a=1"
        assert await store.header_for(SESSION, ORIGIN, "/admin/panel/x") == "c=3; b=2; a=1"
        assert await store.header_for(SESSION, ORIGIN, "/administrator") == "a=1"

    run(scenario())


def test_the_default_path_comes_from_the_request() -> None:
    async def scenario() -> None:
        store, _ = jar()
        await store.store_from_response(SESSION, ORIGIN, "/shop/cart/view", ["x=1"])
        assert await store.header_for(SESSION, ORIGIN, "/shop/cart/other") == "x=1"
        assert await store.header_for(SESSION, ORIGIN, "/shop") is None

    run(scenario())


def test_expiry_max_age_and_deletion() -> None:
    async def scenario() -> None:
        store, clock = jar()
        await store.store_from_response(SESSION, ORIGIN, "/", ["a=1; Max-Age=60", "b=2"])
        assert await store.header_for(SESSION, ORIGIN, "/") == "a=1; b=2"
        clock.now += 61
        assert await store.header_for(SESSION, ORIGIN, "/") == "b=2"
        assert await store.store_from_response(SESSION, ORIGIN, "/", ["b=gone; Max-Age=0"]) == 1
        assert await store.header_for(SESSION, ORIGIN, "/") is None

    run(scenario())


def test_expires_date_in_the_past_deletes_and_in_the_future_keeps() -> None:
    async def scenario() -> None:
        store, _ = jar()
        await store.store_from_response(
            SESSION, ORIGIN, "/", ["a=1; Expires=Fri, 01 Jan 2100 00:00:00 GMT"]
        )
        assert await store.header_for(SESSION, ORIGIN, "/") == "a=1"
        await store.store_from_response(
            SESSION, ORIGIN, "/", ["a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"]
        )
        assert await store.header_for(SESSION, ORIGIN, "/") is None

    run(scenario())


def test_a_cookie_cannot_outlive_the_session_limit() -> None:
    cookie = parse_set_cookie("a=1; Max-Age=999999999", ORIGIN, "/", NOW)
    assert isinstance(cookie, Cookie)
    assert cookie.expires is not None
    assert cookie.expires - NOW <= 8 * 3600


def test_a_newer_cookie_replaces_an_older_one_with_the_same_name_and_path() -> None:
    async def scenario() -> None:
        store, _ = jar()
        await store.store_from_response(SESSION, ORIGIN, "/", ["a=1"])
        await store.store_from_response(SESSION, ORIGIN, "/", ["a=2"])
        assert await store.header_for(SESSION, ORIGIN, "/") == "a=2"

    run(scenario())


def test_domain_attribute_rules() -> None:
    assert isinstance(
        parse_set_cookie(f"a=1; Domain={TOR_PROJECT}.onion", ORIGIN, "/", NOW), Cookie
    )
    assert isinstance(
        parse_set_cookie(f"a=1; Domain=.{TOR_PROJECT}.onion", SUBDOMAIN, "/", NOW), Cookie
    )
    for domain in (
        "onion",
        ".onion",
        "evil.example",
        f"{DUCKDUCKGO}.onion",
        f"x.{TOR_PROJECT}.onion",
    ):
        assert parse_set_cookie(f"a=1; Domain={domain}", ORIGIN, "/", NOW) is None, domain


@pytest.mark.parametrize(
    "header",
    [
        "",
        "novalue",
        "=value",
        "a b=1",
        "a=has space",
        'a="quoted"',
        "a=semi;colon;Path=/",
        "a=1\r\nSet-Cookie: b=2",
        "a=1\x00",
        "a=" + "x" * 5000,
        "caf" + chr(0xE9) + "=1",
        "a=" + chr(0xE9),
    ],
)
def test_malformed_cookies_are_ignored(header: str) -> None:
    result = parse_set_cookie(header, ORIGIN, "/", NOW)
    assert result is None or header.startswith("a=semi")


def test_the_number_of_cookies_per_origin_is_limited() -> None:
    async def scenario() -> None:
        store, clock = jar()
        for index in range(MAX_COOKIES_PER_ORIGIN + 20):
            clock.now += 1
            await store.store_from_response(SESSION, ORIGIN, "/", [f"c{index}=v"])
        header = await store.header_for(SESSION, ORIGIN, "/")
        assert header is not None
        assert header.count("=") == MAX_COOKIES_PER_ORIGIN
        assert "c0=" not in header and f"c{MAX_COOKIES_PER_ORIGIN + 19}=v" in header

    run(scenario())


def test_the_request_header_is_size_limited() -> None:
    async def scenario() -> None:
        store, clock = jar()
        for index in range(40):
            clock.now += 1
            await store.store_from_response(SESSION, ORIGIN, "/", [f"c{index}={'v' * 400}"])
        header = await store.header_for(SESSION, ORIGIN, "/")
        assert header is not None
        assert len(header) <= 8192
        assert not header.endswith(";")

    run(scenario())


def test_the_jar_expires_with_the_session_and_can_be_cleared() -> None:
    async def scenario() -> None:
        store, clock = jar()
        await store.store_from_response(SESSION, ORIGIN, "/", ["a=1"])
        await store.clear(SESSION, ORIGIN)
        assert await store.header_for(SESSION, ORIGIN, "/") is None
        await store.store_from_response(SESSION, ORIGIN, "/", ["a=1"])
        clock.now += 3601
        assert await store.header_for(SESSION, ORIGIN, "/") is None

    run(scenario())


def test_no_cookie_is_sent_when_none_is_stored_and_nothing_changes_without_headers() -> None:
    async def scenario() -> None:
        store, _ = jar()
        assert await store.header_for(SESSION, ORIGIN, "/") is None
        assert await store.store_from_response(SESSION, ORIGIN, "/", []) == 0

    run(scenario())


def test_corrupt_stored_data_is_treated_as_empty() -> None:
    async def scenario() -> None:
        backing = InMemoryStore()
        store = CookieJar(backing, ttl=60)
        await backing.put(f"jar:{SESSION}:{ORIGIN.key}", "not json", 60)
        assert await store.header_for(SESSION, ORIGIN, "/") is None
        await backing.put(f"jar:{SESSION}:{ORIGIN.key}", '[{"unexpected": 1}]', 60)
        assert await store.header_for(SESSION, ORIGIN, "/") is None

    run(scenario())


def test_a_deletion_only_removes_the_cookie_with_the_same_name_and_path() -> None:
    async def scenario() -> None:
        store, _ = jar()
        await store.store_from_response(
            SESSION, ORIGIN, "/", ["a=root; Path=/", "a=sub; Path=/x", "b=keep"]
        )
        assert (
            await store.store_from_response(SESSION, ORIGIN, "/", ["a=; Path=/x; Max-Age=0"]) == 1
        )
        assert await store.header_for(SESSION, ORIGIN, "/x/page") == "a=root; b=keep"
        assert await store.store_from_response(SESSION, ORIGIN, "/", ["a=; Path=/; Max-Age=0"]) == 1
        assert await store.header_for(SESSION, ORIGIN, "/x/page") == "b=keep"
        # Deleting something that is not there changes nothing.
        assert await store.store_from_response(SESSION, ORIGIN, "/", ["zzz=; Max-Age=0"]) == 0

    run(scenario())
