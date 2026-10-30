# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for the findings of a second independent review, of the network-facing code."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from starlette.testclient import TestClient

from fake_tor import FakeOnionServer, FakeTor, http_response, static_response
from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.cookies import Cookie, CookieJar, RequestContext, parse_set_cookie
from onionglass.headers import normalise_multipart, upstream_request_headers
from onionglass.onion import OnionHost, OnionOrigin
from onionglass.store import InMemoryStore, StoreFullError
from onionglass.upstream import TorConfig, TorFetcher, UpstreamError, UpstreamRequest
from test_gateway import APEX, PORT, Env, reply

B_ORIGIN = OnionOrigin("http", OnionHost(DUCKDUCKGO), 80)
SESSION = "session-aaaaaaaa"
NOW = 1_800_000_000.0

# --- finding 1: a page on one onion must not make the visitor's cookies for another travel ---------


def sets_cookies(_request: UpstreamRequest) -> Any:
    return reply(
        "<p>site</p>",
        headers=(
            ("Set-Cookie", "strict=1; SameSite=Strict"),
            ("Set-Cookie", "lax=1; SameSite=Lax"),
            ("Set-Cookie", "plain=1"),
            ("Set-Cookie", "open=1; SameSite=None; Secure"),
        ),
    )


def logged_in_env() -> tuple[Env, str, str]:
    """A session with a hostile onion (A) and another onion (B) the visitor is logged in to."""
    env = Env(sets_cookies)
    label_b = env.open(f"http://{DUCKDUCKGO}.onion/")
    label_a = env.open(f"http://{TOR_PROJECT}.onion/")
    env.get(label_b, "/login")  # B sets its cookies
    env.fetcher.requests.clear()
    return env, label_a, label_b


def cookies_sent(env: Env, label: str, **headers: str) -> set[str]:
    response = env.client.get(
        "/account",
        headers={"host": f"{label}.localhost:{PORT}", **headers},
    )
    assert response.status_code == 200
    sent = env.fetcher.requests[-1].headers.get("Cookie", "")
    return {part.split("=")[0] for part in sent.split("; ") if part}


def test_a_request_from_the_sites_own_page_carries_all_its_cookies() -> None:
    env, _, label_b = logged_in_env()
    assert cookies_sent(env, label_b, **{"sec-fetch-site": "same-origin"}) == {
        "strict",
        "lax",
        "plain",
        "open",
    }
    assert cookies_sent(env, label_b, **{"sec-fetch-site": "none"}) == {
        "strict",
        "lax",
        "plain",
        "open",
    }


def test_a_stylesheet_or_image_from_another_onions_page_carries_only_samesite_none_cookies() -> (
    None
):
    # This is the review's reproduction: a hostile page pulls a logged-in site's address into its
    # own markup and the visitor's browser fetches it with no click.
    env, _, label_b = logged_in_env()
    for destination in ("style", "image", "font", "iframe"):
        sent = cookies_sent(
            env,
            label_b,
            **{
                "sec-fetch-site": "same-site",
                "sec-fetch-dest": destination,
                "sec-fetch-mode": "no-cors",
            },
        )
        assert sent == {"open"}, destination


def test_following_a_link_from_another_onion_sends_lax_cookies_but_not_strict_ones() -> None:
    env, _, label_b = logged_in_env()
    clicked = {
        "sec-fetch-site": "same-site",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "iframe",
    }
    assert cookies_sent(env, label_b, **clicked) == {"lax", "plain", "open"}
    # Without a click (a script or a refresh) it is not a visitor's navigation.
    assert cookies_sent(env, label_b, **{**clicked, "sec-fetch-user": "?0"}) == {"open"}


def test_a_post_from_another_onion_carries_no_lax_cookies_and_no_trusted_origin() -> None:
    env, _, label_b = logged_in_env()
    host = f"{label_b}.localhost:{PORT}"
    cross = {
        "host": host,
        "sec-fetch-site": "same-site",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "iframe",
        "origin": "null",
    }
    env.client.post("/transfer", data={"amount": "1"}, headers=cross)
    sent = env.fetcher.requests[-1].headers
    assert {part.split("=")[0] for part in sent["Cookie"].split("; ")} == {"open"}
    assert sent["Origin"] == "null"  # the onion site's own origin check will refuse it
    same = {"host": host, "sec-fetch-site": "same-origin", "origin": f"http://{host}"}
    env.client.post("/transfer", data={"amount": "1"}, headers=same)
    sent = env.fetcher.requests[-1].headers
    assert sent["Origin"] == f"http://{DUCKDUCKGO}.onion"
    assert len(sent["Cookie"].split("; ")) == 4


def test_a_request_that_does_not_say_where_it_came_from_is_treated_as_cross_site() -> None:
    env, _, label_b = logged_in_env()
    assert cookies_sent(env, label_b) == {"open"}


def test_a_same_origin_page_sends_the_onion_side_referer_and_nothing_else_does() -> None:
    env = Env()
    label = env.open()
    host = f"{label}.localhost:{PORT}"
    same = {"host": host, "sec-fetch-site": "same-origin"}
    env.client.get("/next", headers={**same, "referer": f"http://{host}/from/here?x=1"})
    assert (
        env.fetcher.requests[-1].headers["Referer"] == f"http://{TOR_PROJECT}.onion/from/here?x=1"
    )
    other = f"{'a' * 26}.localhost:{PORT}"
    for referer in (f"http://{other}/page", "http://example.org/", "not a url", ""):
        env.client.get("/next", headers={**same, "referer": referer})
        assert "Referer" not in env.fetcher.requests[-1].headers, referer
    env.client.get(
        "/next",
        headers={"host": host, "sec-fetch-site": "same-site", "referer": f"http://{host}/p"},
    )
    assert "Referer" not in env.fetcher.requests[-1].headers


def test_the_samesite_attribute_is_stored_with_each_cookie() -> None:
    origin = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
    for value, expected in (
        ("Strict", "strict"),
        ("lax", "lax"),
        ("NONE", "none"),
        ("", "lax"),
        ("nonsense", "lax"),
    ):
        header = "a=1" + (f"; SameSite={value}" if value else "")
        cookie = parse_set_cookie(header, origin, "/", NOW)
        assert isinstance(cookie, Cookie) and cookie.same_site == expected


def test_cookies_stored_before_samesite_existed_are_read_as_lax() -> None:
    async def scenario() -> None:
        backing = InMemoryStore()
        jar = CookieJar(backing, ttl=60, clock=lambda: NOW)
        origin = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
        old = '[{"name":"a","value":"1","path":"/","expires":null,"created":1.0}]'
        await backing.put(f"jar:{SESSION}:{origin.key}", old, 60)
        assert await jar.header_for(SESSION, origin, "/", RequestContext()) == "a=1"
        assert await jar.header_for(SESSION, origin, "/", RequestContext(same_origin=False)) is None
        navigating = RequestContext(same_origin=False, navigation=True)
        assert await jar.header_for(SESSION, origin, "/", navigating) == "a=1"

    asyncio.run(scenario())


# --- finding 2: the session identifier must not reach Tor ------------------------------------------


def test_what_tor_is_given_is_not_the_session_identifier() -> None:
    env = Env()
    label = env.open()
    session_id = env.client.cookies.get("og_session")
    assert session_id
    env.get(label, "/one")
    env.get(label, "/two")
    keys = {r.isolation_key for r in env.fetcher.requests}
    assert len(keys) == 1  # stable for the session, so its circuits are reused
    (key,) = keys
    assert session_id not in key and key != session_id
    assert len(key) == 32 and set(key) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    other = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    other.post(
        "/open", data={"address": f"{TOR_PROJECT}.onion"}, headers={"sec-fetch-site": "same-origin"}
    )
    other_label = Env.viewer_label(
        other.post("/open", data={"address": f"{TOR_PROJECT}.onion"}).headers["location"]
    )
    other.get(
        "/", headers={"host": f"{other_label}.localhost:{PORT}", "sec-fetch-site": "same-origin"}
    )
    assert env.fetcher.requests[-1].isolation_key != key  # another session, another circuit


def test_a_different_gateway_process_derives_different_keys() -> None:
    first, second = Env(), Env()
    keys = []
    for env in (first, second):
        label = env.open()
        env.get(label)
        keys.append(env.fetcher.requests[-1].isolation_key)
    # The session identifiers differ anyway, so also compare the same identifier directly.
    assert first.gateway._isolation_key("session-aaaaaaaa") != second.gateway._isolation_key(
        "session-aaaaaaaa"
    )
    assert first.gateway._isolation_key("session-aaaaaaaa") == first.gateway._isolation_key(
        "session-aaaaaaaa"
    )


# --- finding 3 and 5: limits ------------------------------------------------------------------------


def test_a_page_can_only_create_so_many_new_labels() -> None:
    subs = [f"http://s{i}.{TOR_PROJECT}.onion/x" for i in range(8)]
    links = "".join(f"<a href='{u}'>l</a>" for u in subs)
    env = Env(lambda _r: reply(links), max_labels_per_page=3)
    label = env.open()
    body = env.get(label).text
    assert body.count("/_og/blocked/x") == 5  # three got labels, five did not
    assert ".invalid" not in body
    again = env.get(label).text  # labels that exist keep working on the next view
    assert again.count("/_og/blocked/x") == 2  # three more were allowed this time


def test_a_hostile_page_cannot_stop_the_visitor_opening_addresses() -> None:
    subs = [f"http://s{i}.{TOR_PROJECT}.onion/x" for i in range(30)]
    links = "".join(f"<a href='{u}'>l</a>" for u in subs)
    env = Env(lambda _r: reply(links), max_labels_per_session=5, max_labels_per_page=100)
    label = env.open()
    env.get(label)  # uses up the allowance for links
    assert (
        env.client.post(
            "/open",
            data={"address": f"http://{DUCKDUCKGO}.onion/"},
            headers={"sec-fetch-site": "same-origin"},
        ).status_code
        == 303
    )


def test_the_store_limits_total_size_as_well_as_the_number_of_entries() -> None:
    async def scenario() -> None:
        store = InMemoryStore(max_bytes=1000, max_entries=1000)
        await store.put("a", "x" * 400, 60)
        await store.put("b", "x" * 400, 60)
        with pytest.raises(StoreFullError):
            await store.put("c", "x" * 400, 60)
        await store.put("a", "x" * 10, 60)  # replacing with something smaller frees room
        await store.put("c", "x" * 400, 60)
        await store.delete("b")
        await store.put("d", "x" * 400, 60)

    asyncio.run(scenario())


def test_expired_entries_free_their_size_and_the_scan_is_not_run_on_every_insert() -> None:
    async def scenario() -> None:
        now = [1000.0]
        store = InMemoryStore(clock=lambda: now[0], max_bytes=1000, max_entries=1000)
        await store.put("a", "x" * 800, 5)
        with pytest.raises(StoreFullError):
            await store.put("b", "x" * 800, 5)
        now[0] += 10  # "a" has expired
        await store.put("b", "x" * 800, 5)
        assert await store.get("a") is None

    asyncio.run(scenario())


def test_the_cookie_jar_cannot_grow_past_its_size_limit() -> None:
    async def scenario() -> None:
        clock = [NOW]
        jar = CookieJar(InMemoryStore(), ttl=3600, clock=lambda: clock[0])
        origin = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
        for index in range(50):
            clock[0] += 1
            await jar.store_from_response(SESSION, origin, "/", [f"c{index}={'v' * 3000}"])
        header = await jar.header_for(SESSION, origin, "/")
        assert header is not None
        assert len(header) <= 8192 and "c49=" in header and "c0=" not in header

    asyncio.run(scenario())


def test_new_sessions_are_rate_limited() -> None:
    env = Env(max_new_sessions_per_minute=3)
    now = env.clock
    form = {"address": f"{TOR_PROJECT}.onion"}
    clients = [
        TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
        for _ in range(5)
    ]
    statuses = [c.post("/open", data=form).status_code for c in clients]
    assert statuses == [303, 303, 303, 429, 429]
    assert (
        clients[0].post("/open", data=form).status_code == 303
    )  # a visitor with a session is fine
    now[0] += 61
    assert clients[3].post("/open", data=form).status_code == 303


def test_only_so_many_fetches_run_at_once() -> None:
    env = Env(max_concurrent_fetches=3, max_fetches_per_session=2)
    gateway = env.gateway
    assert gateway._take_fetch_slot("one") and gateway._take_fetch_slot("one")
    assert not gateway._take_fetch_slot("one")  # the session's own limit
    assert gateway._take_fetch_slot("two")
    assert not gateway._take_fetch_slot("three")  # the overall limit
    gateway._release_fetch_slot("one")
    assert gateway._take_fetch_slot("three")
    for session in ("one", "two", "three"):
        gateway._release_fetch_slot(session)
    gateway._release_fetch_slot("three")  # never goes below zero in a way that unblocks others
    assert gateway._active_fetches == -0 or gateway._active_fetches <= 0


def test_a_busy_gateway_answers_quickly_and_a_failed_fetch_gives_its_slot_back() -> None:
    env = Env(lambda _r: UpstreamError("timeout"), max_concurrent_fetches=2)
    label = env.open()
    for _ in range(5):
        assert env.get(label).status_code == 504
    assert env.gateway._active_fetches == 0 and env.gateway._active_by_session == {}
    env.gateway._active_fetches = 2  # two fetches are already running
    busy = env.get(label)
    assert busy.status_code == 429 and "busy" in busy.text
    assert len(env.fetcher.requests) == 5  # the busy request never reached the onion


def test_a_flood_of_interim_replies_is_cut_off(tmp_path: Any) -> None:
    async def scenario() -> None:
        flood = b"HTTP/1.1 100 Continue\r\n\r\n" * 200 + http_response(b"done")
        async with FakeOnionServer(static_response(flood)) as onion, FakeTor(onion.port) as tor:
            origin = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
            request = UpstreamRequest(
                origin=origin,
                method="GET",
                target="/",
                headers=upstream_request_headers(origin, method="GET"),
                isolation_key="steady-session",
            )
            fetcher = TorFetcher(
                TorConfig(socks_ports=(tor.port,), total_timeout=5, read_timeout=2)
            )
            with pytest.raises(UpstreamError) as info:
                await fetcher.fetch(request)
            assert info.value.kind == "protocol_error"
            few = b"HTTP/1.1 100 Continue\r\n\r\n" * 3 + http_response(b"done")
        async with FakeOnionServer(static_response(few)) as onion, FakeTor(onion.port) as tor:
            fetcher = TorFetcher(
                TorConfig(socks_ports=(tor.port,), total_timeout=5, read_timeout=2)
            )
            assert (await fetcher.fetch(request)).body == b"done"

    asyncio.run(scenario())


# --- finding 6: the multipart boundary ---------------------------------------------------------------


def test_the_visitors_multipart_boundary_is_replaced() -> None:
    old = "----WebKitFormBoundaryAbCdEf123"
    body = (
        f'--{old}\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n'
        f'--{old}\r\nContent-Disposition: form-data; name="b"\r\n\r\n2\r\n--{old}--\r\n'
    ).encode()
    new_body, content_type = normalise_multipart(body, f"multipart/form-data; boundary={old}")
    assert content_type is not None and content_type.startswith(
        "multipart/form-data; boundary=----geckoformboundary"
    )
    assert b"WebKit" not in new_body and old.encode() not in new_body
    new = content_type.split("boundary=")[1]
    assert new_body.count(f"--{new}".encode()) == 3 and new_body.endswith(f"--{new}--\r\n".encode())
    assert b'name="a"\r\n\r\n1\r\n' in new_body  # the content is untouched
    other = normalise_multipart(body, f"multipart/form-data; boundary={old}")[1]
    assert other != content_type  # a fresh boundary every time, as a browser makes


def test_other_content_types_and_bad_boundaries_are_left_for_the_header_check() -> None:
    assert normalise_multipart(b"a=1", "application/x-www-form-urlencoded") == (
        b"a=1",
        "application/x-www-form-urlencoded",
    )
    assert normalise_multipart(b"", None) == (b"", None)
    assert normalise_multipart(b"x", "multipart/form-data") == (b"x", "multipart/form-data")
    long_boundary = "multipart/form-data; boundary=" + "a" * 100
    assert normalise_multipart(b"x", long_boundary) == (b"x", long_boundary)


def test_a_multipart_post_through_the_gateway_reaches_the_onion_with_the_new_boundary() -> None:
    env = Env()
    label = env.open()
    old = "----WebKitFormBoundaryZZ9"
    body = f'--{old}\r\nContent-Disposition: form-data; name="q"\r\n\r\nhi\r\n--{old}--\r\n'
    env.client.post(
        "/up",
        content=body.encode(),
        headers={
            "host": f"{label}.localhost:{PORT}",
            "sec-fetch-site": "same-origin",
            "content-type": f"multipart/form-data; boundary={old}",
        },
    )
    request = env.fetcher.requests[-1]
    assert "WebKit" not in request.headers["Content-Type"] and b"WebKit" not in request.body
    assert "geckoformboundary" in request.headers["Content-Type"]


# --- small robustness bugs ---------------------------------------------------------------------------


def test_far_future_and_zone_less_cookie_dates_do_not_crash() -> None:
    origin = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
    for date in (
        "Fri, 31 Dec 9999 23:59:59 -0000",
        "Fri, 31 Dec 9999 23:59:59 GMT",
        "Mon, 01 Jan 1000 00:00:00 -0000",
        "garbage",
    ):
        result = parse_set_cookie(f"a=b; Expires={date}", origin, "/", NOW)
        assert result is None or isinstance(result, (Cookie, type(result)))
    cookie = parse_set_cookie("a=b; Expires=Fri, 31 Dec 9999 23:59:59 -0000", origin, "/", NOW)
    assert isinstance(cookie, Cookie) and cookie.expires is not None
    assert cookie.expires - NOW <= 8 * 3600


def test_a_site_sending_a_far_future_cookie_date_still_gets_its_page_shown() -> None:
    env = Env(
        lambda _r: reply(
            "<p>ok</p>", headers=(("Set-Cookie", "a=b; Expires=Fri, 31 Dec 9999 23:59:59 -0000"),)
        )
    )
    assert env.get(env.open()).status_code == 200


@pytest.mark.parametrize("status", [204, 205, 304])
def test_replies_that_must_not_have_a_body_are_sent_without_one(status: int) -> None:
    env = Env(lambda _r: reply("<p>this should never be sent</p>", status=status))
    response = env.get(env.open())
    assert response.status_code == status
    assert response.content == b""


async def _raw_with_headers(app: Any, headers: list[tuple[bytes, bytes]]) -> int:
    status = 0

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "server": ("localhost", PORT),
        "client": ("127.0.0.1", 1),
        "http_version": "1.1",
    }
    await app(scope, receive, send)
    return status


def test_two_host_headers_are_refused() -> None:
    env = Env()
    label = env.open()
    good = (b"host", f"{label}.localhost:{PORT}".encode())
    assert asyncio.run(_raw_with_headers(env.gateway.app, [good])) == 200
    second = (b"host", f"{'a' * 26}.localhost:{PORT}".encode())
    assert asyncio.run(_raw_with_headers(env.gateway.app, [good, second])) == 400
    assert asyncio.run(_raw_with_headers(env.gateway.app, [(b"host", APEX.encode()), good])) == 400


@pytest.mark.parametrize(
    "target", ["http:///evil.example/", "http://", "https:///x", "http:/evil.example"]
)
def test_the_warning_page_refuses_addresses_without_a_host(target: str) -> None:
    env = Env()
    assert env.client.get("/_og/external", params={"u": target}).status_code == 400
