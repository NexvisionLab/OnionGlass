# SPDX-License-Identifier: AGPL-3.0-only
"""The entry relay: it forwards faithfully, passes on nothing that names the visitor, answers for
itself when a request is not its own, and fails cleanly when the gateway misbehaves."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from onionglass.cover import NOT_FOUND_PAGE
from onionglass.headers import HeaderPolicy, cover_headers
from onionglass.relay import (
    MAX_HEADERS,
    MAX_TARGET_CHARS,
    ConnectionAbort,
    Origin,
    Relay,
    RelaySettings,
)
from onionglass.relayauth import HEADER, RelaySigner, RelayVerifier
from onionglass.tickets import KeyRing, generate_key
from relay_origin import FakeOrigin, Reply, Seen, certificate

Headers = list[tuple[str | bytes, str | bytes]]
DOMAIN = "alpha.example.net"
VISITOR = ("203.0.113.9", 4444)
KEY = generate_key()
RING = KeyRing()
RING.add("r1", KEY.public_key())


def relay_for(port: int, **options: Any) -> Relay:
    origin = options.pop("origin", None) or Origin("127.0.0.1", port, tls=False)
    return Relay(
        RelaySettings(
            domains=options.pop("domains", (DOMAIN,)),
            origin=origin,
            signer=RelaySigner("r1", KEY),
            **options,
        )
    )


@dataclass
class Answer:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    finished: bool
    aborted: bool = False  # the relay dropped the connection instead of ending the answer

    def all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name.lower()]


def _bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("latin-1")


async def ask(
    relay: Relay,
    method: str = "GET",
    target: str | bytes = "/",
    *,
    host: str | bytes | None = DOMAIN,
    headers: list[tuple[str | bytes, str | bytes]] | None = None,
    body: list[bytes] | None = None,
    client: tuple[str, int] | None = VISITOR,
    hang: bool = False,
    leave_after: float | None = None,
    drip: float = 0.0,
    slow_reader: bool = False,
) -> Answer:
    """One visitor's request, straight into the relay.

    With ``hang`` the visitor sends the pieces in ``body`` and does not finish. ``drip`` is the
    wait before each piece. A visitor stays connected, as a real one does, until ``leave_after``
    seconds have passed. With ``slow_reader`` the visitor never takes the answer's body."""
    raw = _bytes(target)
    path, _, query = raw.partition(b"?")
    pairs = [] if host is None else [(b"host", _bytes(host))]
    pairs += [(_bytes(k).lower(), _bytes(v)) for k, v in (headers or [])]
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path.decode("latin-1"),
        "raw_path": path,
        "query_string": query,
        "headers": pairs,
        "server": ("relay", 443),
        "client": client,
    }
    pieces = list(body or [])
    answer = Answer(0, [], b"", False)

    async def receive() -> dict[str, Any]:
        if pieces:
            if drip:
                await asyncio.sleep(drip)
            more = bool(pieces[1:]) or hang
            return {"type": "http.request", "body": pieces.pop(0), "more_body": more}
        await asyncio.sleep(3600 if leave_after is None else leave_after)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            answer.status = message["status"]
            answer.headers = [
                (k.decode("latin-1"), v.decode("latin-1")) for k, v in message["headers"]
            ]
        elif message["type"] == "http.response.body":
            if slow_reader:
                await asyncio.sleep(3600)
            answer.body += message.get("body", b"")
            answer.finished = not message.get("more_body", False)

    try:
        await asyncio.wait_for(relay(scope, receive, send), 15)
    except ConnectionAbort:
        answer.aborted = True
    return answer


async def in_flight(relay: Relay, count: int = 1) -> None:
    """Wait until the relay has this many requests being served. A test that must do something
    while one is still going waits for that, and not for a fixed time, which a slow machine
    would make too short."""
    for _ in range(500):
        if relay.busy()[0] >= count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the request never started")


def signed_by_the_relay(seen: Seen) -> str:
    """Check the signature on a request the fake gateway received. Returns the relay's id."""
    return RelayVerifier(RING).verify(seen.one(HEADER), seen.method, seen.one("host"), seen.target)


async def through(
    behave: Any = None, *, relay_options: dict[str, Any] | None = None, **request: Any
) -> tuple[Answer, FakeOrigin]:
    async with FakeOrigin(behave) as origin:
        relay = relay_for(origin.port, **(relay_options or {}))
        answer = await ask(relay, **request)
        assert relay.busy() == (0, 0)
        return answer, origin


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --- forwarding ----------------------------------------------------------------------------------


def test_a_request_reaches_the_gateway_with_the_same_method_host_and_target() -> None:
    answer, origin = run(through(target="/page?q=1&z=%20&a=b", host=DOMAIN))
    assert answer.status == 200 and answer.body == b"ok" and answer.finished
    (seen,) = origin.seen
    assert (seen.method, seen.target) == ("GET", "/page?q=1&z=%20&a=b")
    assert seen.one("host") == DOMAIN
    assert signed_by_the_relay(seen) == "r1"
    assert seen.one("connection") == "close"


@pytest.mark.parametrize(
    "host", ["k3f9abc.alpha.example.net", "alpha.example.net:8443", "A.Alpha.Example.NET."]
)
def test_the_domain_and_every_name_under_it_are_forwarded_exactly_as_asked(host: str) -> None:
    _, origin = run(through(host=host))
    assert [s.one("host") for s in origin.seen] == [host]
    assert signed_by_the_relay(origin.seen[0]) == "r1"


def test_every_header_that_names_the_visitor_is_dropped_and_the_address_appears_nowhere() -> None:
    names = [
        "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
        "x-forwarded-anything", "forwarded", "via", "x-real-ip", "true-client-ip",
        "cf-connecting-ip", "x-client-ip", "x-cluster-client-ip", "fastly-client-ip",
        "client-ip", "x-originating-ip", "x-remote-ip", "x-remote-addr", "x-forwarded",
        "cf-connecting-ipv6", "cf-ipcountry", "cf-ray", "cf-visitor", "x-azure-clientip",
        "x-azure-socketip", "x-original-forwarded-for", "proxy-client-ip", "wl-proxy-client-ip",
        "x-appengine-user-ip", "x-proxyuser-ip", "x-vercel-forwarded-for", "x-coming-from",
        "x-amzn-trace-id", "authorization", "x-og-anything", "x-og-check", "x-og-forwarded",
    ]  # fmt: skip
    headers: list[tuple[str | bytes, str | bytes]] = [(n, VISITOR[0]) for n in names]
    _, origin = run(through(headers=headers))
    (seen,) = origin.seen
    assert not [k for k, _ in seen.headers if k in names]
    assert (
        VISITOR[0].encode() not in seen.raw_head and str(VISITOR[1]).encode() not in seen.raw_head
    )


def test_a_signature_header_the_visitor_sent_is_replaced_by_the_relays_own() -> None:
    forged = RelaySigner("r1", KEY).sign("GET", DOMAIN, "/other")
    _, origin = run(through(headers=[(HEADER, forged), (HEADER.upper(), "r1.abc.def")]))
    (seen,) = origin.seen
    assert len(seen.all(HEADER)) == 1 and seen.one(HEADER) != forged
    assert signed_by_the_relay(seen) == "r1"


def test_headers_of_the_visitors_own_connection_are_dropped_and_the_rest_are_kept() -> None:
    headers: list[tuple[str | bytes, str | bytes]] = [
        ("connection", "keep-alive, x-secret-hop"), ("x-secret-hop", "1"), ("keep-alive", "timeout=5"),
        ("proxy-authorization", "Basic abc"), ("te", "trailers"), ("upgrade", "websocket"),
        ("expect", "100-continue"), ("trailer", "x"),
        ("cookie", "og_session=abc"), ("user-agent", "Browser/1"), ("accept-language", "fa"),
        ("referer", "https://alpha.example.net/x"), ("origin", "https://alpha.example.net"),
        ("sec-fetch-site", "same-origin"), ("accept-encoding", "gzip"), ("accept", "text/html"),
    ]  # fmt: skip
    _, origin = run(through(headers=headers))
    (seen,) = origin.seen
    for gone in (
        "x-secret-hop",
        "keep-alive",
        "proxy-authorization",
        "te",
        "upgrade",
        "expect",
        "trailer",
    ):
        assert seen.all(gone) == [], gone
    assert seen.all("connection") == ["close"]
    for kept, value in (
        ("cookie", "og_session=abc"), ("user-agent", "Browser/1"), ("accept-language", "fa"),
        ("sec-fetch-site", "same-origin"), ("accept-encoding", "gzip"), ("origin", "https://alpha.example.net"),
    ):  # fmt: skip
        assert seen.one(kept) == value


def test_a_body_with_a_length_arrives_whole() -> None:
    payload = [b"a" * 1000, b"b" * 2000, b"c"]
    answer, origin = run(
        through(method="POST", target="/open", headers=[("content-length", "3001")], body=payload)
    )
    assert answer.status == 200
    (seen,) = origin.seen
    assert seen.body == b"".join(payload) and seen.one("content-length") == "3001"


def test_a_chunked_body_arrives_whole() -> None:
    payload = [b"x" * 500, b"y" * 700, b"z" * 3]
    _, origin = run(
        through(method="POST", headers=[("transfer-encoding", "chunked")], body=payload)
    )
    (seen,) = origin.seen
    assert seen.body == b"".join(payload)
    assert seen.all("content-length") == []


def test_an_empty_post_arrives_empty() -> None:
    _, origin = run(through(method="POST", headers=[("content-length", "0")], body=[b""]))
    assert origin.seen[0].body == b""
    assert origin.seen[0].one("content-length") == "0"  # some servers answer 411 without it


def test_a_get_carries_no_length_and_a_head_or_delete_none_either() -> None:
    for method in ("GET", "HEAD", "DELETE", "OPTIONS"):
        _, origin = run(through(method=method))
        assert origin.seen[0].all("content-length") == [], method


# --- the answer comes back unchanged -------------------------------------------------------------


def test_status_headers_and_body_come_back_and_the_gateways_server_headers_do_not() -> None:
    reply = Reply(
        status=302,
        headers=[
            ("Location", "/next"), ("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/"),
            ("Content-Type", "text/html; charset=utf-8"), ("Server", "uvicorn"),
            ("Date", "Mon, 01 Jan 2029 00:00:00 GMT"), ("Connection", "close"), ("Keep-Alive", "x"),
            ("Via", "1.1 proxy"), ("Alt-Svc", 'h3=":8443"'),
        ],
        body=b"moved",
    )  # fmt: skip
    answer, _ = run(through(lambda _s: reply))
    assert answer.status == 302 and answer.body == b"moved"
    assert answer.all("location") == ["/next"]
    assert answer.all("set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert answer.all("content-type") == ["text/html; charset=utf-8"]
    assert answer.all("content-length") == ["5"]
    for gone in (
        "server",
        "date",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "via",
        "alt-svc",
    ):
        assert answer.all(gone) == [], gone


def test_a_chunked_answer_is_passed_on_piece_by_piece_without_the_chunking_header() -> None:
    reply = Reply(chunks=[b"one", b"two", b"three"])
    answer, _ = run(through(lambda _s: reply))
    assert answer.body == b"onetwothree" and answer.finished
    assert answer.all("transfer-encoding") == [] and answer.all("content-length") == []


def test_a_head_request_gets_the_length_and_no_body() -> None:
    reply = Reply(headers=[("Content-Length", "1234")], body=b"")
    answer, origin = run(through(lambda _s: reply, method="HEAD"))
    assert answer.status == 200 and answer.body == b"" and answer.finished
    assert answer.all("content-length") == ["1234"] and origin.seen[0].method == "HEAD"


@pytest.mark.parametrize("status", [204, 304, 404, 500])
def test_the_gateways_own_statuses_are_not_changed(status: int) -> None:
    reply = Reply(status=status, body=b"" if status in (204, 304) else b"text")
    answer, _ = run(through(lambda _s: reply))
    assert answer.status == status


def test_a_large_answer_comes_back_whole() -> None:
    pieces = [bytes([i % 251]) * 65_536 for i in range(48)]
    answer, _ = run(through(lambda _s: Reply(chunks=pieces)))
    assert answer.body == b"".join(pieces)


# --- what the relay answers itself ---------------------------------------------------------------


def cover_style(answer: Answer, status: int, page: bytes) -> None:
    assert answer.status == status and answer.body == page and answer.finished
    expected = {k.lower(): v for k, v in cover_headers(HeaderPolicy("https", DOMAIN)).items()}
    got = dict(answer.headers)
    for name, value in expected.items():
        assert got[name] == value, name
    assert got["content-length"] == str(len(page))
    assert "server" not in got


@pytest.mark.parametrize(
    "host",
    [
        "other.example", "xalpha.example.net", "alpha.example.net.evil.example", "example.net",
        "alpha.example.net:abc", "alpha.example.net:123456", "", "[::1]", "alpha.example.net@evil.example",
    ],
)  # fmt: skip
def test_a_host_that_is_not_the_relays_is_a_missing_page_and_nothing_is_sent_on(host: str) -> None:
    answer, origin = run(through(host=host))
    cover_style(answer, 404, NOT_FOUND_PAGE)
    assert origin.connections == 0


def test_a_host_with_no_value_or_non_ascii_or_given_twice_is_a_missing_page() -> None:
    async def scenario() -> list[Answer]:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port)
            answers = [
                await ask(relay, host=None),
                await ask(relay, host=b"alpha.example.net\xe9"),
                await ask(relay, headers=[("host", DOMAIN)]),
            ]
            assert origin.connections == 0
            return answers

    for answer in run(scenario()):
        cover_style(answer, 404, NOT_FOUND_PAGE)


@pytest.mark.parametrize("method", ["CONNECT", "TRACE", "PROPFIND", "get", "BREW"])
def test_a_method_the_gateway_does_not_use_is_a_missing_page(method: str) -> None:
    answer, origin = run(through(method=method))
    cover_style(answer, 404, NOT_FOUND_PAGE)
    assert origin.connections == 0


@pytest.mark.parametrize(
    "target",
    [
        b"/caf\xc3\xa9",
        b"//evil.example/x",
        b"*",
        b"x",
        b"/a b",
        b"/a\tb",
        "/" + "a" * MAX_TARGET_CHARS,
        b"/\x7f",
    ],
)
def test_a_target_that_is_not_plain_printable_text_is_refused(target: str | bytes) -> None:
    answer, origin = run(through(target=target))
    cover_style(answer, 404, NOT_FOUND_PAGE)  # as the gateway answers a stranger
    assert origin.connections == 0


def test_too_many_headers_or_one_that_is_too_large_is_refused() -> None:
    many: list[tuple[str | bytes, str | bytes]] = [(f"x-h{i}", "1") for i in range(MAX_HEADERS + 1)]
    answer, origin = run(through(headers=many))
    cover_style(answer, 404, NOT_FOUND_PAGE)  # as the gateway answers a stranger
    assert origin.connections == 0
    answer, origin = run(through(headers=[("x-big", "a" * 20_000)]))
    cover_style(answer, 404, NOT_FOUND_PAGE)  # as the gateway answers a stranger
    assert origin.connections == 0


@pytest.mark.parametrize(
    "headers",
    [
        [("content-length", "abc")], [("content-length", "-1")], [("content-length", "1 2")],
        [("content-length", "1"), ("content-length", "1")],
        [("content-length", "1"), ("transfer-encoding", "chunked")],
        [("content-length", "9" * 20)],
    ],
)  # fmt: skip
def test_a_body_length_that_is_not_one_number_is_refused(headers: list[tuple[str, str]]) -> None:
    answer, origin = run(through(method="POST", headers=headers, body=[b"x"]))
    cover_style(answer, 404, NOT_FOUND_PAGE)
    assert origin.connections == 0


def test_a_body_that_is_declared_too_large_is_refused_before_anything_is_sent_on() -> None:
    answer, origin = run(
        through(
            method="POST",
            headers=[("content-length", "101")],
            body=[b"x" * 101],
            relay_options={"max_request_body": 100},
        )
    )
    cover_style(answer, 404, NOT_FOUND_PAGE)
    assert origin.connections == 0


def test_a_chunked_body_that_grows_past_the_limit_is_cut_off_and_never_completed() -> None:
    answer, origin = run(
        through(
            method="POST",
            headers=[("transfer-encoding", "chunked")],
            body=[b"x" * 60, b"y" * 60],
            relay_options={"max_request_body": 100},
        )
    )
    cover_style(answer, 404, NOT_FOUND_PAGE)
    assert origin.seen == []  # the gateway never saw a whole request


def test_a_web_socket_is_closed_and_the_start_and_stop_messages_are_answered() -> None:
    async def scenario() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        relay = relay_for(1)
        sent: list[dict[str, Any]] = []
        inbox = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        lifespans: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return inbox.pop(0)

        async def record(message: dict[str, Any]) -> None:
            lifespans.append(message)

        async def collect(message: dict[str, Any]) -> None:
            sent.append(message)

        await relay({"type": "lifespan"}, receive, record)
        await relay({"type": "websocket", "headers": []}, receive, collect)
        return sent, lifespans

    sent, lifespans = run(scenario())
    assert sent == [{"type": "websocket.close", "code": 1008}]
    assert [m["type"] for m in lifespans] == [
        "lifespan.startup.complete",
        "lifespan.shutdown.complete",
    ]


# --- when the gateway cannot answer --------------------------------------------------------------


def test_a_gateway_that_is_not_there_is_a_bad_gateway() -> None:
    async def scenario() -> Answer:
        relay = relay_for(1)  # nothing listens on port 1
        answer = await ask(relay)
        assert relay.busy() == (0, 0)
        return answer

    assert run(scenario()).status == 502


@pytest.mark.parametrize(
    "reply",
    [
        Reply(raw=b"this is not http\r\n\r\n"),
        Reply(raw=b""),
        Reply(raw=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n"),
        # A switch of protocol, and then something that looks like a good answer: the relay must
        # not read what follows a 101 as the reply.
        Reply(
            raw=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
        ),
        Reply(raw=b"HTTP/1.1 200 OK\r\n" + b"X-A: " + b"a" * 70_000 + b"\r\n\r\n"),
        Reply(raw=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"),
        Reply(
            raw=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello"
        ),
    ],
)
def test_an_answer_that_is_not_a_web_servers_is_a_bad_gateway(reply: Reply) -> None:
    answer, _ = run(through(lambda _s: reply))
    assert answer.status == 502


def test_a_gateway_that_never_answers_is_a_bad_gateway_after_the_idle_time() -> None:
    answer, _ = run(through(lambda _s: Reply(stall=5), relay_options={"idle_timeout": 0.3}))
    assert answer.status == 502


def cut_off(answer: Answer) -> None:
    """The relay dropped the visitor's connection and did not end the answer as if it were whole,
    which would make half a page look like all of it."""
    assert answer.aborted and not answer.finished


def test_an_answer_that_stops_part_way_is_cut_off_and_not_ended_as_if_whole() -> None:
    reply = Reply(body=b"half", short_by=100)
    answer, _ = run(through(lambda _s: reply))
    assert answer.status == 200 and answer.body == b"half"
    cut_off(answer)


def test_a_chunked_answer_that_stops_before_its_end_is_cut_off_and_not_ended_as_if_whole() -> None:
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"
    answer, _ = run(through(lambda _s: Reply(raw=raw)))
    assert answer.status == 200 and answer.body == b"hello"
    cut_off(answer)


def test_an_answer_that_stalls_part_way_is_cut_off_after_the_idle_time() -> None:
    reply = Reply(chunks=[b"a", b"b"], chunk_delay=5)
    answer, _ = run(through(lambda _s: reply, relay_options={"idle_timeout": 0.3}))
    assert answer.body == b"a"
    cut_off(answer)


def test_an_answer_that_hangs_up_after_the_head_is_cut_off() -> None:
    answer, _ = run(through(lambda _s: Reply(hang_up_after_head=True, body=b"x")))
    cut_off(answer)


def test_an_answer_larger_than_the_limit_is_cut_off() -> None:
    reply = Reply(chunks=[b"a" * 1000] * 10)
    answer, _ = run(through(lambda _s: reply, relay_options={"max_response_body": 2500}))
    assert 0 < len(answer.body) <= 2500
    cut_off(answer)


# --- the encrypted hop ---------------------------------------------------------------------------


def test_the_hop_is_encrypted_and_works_when_the_certificate_is_the_pinned_one(
    tmp_path: Path,
) -> None:
    cert, key, pin = certificate(tmp_path)

    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin(tls=(cert, key)) as origin:
            relay = relay_for(origin.port, origin=Origin("127.0.0.1", origin.port, pin_sha256=pin))
            return await ask(relay), origin

    answer, origin = run(scenario())
    assert answer.status == 200 and answer.body == b"ok"
    assert signed_by_the_relay(origin.seen[0]) == "r1"


def test_a_certificate_that_is_not_the_pinned_one_gets_no_request(tmp_path: Path) -> None:
    cert, key, _ = certificate(tmp_path)

    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin(tls=(cert, key)) as origin:
            wrong = "0" * 64
            relay = relay_for(
                origin.port, origin=Origin("127.0.0.1", origin.port, pin_sha256=wrong)
            )
            return await ask(relay, headers=[("cookie", "og_session=abc")]), origin

    answer, origin = run(scenario())
    assert answer.status == 502
    assert origin.seen == []  # nothing, not even the signed head, was sent to the wrong server


def test_an_unencrypted_server_answering_where_tls_is_expected_is_a_bad_gateway(
    tmp_path: Path,
) -> None:
    async def scenario() -> Answer:
        async with FakeOrigin() as origin:  # speaks plain HTTP
            relay = relay_for(
                origin.port, origin=Origin("127.0.0.1", origin.port, pin_sha256="a" * 64)
            )
            return await ask(relay)

    assert run(scenario()).status == 502


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"tls": True}, "pin_sha256"),
        ({"tls": True, "pin_sha256": "A" * 64}, "pin_sha256"),
        ({"tls": True, "pin_sha256": "a" * 63}, "pin_sha256"),
        ({"tls": True, "pin_sha256": "g" * 64}, "pin_sha256"),
        ({"tls": False, "host": "203.0.113.5"}, "unencrypted"),
        ({"tls": False, "host": "gateway.internal"}, "unencrypted"),
        ({"host": ""}, "host"),
        ({"port": 0}, "port"),
        ({"port": 70000}, "port"),
    ],
)
def test_an_origin_that_could_not_be_trusted_is_refused(
    options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        Origin(**{"host": "127.0.0.1", "port": 8443, **options})


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_an_unencrypted_origin_is_fine_on_this_machine(host: str) -> None:
    assert Origin(host, 8080, tls=False).host == host


def test_an_unencrypted_origin_on_a_network_is_allowed_only_when_said() -> None:
    assert Origin("198.51.100.8", 8080, tls=False, allow_plain=True).allow_plain


# --- limits --------------------------------------------------------------------------------------


def test_when_too_many_requests_are_in_flight_the_next_is_told_to_wait_and_the_count_returns_to_zero() -> (
    None
):
    async def scenario() -> list[Answer]:
        async with FakeOrigin(lambda _s: Reply(stall=0.6, body=b"slow")) as origin:
            relay = relay_for(origin.port, max_concurrent=2, max_per_client=50)
            first = [
                asyncio.create_task(ask(relay, client=(f"198.51.100.{i}", 1))) for i in range(2)
            ]
            await in_flight(relay, 2)
            refused = await ask(relay, client=("198.51.100.99", 1))
            done = await asyncio.gather(*first)
            assert relay.busy() == (0, 0)
            again = await ask(relay, client=("198.51.100.99", 1))
            return [refused, *done, again]

    refused, one, two, again = run(scenario())
    assert refused.status == 503 and dict(refused.headers)["retry-after"] == "5"
    assert one.status == two.status == again.status == 200


def test_one_visitor_cannot_use_up_the_relay() -> None:
    async def scenario() -> list[Answer]:
        async with FakeOrigin(lambda _s: Reply(stall=0.6, body=b"slow")) as origin:
            relay = relay_for(origin.port, max_per_client=2)
            held = [asyncio.create_task(ask(relay, client=("198.51.100.1", i))) for i in range(2)]
            await in_flight(relay, 2)
            same = await ask(relay, client=("198.51.100.1", 99))
            other = await ask(relay, client=("198.51.100.2", 1))
            await asyncio.gather(*held)
            assert relay.busy() == (0, 0)
            return [same, other]

    same, other = run(scenario())
    assert same.status == 429 and dict(same.headers)["retry-after"] == "5"
    assert other.status == 200


@pytest.mark.parametrize(
    "request_",
    [
        {"host": "other.example"},
        {"target": b"/caf\xc3\xa9"},
        {"method": "POST", "headers": [("content-length", "500")], "body": [b"x" * 500]},
    ],
)
def test_refused_requests_do_not_leave_the_count_up(request_: dict[str, Any]) -> None:
    async def scenario() -> tuple[int, int]:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port, max_concurrent=1, max_per_client=1, max_request_body=100)
            for _ in range(3):
                await ask(relay, **request_)
            return relay.busy()

    assert run(scenario()) == (0, 0)


def test_failures_do_not_leave_the_count_up() -> None:
    async def scenario() -> tuple[int, int]:
        async with FakeOrigin(lambda _s: Reply(raw=b"junk\r\n\r\n")) as origin:
            relay = relay_for(origin.port, max_concurrent=1, max_per_client=1)
            for _ in range(3):
                assert (await ask(relay)).status == 502
            return relay.busy()

    assert run(scenario()) == (0, 0)


def test_the_visitors_address_is_taken_from_a_proxy_in_front_only_when_asked_and_only_from_this_machine() -> (
    None
):
    async def scenario(trust: bool, peer: str) -> list[int]:
        async with FakeOrigin(lambda _s: Reply(stall=0.5, body=b"slow")) as origin:
            relay = relay_for(origin.port, max_per_client=1, trust_forwarded=trust)
            first = asyncio.create_task(
                ask(relay, client=(peer, 1), headers=[("x-forwarded-for", "198.51.100.1")])
            )
            await in_flight(relay)
            second = await ask(
                relay, client=(peer, 2), headers=[("x-forwarded-for", "198.51.100.2")]
            )
            await first
            return [second.status]

    assert run(scenario(True, "127.0.0.1")) == [200]  # two visitors behind one local proxy
    assert run(scenario(False, "127.0.0.1")) == [429]  # not trusted: both look like the proxy
    assert run(scenario(True, "203.0.113.50")) == [429]  # trusted only from this machine


def test_the_last_address_the_proxy_wrote_is_the_one_used_and_a_bad_one_is_ignored() -> None:
    async def scenario() -> list[int]:
        async with FakeOrigin(lambda _s: Reply(stall=0.5, body=b"slow")) as origin:
            relay = relay_for(origin.port, max_per_client=1, trust_forwarded=True)
            spoof = "x-forwarded-for", "198.51.100.77, 198.51.100.1"
            first = asyncio.create_task(ask(relay, client=("127.0.0.1", 1), headers=[spoof]))
            await in_flight(relay)
            same = await ask(
                relay,
                client=("127.0.0.1", 2),
                headers=[("x-forwarded-for", "198.51.100.9, 198.51.100.1")],
            )
            junk = await ask(
                relay, client=("127.0.0.1", 3), headers=[("x-forwarded-for", "not-an-address")]
            )
            await first
            return [same.status, junk.status]

    assert run(scenario()) == [429, 200]


# --- the settings --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "options",
    [
        {"domains": ()},
        {"domains": ("Not.Valid.Example",)},
        {"domains": ("a..b",)},
        {"max_concurrent": 0},
        {"max_per_client": 0},
        {"max_request_body": 0},
        {"max_request_body": 100_000_001},
        {"max_response_body": 0},
        {"connect_timeout": 0},
        {"idle_timeout": 601},
    ],
)
def test_relay_settings_that_could_not_work_are_refused(options: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"."):
        relay_for(1, **options)


# --- what the relay writes down ------------------------------------------------------------------


def test_a_request_that_works_writes_nothing_down(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    run(through(target="/secret-path?token=abc", client=VISITOR))
    ours = [record for record in caplog.records if record.name.startswith("onionglass")]
    assert ours == []


def test_a_failure_is_logged_without_the_visitor_the_host_or_the_page(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")

    async def scenario() -> None:
        relay = relay_for(1)  # nothing listens, so the request fails
        await ask(
            relay,
            target="/secret-path?token=abc",
            host="k3f9abc.alpha.example.net",
            client=VISITOR,
            headers=[("cookie", "og_session=hunter2")],
        )

    run(scenario())
    assert [r for r in caplog.records if r.name.startswith("onionglass")], "say it once"
    written = " ".join(record.getMessage() for record in caplog.records)
    for secret_thing in (VISITOR[0], "secret-path", "token=abc", "k3f9abc", DOMAIN, "hunter2"):
        assert secret_thing not in written


def test_a_certificate_that_is_not_the_pinned_one_is_logged_without_naming_anything(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    cert, key, _ = certificate(tmp_path)

    async def scenario() -> None:
        async with FakeOrigin(tls=(cert, key)) as origin:
            relay = relay_for(
                origin.port, origin=Origin("127.0.0.1", origin.port, pin_sha256="0" * 64)
            )
            await ask(relay, target="/secret-path", client=VISITOR)

    run(scenario())
    written = " ".join(record.getMessage() for record in caplog.records)
    assert "pinned" in written
    assert "secret-path" not in written and VISITOR[0] not in written


# --- a visitor who goes quiet --------------------------------------------------------------------


@pytest.mark.parametrize("framing", [("content-length", "100"), ("transfer-encoding", "chunked")])
def test_a_visitor_who_stops_sending_the_body_is_timed_out_and_the_slot_is_freed(
    framing: tuple[str, str],
) -> None:
    async def scenario() -> tuple[Answer, Answer, FakeOrigin]:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port, idle_timeout=0.3, max_per_client=1)
            slow = await ask(relay, "POST", "/open", headers=[framing], body=[b"x" * 10], hang=True)
            assert relay.busy() == (0, 0)
            return slow, await ask(relay), origin  # the same visitor can carry on

    slow, fine, origin = run(scenario())
    assert slow.status == 408 and slow.finished
    assert fine.status == 200
    assert [seen for seen in origin.seen if seen.method == "POST"] == []  # never completed


def test_a_visitor_who_sends_nothing_at_all_of_a_declared_body_is_timed_out_too() -> None:
    async def scenario() -> Answer:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port, idle_timeout=0.3)
            return await ask(
                relay, "POST", "/open", headers=[("content-length", "5")], body=[], hang=True
            )

    assert run(scenario()).status == 408


def test_only_ordinary_browser_headers_pass_and_a_header_nobody_thought_of_does_not() -> None:
    headers: list[tuple[str | bytes, str | bytes]] = [
        ("x_forwarded_for", VISITOR[0]),
        ("x_real_ip", VISITOR[0]),
        ("client_ip", VISITOR[0]),
        ("x_og_relay", "r1.abc.def.ghi"),
        ("custom_header", "1"),
        ("x-custom-header", "dropped too"),
        ("x-brand-new-visitor-header", VISITOR[0]),
        ("user-agent", "Browser/1"),
        ("sec-ch-ua-platform", '"x"'),
        ("sec-fetch-dest", "document"),
    ]
    _, origin = run(through(headers=headers))
    (seen,) = origin.seen
    names = {name for name, _ in seen.headers}
    assert not [n for n in names if "_" in n or n.startswith(("x-custom", "x-brand"))]
    assert seen.one("user-agent") == "Browser/1" and seen.one("sec-fetch-dest") == "document"
    assert seen.one("sec-ch-ua-platform") == '"x"'
    assert VISITOR[0].encode() not in seen.raw_head


# --- the operator's check ------------------------------------------------------------------------


def test_only_the_operators_own_check_carries_the_marker_and_a_visitor_cannot_add_it() -> None:
    from onionglass.relay import probe  # noqa: PLC0415
    from onionglass.relayauth import CHECK_HEADER  # noqa: PLC0415

    async def scenario() -> FakeOrigin:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port)
            await ask(relay, headers=[(CHECK_HEADER, "1")])  # a visitor trying it
            await probe(relay, DOMAIN, "/_og/relay-check")
            return origin

    visitor, operator = run(scenario()).seen
    assert visitor.all(CHECK_HEADER) == []
    assert operator.all(CHECK_HEADER) == ["1"]


# --- a visitor who is slow, quiet or gone ---------------------------------------------------------


def test_a_visitor_who_does_not_take_the_answer_is_cut_off_and_the_slot_is_freed() -> None:
    reply = Reply(chunks=[b"x" * 1000] * 5, chunk_delay=0.01)

    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin(lambda _s: reply) as origin:
            relay = relay_for(origin.port, idle_timeout=0.3, max_per_client=1)
            slow = await ask(relay, slow_reader=True)
            assert relay.busy() == (0, 0)
            return slow, origin

    slow, _ = run(scenario())
    assert slow.status == 200
    cut_off(slow)


def test_a_visitor_who_sends_a_body_a_little_at_a_time_is_stopped_by_the_total_time() -> None:
    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port, idle_timeout=5, max_request_seconds=0.6)
            answer = await ask(
                relay,
                "POST",
                "/open",
                headers=[("content-length", "10")],
                body=[b"x"] * 10,
                drip=0.2,
                hang=True,
            )
            assert relay.busy() == (0, 0)
            return answer, origin

    answer, origin = run(scenario())
    assert answer.status == 408  # each piece came in time, but all of them took too long
    assert [seen for seen in origin.seen if seen.method == "POST"] == []


def test_the_total_time_also_ends_an_answer_that_never_finishes() -> None:
    reply = Reply(chunks=[b"x"] * 100, chunk_delay=0.2)
    answer, _ = run(
        through(lambda _s: reply, relay_options={"idle_timeout": 5, "max_request_seconds": 0.6})
    )
    assert 0 < len(answer.body) < 100
    cut_off(answer)


def test_a_visitor_who_leaves_in_the_middle_of_an_upload_is_forgotten_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")

    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port)
            answer = await ask(
                relay,
                "POST",
                "/open",
                headers=[("content-length", "100")],
                body=[b"x" * 10],
                hang=True,
                leave_after=0,
            )
            assert relay.busy() == (0, 0)
            return answer, origin

    answer, origin = run(scenario())
    assert answer.status == 0  # nobody was there to answer
    assert [seen for seen in origin.seen if seen.method == "POST"] == []
    assert [r for r in caplog.records if r.name.startswith("onionglass")] == []


def test_a_visitor_who_leaves_in_the_middle_of_an_answer_stops_the_relay_pulling_it() -> None:
    reply = Reply(chunks=[b"x" * 10_000] * 100, chunk_delay=0.05)  # five seconds in all

    async def scenario() -> tuple[Answer, float]:
        async with FakeOrigin(lambda _s: reply) as origin:
            relay = relay_for(origin.port)
            started = time.monotonic()
            answer = await ask(relay, leave_after=0.3)
            took = time.monotonic() - started
            assert relay.busy() == (0, 0)
            assert origin.connections == 1
            return answer, took

    answer, took = run(scenario())
    assert took < 3
    assert answer.status == 200 and not answer.finished and not answer.aborted


def test_an_answer_the_gateway_gives_before_it_has_read_a_large_upload_reaches_the_visitor() -> (
    None
):
    reply = Reply(status=404, body=b"not here")
    pieces = [b"x" * 100_000 for _ in range(9)]

    async def scenario() -> list[int]:
        async with FakeOrigin(lambda _s: reply, early=True) as origin:
            relay = relay_for(origin.port)
            statuses = []
            for _ in range(5):
                answer = await ask(
                    relay,
                    "POST",
                    "/open",
                    headers=[("content-length", str(sum(map(len, pieces))))],
                    body=list(pieces),
                )
                statuses.append(answer.status)
            assert relay.busy() == (0, 0)
            return statuses

    assert run(scenario()) == [404] * 5


# --- an origin that could not be trusted ---------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "a..b.example", ".example", "-a.example", "a-.example", "a_b.example", "ho st",
        "a" * 64 + ".example", "x" * 254, "a.example.", "gateway.example/x", "a@b", "a:b",
    ],
)  # fmt: skip
def test_an_origin_host_that_is_not_a_name_or_an_address_is_refused(host: str) -> None:
    with pytest.raises(ValueError, match="host"):
        Origin(host, 8443, tls=False, allow_plain=True)


@pytest.mark.parametrize(
    "host",
    [
        "gateway", "gateway.internal", "g-1.example.net", "203.0.113.5", "2001:db8::1",
        "127.0.0.1", "localhost", "xn--bcher-kva.example", "GATEWAY.Example",
    ],
)  # fmt: skip
def test_an_origin_host_that_is_a_name_or_an_address_is_accepted(host: str) -> None:
    assert Origin(host, 8443, tls=False, allow_plain=True).host == host


@pytest.mark.parametrize("pin", ["xyz", "A" * 64, "a" * 63, "g" * 64, ""])
def test_a_fingerprint_is_checked_even_when_the_hop_is_not_encrypted(pin: str) -> None:
    with pytest.raises(ValueError, match="pin_sha256"):
        Origin("127.0.0.1", 8080, tls=False, pin_sha256=pin)


def test_a_list_of_fingerprints_is_checked_one_by_one() -> None:
    with pytest.raises(ValueError, match="pin_sha256"):
        Origin("127.0.0.1", 8443, pin_sha256=("a" * 64, "zz"))
    with pytest.raises(ValueError, match="pin_sha256"):
        Origin("127.0.0.1", 8443, pin_sha256=())
    assert Origin("127.0.0.1", 8443, pin_sha256=("a" * 64, "b" * 64)).pins == ("a" * 64, "b" * 64)


def test_the_hop_works_if_any_one_of_the_pinned_fingerprints_matches(tmp_path: Path) -> None:
    # A certificate is renewed by giving every relay the new fingerprint beside the old one first,
    # so that the change does not stop the relays for the moment between the two.
    cert, key, pin = certificate(tmp_path)

    async def scenario(pins: tuple[str, ...]) -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin(tls=(cert, key)) as origin:
            relay = relay_for(origin.port, origin=Origin("127.0.0.1", origin.port, pin_sha256=pins))
            return await ask(relay), origin

    answer, origin = run(scenario(("0" * 64, pin)))
    assert answer.status == 200 and len(origin.seen) == 1
    answer, origin = run(scenario((pin, "0" * 64)))
    assert answer.status == 200
    answer, origin = run(scenario(("0" * 64, "1" * 64)))
    assert answer.status == 502 and origin.seen == []


# --- who is asking, for the limits ---------------------------------------------------------------


async def are_they_one_visitor(
    first: tuple[str, int],
    second: tuple[str, int],
    first_headers: Headers | None = None,
    second_headers: Headers | None = None,
    *,
    trust: bool = False,
) -> bool:
    """Whether the relay counts two requests as coming from one visitor, by whether a limit of one
    in flight for each visitor turns the second away while the first is still going."""
    async with FakeOrigin(lambda _s: Reply(stall=0.5, body=b"slow")) as origin:
        relay = relay_for(origin.port, max_per_client=1, trust_forwarded=trust)
        held = asyncio.create_task(ask(relay, client=first, headers=first_headers))
        await in_flight(relay)
        answer = await ask(relay, client=second, headers=second_headers)
        await held
        return answer.status == 429


def test_the_last_forwarded_address_the_proxy_wrote_is_the_one_used_even_on_a_second_line() -> None:
    proxy = ("127.0.0.1", 1)
    forged: Headers = [("x-forwarded-for", "192.0.2.66"), ("x-forwarded-for", "198.51.100.1")]
    real: Headers = [("x-forwarded-for", "198.51.100.1")]
    # The visitor's own first line must not decide who they are: the proxy's line, the last, does.
    assert run(are_they_one_visitor(proxy, proxy, forged, real, trust=True)) is True
    other: Headers = [("x-forwarded-for", "198.51.100.2")]
    assert run(are_they_one_visitor(proxy, proxy, forged, other, trust=True)) is False


def test_an_address_and_its_ipv4_mapped_ipv6_form_are_one_visitor() -> None:
    assert run(are_they_one_visitor(("198.51.100.7", 1), ("::ffff:198.51.100.7", 2))) is True


def test_ipv6_visitors_in_one_network_are_one_visitor_and_another_network_is_not() -> None:
    near = run(are_they_one_visitor(("2001:db8:1:2::1", 1), ("2001:db8:1:2::ffff", 2)))
    far = run(are_they_one_visitor(("2001:db8:1:2::1", 1), ("2001:db8:1:3::1", 2)))
    assert near is True and far is False
