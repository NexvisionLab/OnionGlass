# SPDX-License-Identifier: AGPL-3.0-only
"""Fetching through Tor: properties P4 (clean requests) and P5 (only onion destinations)."""

from __future__ import annotations

import asyncio
import hashlib
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from fake_tor import (
    FakeOnionServer,
    FakeTor,
    http_response,
    make_certificate,
    static_response,
)
from helpers import TOR_PROJECT
from onionglass.headers import upstream_request_headers
from onionglass.onion import OnionHost, OnionOrigin
from onionglass.upstream import (
    TorConfig,
    TorFetcher,
    UpstreamError,
    UpstreamRequest,
)

HTTP_ORIGIN = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
HTTPS_ORIGIN = OnionOrigin("https", OnionHost(TOR_PROJECT), 443)


def make_request(
    origin: OnionOrigin = HTTP_ORIGIN,
    *,
    method: str = "GET",
    target: str = "/page?x=1",
    key: str = "session-one",
    body: bytes = b"",
    cookie: str | None = None,
    content_type: str | None = None,
) -> UpstreamRequest:
    headers = upstream_request_headers(
        origin, method=method, cookie=cookie, content_type=content_type
    )
    return UpstreamRequest(
        origin=origin, method=method, target=target, headers=headers, isolation_key=key, body=body
    )


def config(tor: FakeTor, **overrides: object) -> TorConfig:
    values: dict[str, object] = {
        "socks_ports": (tor.port,),
        "connect_timeout": 2.0,
        "read_timeout": 2.0,
        "total_timeout": 4.0,
    }
    values.update(overrides)
    return TorConfig(**values)  # type: ignore[arg-type]


def run(coro: object) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def test_a_page_is_fetched_and_the_request_is_clean() -> None:
    async def scenario() -> None:
        page = http_response(
            b"<p>hello</p>",
            headers=(("Content-Type", "text/html"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")),
        )
        async with FakeOnionServer(static_response(page)) as onion, FakeTor(onion.port) as tor:
            response = await TorFetcher(config(tor)).fetch(make_request(cookie="sid=abc"))
            assert response.status == 200
            assert response.reason == "OK"
            assert response.body == b"<p>hello</p>"
            assert response.header("Content-Type") == "text/html"
            assert response.header_all("set-cookie") == ["a=1", "b=2"]
            assert response.header("missing") is None
            sent = onion.requests[0].decode("latin-1")
            assert sent.startswith("GET /page?x=1 HTTP/1.1\r\n")
            lines = {
                line.split(":", 1)[0].lower() for line in sent.split("\r\n")[1:] if ":" in line
            }
            assert lines == {
                "host",
                "user-agent",
                "accept",
                "accept-language",
                "accept-encoding",
                "cookie",
                "connection",
            }
            assert f"host: {TOR_PROJECT}.onion".lower() in sent.lower()
            assert "connection: close" in sent.lower()

    run(scenario())


def test_the_connection_uses_the_onion_name_the_right_port_and_a_per_session_credential() -> None:
    async def scenario() -> None:
        async with (
            FakeOnionServer(static_response(http_response(b"x"))) as onion,
            FakeTor(onion.port) as tor,
        ):
            fetcher = TorFetcher(config(tor))
            await fetcher.fetch(make_request(key="aaaaaaaa"))
            await fetcher.fetch(make_request(key="bbbbbbbb"))
            first, second = tor.seen
            assert first.address_type == 3  # the name is sent to Tor, never looked up locally
            assert first.host == f"{TOR_PROJECT}.onion"
            assert first.port == 80
            assert first.username == "og-aaaaaaaa"
            assert second.username == "og-bbbbbbbb"

    run(scenario())


def test_chunked_responses_head_requests_and_informational_responses() -> None:
    async def scenario() -> None:
        chunked = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        )
        async with FakeOnionServer(static_response(chunked)) as onion, FakeTor(onion.port) as tor:
            assert (await TorFetcher(config(tor)).fetch(make_request())).body == b"hello world"
        informational = b"HTTP/1.1 100 Continue\r\n\r\n" + http_response(b"done")
        async with (
            FakeOnionServer(static_response(informational)) as onion,
            FakeTor(onion.port) as tor,
        ):
            assert (await TorFetcher(config(tor)).fetch(make_request())).body == b"done"
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\n"
        async with FakeOnionServer(static_response(head)) as onion, FakeTor(onion.port) as tor:
            response = await TorFetcher(config(tor)).fetch(make_request(method="HEAD"))
            assert response.body == b""
            assert response.header("content-length") == "500"

    run(scenario())


def test_a_response_ended_by_closing_the_connection_is_read_in_full() -> None:
    async def scenario() -> None:
        old_style = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nbody until close"
        async with FakeOnionServer(static_response(old_style)) as onion, FakeTor(onion.port) as tor:
            assert (await TorFetcher(config(tor)).fetch(make_request())).body == b"body until close"

    run(scenario())


def test_post_sends_the_body_and_origin() -> None:
    async def scenario() -> None:
        async with (
            FakeOnionServer(static_response(http_response(b"ok"))) as onion,
            FakeTor(onion.port) as tor,
        ):
            request = make_request(
                method="POST",
                body=b"a=1&b=2",
                content_type="application/x-www-form-urlencoded",
            )
            assert (await TorFetcher(config(tor)).fetch(request)).status == 200
            sent = onion.requests[0]
            assert sent.startswith(b"POST /page?x=1 HTTP/1.1\r\n")
            assert sent.endswith(b"\r\n\r\na=1&b=2")
            lowered = sent.lower()
            assert b"content-length: 7" in lowered
            assert b"content-type: application/x-www-form-urlencoded" in lowered
            assert f"origin: http://{TOR_PROJECT}.onion".encode() in lowered

    run(scenario())


def test_redirects_are_returned_not_followed() -> None:
    async def scenario() -> None:
        redirect = http_response(
            status="302 Found", headers=(("Location", "http://evil.example/x"),)
        )
        async with FakeOnionServer(static_response(redirect)) as onion, FakeTor(onion.port) as tor:
            response = await TorFetcher(config(tor)).fetch(make_request())
            assert response.status == 302
            assert response.header("location") == "http://evil.example/x"
            assert len(tor.seen) == 1
            assert len(onion.requests) == 1

    run(scenario())


@pytest.mark.parametrize(
    ("code", "kind"),
    [
        (0xF0, "descriptor_not_found"),
        (0xF1, "descriptor_invalid"),
        (0xF2, "introduction_failed"),
        (0xF3, "rendezvous_failed"),
        (0xF4, "auth_required"),
        (0xF5, "auth_wrong"),
        (0xF6, "invalid_address"),
        (0xF7, "introduction_timeout"),
        (0x05, "connection_refused"),
    ],
)
def test_tors_failure_reasons_reach_the_caller(code: int, kind: str) -> None:
    async def scenario() -> None:
        async with FakeTor(reply=code) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor)).fetch(make_request())
            assert info.value.kind == kind

    run(scenario())


def test_tor_not_running() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]

    async def scenario() -> None:
        fetcher = TorFetcher(TorConfig(socks_ports=(free_port,), proxy_connect_timeout=1.0))
        with pytest.raises(UpstreamError) as info:
            await fetcher.fetch(make_request())
        assert info.value.kind == "proxy_unreachable"

    run(scenario())


def test_timeouts() -> None:
    async def scenario() -> None:
        async def stall(_request: bytes, writer: asyncio.StreamWriter) -> None:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
            await writer.drain()
            await asyncio.sleep(3600)

        async with FakeOnionServer(stall) as onion, FakeTor(onion.port) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor, read_timeout=0.3)).fetch(make_request())
            assert info.value.kind == "timeout"
        async with FakeTor(stall_connect=True) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor, connect_timeout=0.3)).fetch(make_request())
            assert info.value.kind == "connect_timeout"
        async with FakeOnionServer(stall) as onion, FakeTor(onion.port) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor, read_timeout=30.0, total_timeout=0.4)).fetch(
                    make_request()
                )
            assert info.value.kind == "timeout"

    run(scenario())


def test_the_body_size_limit() -> None:
    async def scenario() -> None:
        big = http_response(b"a" * 5000)
        async with FakeOnionServer(static_response(big)) as onion, FakeTor(onion.port) as tor:
            fetcher = TorFetcher(config(tor, max_body_bytes=1000))
            with pytest.raises(UpstreamError) as info:
                await fetcher.fetch(make_request())
            assert info.value.kind == "too_large"
            # A per-request limit overrides the default.
            assert len((await fetcher.fetch(make_request(), max_body_bytes=10_000)).body) == 5000

    run(scenario())


def test_a_body_without_a_length_is_limited_too() -> None:
    async def scenario() -> None:
        async def endless(_request: bytes, writer: asyncio.StreamWriter) -> None:
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            for _ in range(1000):
                writer.write(b"a" * 1024)
                await writer.drain()

        async with FakeOnionServer(endless) as onion, FakeTor(onion.port) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor, max_body_bytes=10_000)).fetch(make_request())
            assert info.value.kind == "too_large"

    run(scenario())


@pytest.mark.parametrize(
    "raw",
    [
        b"garbage that is not http\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n" + b"X-Big: " + b"a" * 200_000 + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
        b"HTTP/1.1 999999 Nope\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad Header Line\r\n\r\n",
    ],
)
def test_malformed_responses_are_protocol_errors(raw: bytes) -> None:
    async def scenario() -> None:
        async with FakeOnionServer(static_response(raw)) as onion, FakeTor(onion.port) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor)).fetch(make_request())
            assert info.value.kind == "protocol_error"

    run(scenario())


def test_a_connection_cut_before_the_response_is_complete() -> None:
    async def scenario() -> None:
        cut = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"
        async with FakeOnionServer(static_response(cut)) as onion, FakeTor(onion.port) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor)).fetch(make_request())
            assert info.value.kind in ("connection_closed", "protocol_error")
        async with FakeOnionServer(static_response()) as onion, FakeTor(onion.port) as tor:
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor)).fetch(make_request())
            assert info.value.kind in ("connection_closed", "protocol_error")

    run(scenario())


# --- what the fetcher refuses to send (P4, P5) ----------------------------------------------------


def test_requests_that_are_not_clean_are_refused_before_any_connection() -> None:
    async def scenario() -> None:
        async with FakeTor() as tor:
            fetcher = TorFetcher(config(tor))
            good = make_request()
            bad_requests = [
                replace(good, method="DELETE"),
                replace(good, method="get"),
                replace(good, target="no-leading-slash"),
                replace(good, target="/has space"),
                replace(good, target="/line\r\nbreak"),
                replace(good, target="/" + "a" * 9000),
                replace(good, target="/caf" + chr(0xE9)),
                replace(good, isolation_key=""),
                replace(good, isolation_key="has space"),
                replace(good, isolation_key="a:b"),
                replace(good, isolation_key="x" * 201),
                replace(good, body=b"data"),  # a body on a GET
                replace(good, headers={**good.headers, "X-Forwarded-For": "203.0.113.9"}),
                replace(good, headers={**good.headers, "Via": "1.1 proxy"}),
                replace(good, headers={**good.headers, "Authorization": "Basic abc"}),
                replace(good, headers={**good.headers, "Cookie": "a=b\r\nX: y"}),
                replace(good, headers={**good.headers, "Host": "evil.example"}),
                replace(good, headers={k: v for k, v in good.headers.items() if k != "Host"}),
            ]
            for request in bad_requests:
                with pytest.raises(UpstreamError) as info:
                    await fetcher.fetch(request)
                assert info.value.kind == "bad_request", request
            assert tor.seen == []  # nothing reached Tor

    run(scenario())


def test_an_oversized_request_body_is_refused() -> None:
    async def scenario() -> None:
        async with FakeTor() as tor:
            request = make_request(
                method="POST", body=b"a" * 100, content_type="application/x-www-form-urlencoded"
            )
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor, max_request_body_bytes=50)).fetch(request)
            assert info.value.kind == "too_large"
            assert tor.seen == []

    run(scenario())


def test_a_session_always_uses_the_same_tor_port_and_sessions_spread_out() -> None:
    async def scenario() -> None:
        async with (
            FakeOnionServer(static_response(http_response(b"x"))) as onion,
            FakeTor(onion.port) as tor_a,
            FakeTor(onion.port) as tor_b,
        ):
            fetcher = TorFetcher(TorConfig(socks_ports=(tor_a.port, tor_b.port), total_timeout=4))
            for _ in range(3):
                await fetcher.fetch(make_request(key="steady-session"))
            counts = (len(tor_a.seen), len(tor_b.seen))
            assert sorted(counts) == [0, 3]  # one session never hops between Tor processes
            for index in range(40):
                await fetcher.fetch(make_request(key=f"session-{index:04d}"))
            assert len(tor_a.seen) > 3 and len(tor_b.seen) > 3  # and sessions use both

    run(scenario())


def test_the_pool_needs_at_least_one_port() -> None:
    with pytest.raises(ValueError, match="SOCKS port"):
        TorConfig(socks_ports=())


# --- https onions ------------------------------------------------------------------------------------


def test_https_onions_are_fetched_without_verifying_the_certificate_which_is_recorded(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        context, der = make_certificate(tmp_path)
        page = http_response(b"secure page")
        async with (
            FakeOnionServer(static_response(page), ssl_context=context) as onion,
            FakeTor(onion.port) as tor,
        ):
            response = await TorFetcher(config(tor)).fetch(make_request(HTTPS_ORIGIN))
            assert response.body == b"secure page"
            assert response.tls is not None
            assert response.tls.fingerprint_sha256 == hashlib.sha256(der).hexdigest()
            assert response.tls.self_signed is True
            assert "test.example" in response.tls.subject
            assert response.tls.protocol.startswith("TLSv1.")
            assert tor.seen[0].port == 443

    run(scenario())


def test_plain_http_responses_have_no_tls_information() -> None:
    async def scenario() -> None:
        async with (
            FakeOnionServer(static_response(http_response(b"x"))) as onion,
            FakeTor(onion.port) as tor,
        ):
            assert (await TorFetcher(config(tor)).fetch(make_request())).tls is None

    run(scenario())


def test_an_https_onion_that_speaks_plain_http_is_a_tls_failure() -> None:
    async def scenario() -> None:
        async with (
            FakeOnionServer(static_response(http_response(b"x"))) as onion,
            FakeTor(onion.port) as tor,
        ):
            with pytest.raises(UpstreamError) as info:
                await TorFetcher(config(tor)).fetch(make_request(HTTPS_ORIGIN))
            assert info.value.kind in ("tls_failed", "connection_closed", "timeout")

    run(scenario())
