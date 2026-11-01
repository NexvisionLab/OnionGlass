# SPDX-License-Identifier: AGPL-3.0-only
"""The whole chain with nothing faked in the middle: a visitor, a relay, and the real gateway
served by a real web server. A visitor who goes round the relay sees only the cover page."""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
import uvicorn

from onionglass.cover import DEFAULT_PAGE, NOT_FOUND_PAGE
from onionglass.relay import Origin, Relay, RelaySettings, probe
from onionglass.relayauth import RelaySigner
from test_relay import Answer, ask
from test_relay_gateway import HOST, Relayed


async def visit(relay: Relay, **request: Any) -> Answer:
    """A visitor asking this chain's domain, which is not the default of the other tests."""
    request.setdefault("host", HOST)
    return await ask(relay, **request)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class Chain:
    """The gateway on a real port and a relay in front of it."""

    def __init__(self, *, require: bool = True, cover: bool = True) -> None:
        self.env = Relayed(require=require, cover=cover)
        self.port = free_port()
        config = uvicorn.Config(
            self.env.gateway.app,
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
            access_log=False,
            server_header=False,
            proxy_headers=False,
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.relay = Relay(
            RelaySettings(
                domains=(HOST,),
                origin=Origin("127.0.0.1", self.port, tls=False),
                signer=RelaySigner("r1", self.env.relay_key),
            )
        )

    def __enter__(self) -> Chain:
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            assert time.monotonic() < deadline, "the gateway did not start"
            time.sleep(0.02)
        return self

    def __exit__(self, *_: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)

    async def direct(self, target: str, host: str = HOST) -> tuple[int, bytes]:
        """A visitor who goes straight to the gateway's own address."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(f"GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = await reader.read()
        writer.close()
        head, _, body = data.partition(b"\r\n\r\n")
        return int(head.split(b" ")[1]), body


@pytest.fixture
def chain() -> Iterator[Chain]:
    with Chain() as running:
        yield running


def test_through_the_relay_a_visitor_gets_the_cover_page(chain: Chain) -> None:
    answer = asyncio.run(visit(chain.relay, host=HOST))
    assert answer.status == 200 and answer.body == DEFAULT_PAGE


def test_around_the_relay_a_visitor_gets_the_cover_page_and_nothing_more(chain: Chain) -> None:
    async def scenario() -> list[tuple[int, bytes]]:
        return [
            await chain.direct(t) for t in ("/", "/abuse", f"/enter?t={chain.env.ticket()}", "/x")
        ]

    root, abuse, enter, other = asyncio.run(scenario())
    assert root == (200, DEFAULT_PAGE)
    assert abuse == enter == other == (404, NOT_FOUND_PAGE)


def test_a_sign_in_link_works_through_the_relay_and_the_visitor_is_then_served(
    chain: Chain,
) -> None:
    async def scenario() -> tuple[Answer, Answer]:
        first = await visit(chain.relay, target=f"/enter?t={chain.env.ticket()}")
        cookie = first.all("set-cookie")[0].split(";")[0]
        return first, await visit(chain.relay, target="/abuse", headers=[("cookie", cookie)])

    first, abuse = asyncio.run(scenario())
    assert first.status == 303 and first.all("location")
    assert abuse.status == 200 and b"abuse@example.org" in abuse.body


def test_the_signed_in_cookie_does_not_help_a_visitor_who_goes_around_the_relay(
    chain: Chain,
) -> None:
    async def scenario() -> tuple[int, bytes]:
        first = await visit(chain.relay, target=f"/enter?t={chain.env.ticket()}")
        assert first.status == 303
        return await chain.direct("/abuse")

    assert asyncio.run(scenario()) == (404, NOT_FOUND_PAGE)


def test_the_relay_check_answers_only_through_a_relay_the_gateway_knows(chain: Chain) -> None:
    async def scenario() -> tuple[tuple[int, bytes], tuple[int, bytes]]:
        return await probe(chain.relay, HOST, "/_og/relay-check"), await chain.direct(
            "/_og/relay-check"
        )

    through, around = asyncio.run(scenario())
    assert through == (200, b"ok r1\n")
    assert around == (404, NOT_FOUND_PAGE)


@pytest.mark.parametrize("path", ["/_og/relay-check", "/_og/relay%2Dcheck", "/_og/relay-check/"])
def test_a_visitor_cannot_use_the_relay_check_and_gets_what_any_missing_page_gives(
    chain: Chain, path: str
) -> None:
    async def scenario() -> tuple[Answer, Answer]:
        return await visit(chain.relay, target=path), await visit(chain.relay, target="/nowhere")

    asked, missing = asyncio.run(scenario())
    assert asked.status == 404 and asked.body == NOT_FOUND_PAGE
    assert (asked.status, asked.body, sorted(asked.headers)) == (
        missing.status,
        missing.body,
        sorted(missing.headers),
    )


def test_a_relay_whose_key_was_taken_out_is_cut_off_and_the_visitor_sees_the_cover_page(
    chain: Chain,
) -> None:
    async def scenario() -> tuple[tuple[int, bytes], tuple[int, bytes]]:
        before = await probe(chain.relay, HOST, "/_og/relay-check")
        chain.env.relay_keys.remove("r1")
        return before, await probe(chain.relay, HOST, "/_og/relay-check")

    before, after = asyncio.run(scenario())
    assert before[0] == 200
    assert after == (404, NOT_FOUND_PAGE)


def test_the_gateway_only_ever_sees_the_relay_as_the_peer_and_never_the_visitor(
    chain: Chain, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    original = chain.env.gateway._relay_gate

    async def watch(request: Any) -> Any:
        seen.append(request.client.host if request.client else "")
        return await original(request)

    monkeypatch.setattr(chain.env.gateway, "_relay_gate", watch)
    asyncio.run(
        visit(
            chain.relay, headers=[("x-forwarded-for", "198.51.100.7")], client=("198.51.100.7", 1)
        )
    )
    assert seen == ["127.0.0.1"]
