# SPDX-License-Identifier: AGPL-3.0-only
"""What a stranger who reaches the gateway directly can tell it apart by. In cover mode, and when
relays are required, an odd method or an odd kind of address must get the same missing page as any
other request, and never the web framework's own answer, which would say what this is."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from onionglass.cover import NOT_FOUND_PAGE
from test_cover import Covered
from test_relay_gateway import HOST, Relayed

METHODS = ["TRACE", "FOO", "PROPFIND", "LOCK", "PURGE"]
TARGETS = ["http://example.com/x", "*", "x", "http://[::1]/", "/..", "//host/path"]


def gateways() -> list[tuple[str, Any, str]]:
    return [
        ("cover mode", Covered().gateway.app, "gw.example"),
        ("relays required", Relayed(require=True).gateway.app, HOST),
    ]


async def raw(
    app: Any, method: str, path: str, host: str
) -> tuple[int, bytes, list[tuple[str, str]]]:
    """One request straight into the application, whatever its method and target look like."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [(b"host", host.encode("ascii"))],
        "server": ("gw.example", 443),
        "client": ("203.0.113.9", 4444),
    }
    status = 0
    headers: list[tuple[str, str]] = []
    body = bytearray()
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
            headers.extend((k.decode(), v.decode()) for k, v in message["headers"])
        else:
            body.extend(message.get("body", b""))

    await app(scope, receive, send)
    return status, bytes(body), headers


def comparable(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return sorted((k.lower(), v) for k, v in headers if k.lower() != "content-length")


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("which", [0, 1], ids=["cover mode", "relays required"])
def test_a_method_nobody_uses_gets_the_missing_page_and_not_the_frameworks_own_answer(
    method: str, which: int
) -> None:
    _, app, host = gateways()[which]

    async def scenario() -> tuple[Any, Any]:
        return await raw(app, method, "/", host), await raw(app, "GET", "/nowhere", host)

    odd, ordinary = asyncio.run(scenario())
    assert odd[0] == 404 and odd[1] == NOT_FOUND_PAGE
    assert comparable(odd[2]) == comparable(ordinary[2])
    assert "allow" not in {k.lower() for k, _ in odd[2]}


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("which", [0, 1], ids=["cover mode", "relays required"])
def test_an_address_that_is_not_a_path_gets_the_missing_page_and_not_the_frameworks_own_answer(
    target: str, which: int
) -> None:
    _, app, host = gateways()[which]

    async def scenario() -> tuple[Any, Any]:
        return await raw(app, "GET", target, host), await raw(app, "GET", "/nowhere", host)

    odd, ordinary = asyncio.run(scenario())
    assert odd[0] == 404 and odd[1] == NOT_FOUND_PAGE
    assert comparable(odd[2]) == comparable(ordinary[2])


def test_without_cover_mode_the_frameworks_answers_are_left_alone() -> None:
    # Cover mode is what asks for this. Personal mode and plain team mode keep the usual answers.
    from onionglass.gateway import Gateway  # noqa: PLC0415
    from onionglass.settings import Settings  # noqa: PLC0415
    from test_gateway import FakeFetcher  # noqa: PLC0415

    app = Gateway(Settings(base_domain="localhost", open_mode=True), fetcher=FakeFetcher()).app
    status, _, _ = asyncio.run(raw(app, "TRACE", "/", "localhost"))
    assert status == 405
