# SPDX-License-Identifier: AGPL-3.0-only
"""The SOCKS5 client: isolation credentials, remote name lookup and Tor's extended errors."""

from __future__ import annotations

import asyncio
import socket

import pytest

from fake_tor import FakeTor
from onionglass.socks import REPLY_KINDS, SocksError, socks5_connect

TARGET = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"


async def connect(tor: FakeTor, **overrides: object) -> None:
    args: dict[str, object] = {
        "proxy_port": tor.port,
        "username": "og-session-1",
        "connect_timeout": 2.0,
    }
    args.update(overrides)
    _reader, writer = await socks5_connect(TARGET, 80, **args)  # type: ignore[arg-type]
    writer.close()


def test_the_target_is_sent_as_a_name_and_the_credentials_are_sent_for_isolation() -> None:
    async def scenario() -> None:
        async with FakeTor() as tor:
            await connect(tor)
            seen = tor.seen[0]
            assert seen.methods == b"\x02"  # only user name and password is offered
            assert seen.username == "og-session-1"
            assert seen.password == "x"
            assert seen.address_type == 3  # a domain name, so Tor does the lookup
            assert seen.host == TARGET
            assert seen.port == 80

    asyncio.run(scenario())


def test_different_sessions_present_different_credentials() -> None:
    async def scenario() -> None:
        async with FakeTor() as tor:
            await connect(tor, username="og-aaaa")
            await connect(tor, username="og-bbbb")
            assert [s.username for s in tor.seen] == ["og-aaaa", "og-bbbb"]

    asyncio.run(scenario())


@pytest.mark.parametrize("bound", [1, 3, 4])
def test_every_kind_of_bound_address_in_the_reply_is_understood(bound: int) -> None:
    async def scenario() -> None:
        async with FakeTor(bound_address_type=bound) as tor:
            await connect(tor)

    asyncio.run(scenario())


@pytest.mark.parametrize(("code", "kind"), sorted(REPLY_KINDS.items()))
def test_every_failure_code_maps_to_a_named_kind(code: int, kind: str) -> None:
    async def scenario() -> None:
        async with FakeTor(reply=code) as tor:
            with pytest.raises(SocksError) as info:
                await connect(tor)
            assert info.value.kind == kind
            assert info.value.code == code

    asyncio.run(scenario())


def test_tors_extended_errors_have_readable_names() -> None:
    assert REPLY_KINDS[0xF0] == "descriptor_not_found"
    assert REPLY_KINDS[0xF2] == "introduction_failed"
    assert REPLY_KINDS[0xF3] == "rendezvous_failed"
    assert REPLY_KINDS[0xF4] == "auth_required"
    assert REPLY_KINDS[0xF5] == "auth_wrong"
    assert REPLY_KINDS[0xF7] == "introduction_timeout"


def test_an_unknown_failure_code_is_still_a_failure() -> None:
    async def scenario() -> None:
        async with FakeTor(reply=0x99) as tor:
            with pytest.raises(SocksError) as info:
                await connect(tor)
            assert info.value.kind == "unknown_failure"
            assert info.value.code == 0x99

    asyncio.run(scenario())


def test_nothing_listening_on_the_proxy_port() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]

    async def scenario() -> None:
        with pytest.raises(SocksError) as info:
            await socks5_connect(
                TARGET, 80, proxy_port=free_port, username="og-x", proxy_connect_timeout=1.0
            )
        assert info.value.kind == "proxy_unreachable"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("options", "kind"),
    [
        ({"method_reply": 0xFF}, "proxy_refused_auth_method"),
        ({"method_reply": 0x00}, "proxy_refused_auth_method"),
        ({"auth_status": 1}, "proxy_rejected_credentials"),
        ({"close_after_greeting": True}, "proxy_closed"),
        ({"close_after_auth": True}, "proxy_closed"),
    ],
)
def test_a_misbehaving_proxy_is_reported(options: dict[str, object], kind: str) -> None:
    async def scenario() -> None:
        async with FakeTor(**options) as tor:  # type: ignore[arg-type]
            with pytest.raises(SocksError) as info:
                await connect(tor)
            assert info.value.kind == kind

    asyncio.run(scenario())


def test_a_proxy_that_never_answers_times_out() -> None:
    async def scenario() -> None:
        async with FakeTor(stall_connect=True) as tor:
            with pytest.raises(SocksError) as info:
                await connect(tor, connect_timeout=0.3)
            assert info.value.kind == "connect_timeout"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "bad",
    [
        {"username": ""},
        {"username": "x" * 256},
        {"username": "caf" + chr(0xE9)},
        {"password": ""},
    ],
)
def test_bad_credentials_are_refused_before_connecting(bad: dict[str, str]) -> None:
    async def scenario() -> None:
        with pytest.raises(ValueError, match="1 to 255"):
            await socks5_connect(TARGET, 80, **{"username": "og-x", **bad})  # type: ignore[arg-type]

    asyncio.run(scenario())


def test_bad_targets_are_refused_before_connecting() -> None:
    async def scenario() -> None:
        for host, port in (
            ("", 80),
            ("a" * 256, 80),
            ("caf" + chr(0xE9) + ".onion", 80),
            (TARGET, 0),
            (TARGET, 70000),
        ):
            with pytest.raises(ValueError, match="target"):
                await socks5_connect(host, port, username="og-x")

    asyncio.run(scenario())
