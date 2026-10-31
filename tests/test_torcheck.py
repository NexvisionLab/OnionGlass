# SPDX-License-Identifier: AGPL-3.0-only
"""Checking that Tor is there, is Tor, and can reach onion sites, with a plain answer for each way
it can be wrong. The probe asks for a made-up onion address, so it never leaves through an exit."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from typing import Any

import pytest

from fake_tor import FakeTor
from onionglass import cli
from onionglass.onion import parse_onion_url
from onionglass.torcheck import CHECK_USER, TorStatus, check_tor, check_tor_quickly
from test_config import Layout


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def deep(tor: FakeTor, **options: Any) -> TorStatus:
    return await check_tor("127.0.0.1", tor.port, wait=options.pop("wait", 5.0), **options)


# --- every way Tor can answer --------------------------------------------------------------------


@pytest.mark.parametrize("reply", [0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF7])
def test_a_tor_that_looks_the_onion_up_is_working(reply: int) -> None:
    async def scenario() -> TorStatus:
        async with FakeTor(reply=reply) as tor:
            return await deep(tor)

    status = asyncio.run(scenario())
    assert status.ok and status.state == "working"
    assert "127.0.0.1" in status.message


def test_a_tor_without_detailed_errors_is_working_and_says_what_is_missing() -> None:
    async def scenario() -> TorStatus:
        async with FakeTor(reply=0x04) as tor:
            return await deep(tor)

    status = asyncio.run(scenario())
    assert status.ok and status.state == "working"
    assert "detailed" in status.message


@pytest.mark.parametrize("reply", [0x01, 0x03, 0x06])
def test_a_tor_that_cannot_reach_the_network_yet_is_starting(reply: int) -> None:
    async def scenario() -> TorStatus:
        async with FakeTor(reply=reply) as tor:
            return await deep(tor)

    status = asyncio.run(scenario())
    assert not status.ok and status.state == "starting"
    assert "wait" in status.message


def test_a_tor_that_never_finishes_the_lookup_is_slow() -> None:
    async def scenario() -> TorStatus:
        async with FakeTor(stall_connect=True) as tor:
            return await deep(tor, wait=0.3)

    status = asyncio.run(scenario())
    assert not status.ok and status.state == "slow"


def test_a_port_with_nothing_on_it_is_not_listening() -> None:
    port = free_port()
    status = asyncio.run(check_tor("127.0.0.1", port, wait=2.0))
    assert not status.ok and status.state == "not_listening"
    assert str(port) in status.message and "--tor-port" in status.message


def test_something_that_does_not_speak_socks_is_not_tor() -> None:
    async def scenario() -> TorStatus:
        async def web(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(16)
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(web, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await check_tor("127.0.0.1", port, wait=3.0)
        finally:
            server.close()

    status = asyncio.run(scenario())
    assert not status.ok and status.state == "not_socks"
    assert "SOCKS" in status.message


@pytest.mark.parametrize(
    ("options", "state"),
    [
        ({"close_after_greeting": True}, "not_socks"),
        ({"method_reply": 0xFF}, "no_login"),
        ({"auth_status": 1}, "no_login"),
    ],
)
def test_a_socks_port_that_will_not_take_the_login_or_hangs_up_is_reported(
    options: dict[str, Any], state: str
) -> None:
    async def scenario() -> TorStatus:
        async with FakeTor(**options) as tor:
            return await deep(tor)

    status = asyncio.run(scenario())
    assert not status.ok and status.state == state


def test_an_odd_answer_is_reported_with_its_code() -> None:
    async def scenario() -> TorStatus:
        async with FakeTor(reply=0x02) as tor:
            return await deep(tor)

    status = asyncio.run(scenario())
    assert not status.ok and status.state == "refused" and "not_allowed" in status.message


# --- what the probe asks for ---------------------------------------------------------------------


def test_the_probe_asks_only_for_a_made_up_onion_address_and_a_fixed_login() -> None:
    async def scenario() -> tuple[list[str], list[str]]:
        async with FakeTor(reply=0xF0) as tor:
            await deep(tor)
            await deep(tor)
            lookups = [s for s in tor.seen if s.host]  # the quick check asks for nothing
            return [s.host for s in lookups], [s.username for s in lookups]

    hosts, users = asyncio.run(scenario())
    assert len(hosts) == 2 and hosts[0] != hosts[1]  # a new address every time
    for host in hosts:
        assert host.endswith(".onion") and host.count(".") == 1
        parse_onion_url(f"http://{host}/")  # it is a well-formed address, checksum and all
    assert users == [CHECK_USER, CHECK_USER]


# --- the quick check used at start-up ------------------------------------------------------------


def test_the_quick_check_passes_for_a_socks_port_without_looking_anything_up() -> None:
    async def scenario() -> tuple[TorStatus, int]:
        async with FakeTor(reply=0xF0) as tor:
            status = await check_tor_quickly("127.0.0.1", tor.port)
            return status, sum(1 for s in tor.seen if s.host)

    status, lookups = asyncio.run(scenario())
    assert status.ok and lookups == 0


def test_the_quick_check_reports_a_closed_port() -> None:
    status = asyncio.run(check_tor_quickly("127.0.0.1", free_port()))
    assert not status.ok and status.state == "not_listening"


def test_the_quick_check_does_not_hang_on_a_server_that_says_nothing() -> None:
    async def scenario() -> TorStatus:
        async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await asyncio.sleep(30)

        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        try:
            return await check_tor_quickly("127.0.0.1", server.sockets[0].getsockname()[1], 0.3)
        finally:
            server.close()

    status = asyncio.run(scenario())
    assert not status.ok and status.state == "not_socks"


# --- the command ---------------------------------------------------------------------------------


def test_the_command_succeeds_when_every_tor_works(capsys: pytest.CaptureFixture[str]) -> None:
    async def scenario() -> int:
        async with FakeTor(reply=0xF0) as first, FakeTor(reply=0xF0) as second:
            argv = ["check-tor", "--tor-port", str(first.port), "--tor-port", str(second.port)]
            return await asyncio.to_thread(cli.main, argv)

    assert asyncio.run(scenario()) == 0
    shown = capsys.readouterr().out
    assert shown.count("ok") == 2 and "FAIL" not in shown


def test_the_command_fails_and_names_the_port_that_is_wrong(
    capsys: pytest.CaptureFixture[str],
) -> None:
    closed = free_port()

    async def scenario() -> int:
        async with FakeTor(reply=0xF0) as good:
            argv = ["check-tor", "--tor-port", str(good.port), "--tor-port", str(closed)]
            return await asyncio.to_thread(cli.main, argv)

    assert asyncio.run(scenario()) == 1
    shown = capsys.readouterr().out
    assert "FAIL" in shown and str(closed) in shown and "ok" in shown


def test_the_command_reads_the_tor_ports_from_a_config_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout = Layout(tmp_path)
    assert cli.main(["check-tor", "--config", str(layout.config), "--wait", "2"]) == 1
    shown = capsys.readouterr().out
    assert "9050" in shown and "9052" in shown  # the two ports in the example file


@pytest.mark.parametrize("wait", ["0", "-3", "1000", "soon"])
def test_a_bad_wait_is_refused(wait: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["check-tor", "--wait", wait])
    assert caught.value.code == 2
    assert "wait" in capsys.readouterr().err


def test_the_command_does_not_print_the_made_up_address(
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def scenario() -> int:
        async with FakeTor(reply=0xF0) as tor:
            return await asyncio.to_thread(cli.main, ["check-tor", "--tor-port", str(tor.port)])

    asyncio.run(scenario())
    assert ".onion" not in capsys.readouterr().out


# --- personal mode warns at start-up -------------------------------------------------------------


def started(monkeypatch: pytest.MonkeyPatch, tor_port: int) -> int:
    monkeypatch.setattr("onionglass.cli.uvicorn.run", lambda *args, **kwargs: None)
    return cli.main(["--port", str(free_port()), "--tor-port", str(tor_port)])


def test_personal_mode_warns_when_tor_is_not_there_and_still_starts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    port = free_port()
    assert started(monkeypatch, port) == 0
    warned = capsys.readouterr().err
    assert "warning" in warned and str(port) in warned and "check-tor" in warned


def test_personal_mode_says_nothing_when_tor_is_there(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> int:
        async with FakeTor(reply=0xF0) as tor:
            return await asyncio.to_thread(started, monkeypatch, tor.port)

    assert asyncio.run(scenario()) == 0
    assert "warning" not in capsys.readouterr().err


# --- the guides ----------------------------------------------------------------------------------


def test_the_guides_tell_people_about_the_command() -> None:
    root = Path(__file__).resolve().parent.parent
    for page in (root / "README.md", root / "docs" / "running.md"):
        text = page.read_text(encoding="utf-8")
        assert "onionglass check-tor" in text, page.name
    running = (root / "docs" / "running.md").read_text(encoding="utf-8")
    for state in ("not_listening", "not_socks", "no_login", "starting", "slow", "refused"):
        assert f"`{state}`" in running
