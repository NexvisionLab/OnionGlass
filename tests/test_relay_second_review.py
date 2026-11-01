# SPDX-License-Identifier: AGPL-3.0-only
"""What the second review found, each as a test: a slow upload that is still going, a gateway that
answers early and closes, a gateway that stops reading, a visitor who leaves while the relay waits,
and the noise a cut-off answer makes. Several of these only show up against the real gateway."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from onionglass import cli
from onionglass.cover import NOT_FOUND_PAGE
from onionglass.relay import ConnectionAbort
from onionglass.relaycli import QuietAbort
from relay_origin import FakeOrigin, Reply
from test_relay import (
    DOMAIN,
    Answer,
    ask,
    cut_off,
    relay_for,
    run,
    through,
)
from test_relay_cli import relay_file
from test_relay_end_to_end import Chain, visit


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# --- an upload that is slow but still going ------------------------------------------------------


def test_an_upload_that_takes_longer_than_the_idle_time_is_not_cut_off_while_it_keeps_coming() -> (
    None
):
    # Each piece arrives well inside the idle time. The gateway says nothing until it has them
    # all, so a clock on the gateway's silence would end this request at the idle time.
    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port, idle_timeout=1.0, max_request_seconds=30)
            answer = await ask(
                relay,
                "POST",
                "/open",
                headers=[("content-length", "3")],
                body=[b"x"] * 3,
                drip=0.6,
            )
            assert relay.busy() == (0, 0)
            return answer, origin

    answer, origin = run(scenario())
    assert answer.status == 200 and answer.finished
    assert [seen.body for seen in origin.seen] == [b"xxx"]


def test_a_gateway_that_says_nothing_after_the_whole_upload_is_still_a_bad_gateway_after_the_idle_time() -> (
    None
):
    async def scenario() -> Answer:
        async with FakeOrigin(lambda _s: Reply(stall=5)) as origin:
            relay = relay_for(origin.port, idle_timeout=0.5)
            return await ask(
                relay, "POST", "/open", headers=[("content-length", "2")], body=[b"hi"]
            )

    assert run(scenario()).status == 502


# --- a visitor who leaves while the relay waits for the gateway ---------------------------------


def test_a_visitor_who_leaves_while_the_relay_waits_for_the_gateway_frees_the_slot() -> None:
    async def scenario() -> tuple[Answer, float]:
        async with FakeOrigin(lambda _s: Reply(stall=5, body=b"late")) as origin:
            relay = relay_for(origin.port)
            started = time.monotonic()
            answer = await ask(relay, leave_after=0.3)
            took = time.monotonic() - started
            assert relay.busy() == (0, 0)
            return answer, took

    answer, took = run(scenario())
    assert took < 3 and answer.status == 0  # nobody was left to answer


# --- a gateway that stops reading ----------------------------------------------------------------


def test_a_gateway_that_stops_reading_an_upload_does_not_keep_a_place() -> None:
    async def scenario() -> tuple[Answer, float]:
        async def never_reads(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await asyncio.sleep(60)

        server = await asyncio.start_server(never_reads, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            # Twelve megabytes, more than the sockets between here and a gateway that never reads
            # can hold, so that the relay is left with data it cannot hand over.
            relay = relay_for(port, idle_timeout=1.0, max_request_body=50_000_000)
            started = time.monotonic()
            answer = await ask(
                relay,
                "POST",
                "/open",
                headers=[("content-length", "12000000")],
                body=[b"x" * 100_000 for _ in range(120)],
            )
            took = time.monotonic() - started
            assert relay.busy() == (0, 0)
            return answer, took
        finally:
            server.close()

    answer, took = run(scenario())
    assert answer.status in (408, 502) and took < 12


# --- what is written down ------------------------------------------------------------------------


def lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name.startswith("onionglass")]


def test_a_visitor_who_does_not_take_the_answer_is_not_blamed_on_the_gateway(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    reply = Reply(chunks=[b"x" * 1000] * 5, chunk_delay=0.01)
    answer, _ = run(
        through(lambda _s: reply, relay_options={"idle_timeout": 0.3}, slow_reader=True)
    )
    cut_off(answer)
    assert lines(caplog) == []


def test_an_answer_that_outlasts_the_total_time_is_not_blamed_on_the_gateway(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    reply = Reply(chunks=[b"x"] * 100, chunk_delay=0.2)
    answer, _ = run(
        through(lambda _s: reply, relay_options={"idle_timeout": 5, "max_request_seconds": 0.6})
    )
    cut_off(answer)
    assert lines(caplog) == []


def test_a_gateway_that_goes_quiet_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    answer, _ = run(through(lambda _s: Reply(stall=5), relay_options={"idle_timeout": 0.3}))
    assert answer.status == 502
    assert len(lines(caplog)) == 1


def test_a_gateway_that_cannot_be_reached_at_all_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")

    async def scenario() -> Answer:
        return await ask(relay_for(1))

    assert run(scenario()).status == 502
    assert len(lines(caplog)) == 1


def record_with(error: BaseException | None) -> logging.LogRecord:
    exc = (type(error), error, None) if error is not None else None
    return logging.LogRecord(
        "uvicorn.error", logging.ERROR, "x", 1, "Exception in ASGI application", (), exc
    )


def test_the_server_does_not_write_a_traceback_for_an_answer_the_relay_cut_off_on_purpose() -> None:
    quiet = QuietAbort()
    assert quiet.filter(record_with(ConnectionAbort())) is False
    assert quiet.filter(record_with(RuntimeError("something else"))) is True
    assert quiet.filter(record_with(None)) is True


def test_the_relay_is_started_with_that_filter_and_with_the_servers_own_logging_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from onionglass.tickets import generate_key  # noqa: PLC0415

    started: dict[str, object] = {}
    monkeypatch.setattr(
        "onionglass.relaycli.uvicorn.run", lambda app, **kwargs: started.update(kwargs, app=app)
    )
    logger = logging.getLogger("uvicorn.error")
    before = list(logger.filters)
    try:
        file = relay_file(tmp_path, 8080, generate_key())
        assert cli.main(["relay", "run", "--config", str(file)]) == 0
        assert started["log_config"] is None
        assert any(isinstance(f, QuietAbort) for f in logger.filters)
    finally:
        for added in [f for f in logger.filters if f not in before]:
            logger.removeFilter(added)


def test_the_check_command_says_so_when_the_gateway_cuts_its_answer_short(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from onionglass.tickets import generate_key  # noqa: PLC0415

    cut = Reply(raw=b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nok r")

    async def scenario() -> int:
        async with FakeOrigin(lambda _s: cut) as origin:
            file = relay_file(tmp_path, origin.port, generate_key())
            return await asyncio.to_thread(cli.main, ["relay", "check", "--config", str(file)])

    assert asyncio.run(scenario()) == 1
    shown = capsys.readouterr().out
    assert "FAIL" in shown and "cut" in shown


# --- hosts that are not names --------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        f"x/y.{DOMAIN}",
        f"x?y.{DOMAIN}",
        f"x#y.{DOMAIN}",
        f"x@y.{DOMAIN}",
        f"x y.{DOMAIN}",
        f"x_y.{DOMAIN}",
        f"x\\y.{DOMAIN}",
        f"x%2fy.{DOMAIN}",
    ],
)
def test_a_name_under_the_domain_that_is_not_a_name_is_a_missing_page(host: str) -> None:
    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin() as origin:
            return await ask(relay_for(origin.port), host=host), origin

    answer, origin = run(scenario())
    assert answer.status == 404 and answer.body == NOT_FOUND_PAGE
    assert origin.connections == 0


# --- the real gateway ----------------------------------------------------------------------------


@pytest.fixture
def chain() -> Iterator[Chain]:
    with Chain() as running:
        yield running


@pytest.mark.parametrize("size", [1_000, 200_000, 900_000])
def test_a_gateway_that_answers_before_it_has_read_the_upload_is_still_heard(
    chain: Chain, size: int
) -> None:
    # The real gateway answers a stranger's post at once, as a missing page, and closes the
    # connection. A close with unread data can reset the connection and lose the answer on its
    # way, so that the visitor gets a cut-off page or the relay's own error where the gateway
    # would have said "not found". Both would tell a probe what is in front of the gateway.
    pieces = [b"x" * 100_000] * (size // 100_000) or [b"x" * size]

    async def scenario() -> list[Answer]:
        answers = []
        for _ in range(12):
            answers.append(
                await visit(
                    chain.relay,
                    method="POST",
                    target="/nowhere",
                    headers=[("content-length", str(sum(map(len, pieces))))],
                    body=list(pieces),
                )
            )
        return answers

    for answer in asyncio.run(scenario()):
        assert answer.status == 404 and answer.body == NOT_FOUND_PAGE and answer.finished


def test_the_gateway_reads_and_throws_away_a_strangers_upload_before_it_answers() -> None:
    from test_relay_gateway import HOST, Relayed  # noqa: PLC0415

    env = Relayed(require=False)
    seen: list[str] = []
    pieces = [b"a" * 1000, b"b" * 1000, b"c" * 1000]

    async def scenario() -> int:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/nowhere",
            "raw_path": b"/nowhere",
            "query_string": b"",
            "headers": [(b"host", HOST.encode()), (b"content-length", b"3000")],
            "server": (HOST, 443),
            "client": ("203.0.113.9", 4444),
        }
        queue = list(pieces)
        status = 0

        async def receive() -> dict[str, Any]:
            if queue:
                chunk = queue.pop(0)
                seen.append("body")
                return {"type": "http.request", "body": chunk, "more_body": bool(queue)}
            await asyncio.sleep(0.05)
            return {"type": "http.disconnect"}

        async def send(message: Any) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                assert len(seen) == 3, "the answer came before the whole body was taken in"
                status = int(str(message["status"]))

        await env.gateway.app(scope, receive, send)
        return status

    assert asyncio.run(scenario()) == 404
    assert len(seen) == 3


def test_a_gateway_without_cover_mode_that_answers_a_small_post_at_once_is_still_heard() -> None:
    # Without cover mode the gateway does not read a body it has no use for. The relay sends the
    # head and the first piece of the body together, so that nothing of a small request is left
    # unread when the gateway answers and closes, which could reset the connection.
    with Chain(require=False, cover=False) as plain:

        async def scenario() -> list[Answer]:
            return [
                await visit(
                    plain.relay,
                    method="POST",
                    target="/nowhere",
                    headers=[("content-length", "1000")],
                    body=[b"x" * 1000],
                )
                for _ in range(20)
            ]

        for answer in asyncio.run(scenario()):
            assert answer.status == 404 and answer.finished and answer.body


# --- the relay behind a real web server ----------------------------------------------------------

CRLF = chr(13) + chr(10)


class LiveRelay:
    """The relay served by a real web server, as `onionglass relay run` serves it."""

    def __init__(self, gateway_port: int, **options: Any) -> None:
        self.relay = relay_for(gateway_port, **options)
        self.port = free_port()
        config = uvicorn.Config(
            self.relay,
            host="127.0.0.1",
            port=self.port,
            log_level="error",
            access_log=False,
            server_header=False,
            proxy_headers=False,
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> LiveRelay:
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            assert time.monotonic() < deadline, "the relay did not start"
            time.sleep(0.02)
        return self

    def __exit__(self, *_: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)


def test_a_gateway_that_stops_reading_does_not_keep_a_place_behind_a_real_web_server() -> None:
    # The relay's slot is freed when the request is over, which means closing the connection to a
    # gateway that has data still waiting to be taken. A close that waits for the data to be taken
    # never finishes, and the relay is then one place short for good.
    async def scenario() -> tuple[bytes, tuple[int, int]]:
        async def never_reads(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await asyncio.sleep(60)

        gateway = await asyncio.start_server(never_reads, "127.0.0.1", 0)
        gateway_port = gateway.sockets[0].getsockname()[1]
        size = 12_000_000
        try:
            with LiveRelay(gateway_port, idle_timeout=1.0, max_request_body=50_000_000) as live:
                reader, writer = await asyncio.open_connection("127.0.0.1", live.port)
                head = f"POST /open HTTP/1.1{CRLF}Host: {DOMAIN}{CRLF}Content-Length: {size}{CRLF}{CRLF}"
                writer.write(head.encode("ascii"))
                try:
                    for _ in range(size // 100_000):
                        writer.write(b"x" * 100_000)
                        await asyncio.wait_for(writer.drain(), 5)
                except (TimeoutError, ConnectionError):
                    pass  # the relay may have answered and closed already
                answer = b""
                with contextlib.suppress(TimeoutError, ConnectionError):
                    answer = await asyncio.wait_for(reader.read(200), 8)
                for _ in range(80):  # up to eight seconds for the place to come back
                    if live.relay.busy() == (0, 0):
                        break
                    await asyncio.sleep(0.1)
                writer.close()
                return answer, live.relay.busy()
        finally:
            gateway.close()

    answer, busy = asyncio.run(scenario())
    assert busy == (0, 0), "the relay is still holding a place for a gateway that never reads"
    assert answer.startswith(b"HTTP/1.1 ")
