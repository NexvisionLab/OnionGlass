# SPDX-License-Identifier: AGPL-3.0-only
"""Reachability: where a connection to a domain fails, in the order a censor can interfere.

The name lookup, the connection, the TLS handshake and the page each fail in a different way, and
the way tells an operator what is being done. The check only asks for the front page, sends
nothing about anyone, and follows nothing.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from pathlib import Path
from typing import Any

import pytest

from hook_server import make_certificate
from onionglass import reach
from onionglass.entries import Entry
from onionglass.reach import Reach, check_domain
from onionglass.teamcli import run
from test_config import Layout
from test_entries import with_entries

DOMAIN = "gw.example"
CRLF = bytes([13, 10])
BODY = b"<html><body>Welcome</body></html>"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def resolve_locally(name: str, port: int) -> list[str]:
    return ["127.0.0.1"]


def trusting(cert: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(cert))


class Site:
    """A TLS web server on this machine. ``behaviour`` decides what it does with a connection."""

    def __init__(
        self, directory: Path, behaviour: str = "page", names: tuple[str, ...] = (DOMAIN,)
    ) -> None:
        self.behaviour = behaviour
        self.requests: list[bytes] = []
        self.cert, key = make_certificate(directory, names)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(self.cert, key)
        self.server: asyncio.Server | None = None
        self.port = 0

    async def __aenter__(self) -> Site:
        use_tls = None if self.behaviour in ("plain-close", "silent") else self.context
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0, ssl=use_tls)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self.server is not None
        self.server.close()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if self.behaviour == "plain-close":
                writer.close()
                return
            if self.behaviour == "silent":
                await asyncio.sleep(30)
                return
            request = await reader.readuntil(CRLF + CRLF)
            self.requests.append(request)
            if self.behaviour == "no-reply":
                return
            if self.behaviour == "redirect":
                head = b"HTTP/1.1 302 Found" + CRLF + b"Location: http://elsewhere.example/"
                writer.write(head + CRLF + b"Content-Length: 0" + CRLF + CRLF)
            elif self.behaviour == "missing":
                writer.write(b"HTTP/1.1 404 Not Found" + CRLF + b"Content-Length: 0" + CRLF + CRLF)
            elif self.behaviour == "huge":
                writer.write(b"HTTP/1.1 200 OK" + CRLF + b"Connection: close" + CRLF + CRLF)
                for _ in range(80):
                    writer.write(b"x" * 100_000)
                    await writer.drain()
            else:
                length = str(len(BODY)).encode("ascii")
                writer.write(
                    b"HTTP/1.1 200 OK" + CRLF + b"Content-Length: " + length + CRLF + CRLF + BODY
                )
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            writer.close()


def probe(site: Site, **options: Any) -> Reach:
    settings: dict[str, Any] = {
        "port": site.port,
        "resolve": resolve_locally,
        "tls_context": trusting(site.cert),
        "timeout": 3.0,
        "check_wildcard": False,
    }
    settings.update(options)
    return asyncio.run(check_domain(DOMAIN, **settings))


def served(tmp_path: Path, behaviour: str = "page", **options: Any) -> tuple[Reach, Site]:
    async def scenario() -> tuple[Reach, Site]:
        async with Site(tmp_path, behaviour) as site:
            result = await check_domain(
                DOMAIN,
                **{
                    "port": site.port,
                    "resolve": resolve_locally,
                    "tls_context": trusting(site.cert),
                    "timeout": 3.0,
                    "check_wildcard": False,
                    **options,
                },
            )
            return result, site

    return asyncio.run(scenario())


# --- every stage ---------------------------------------------------------------------------------


def test_a_domain_that_works_is_reachable(tmp_path: Path) -> None:
    result, _ = served(tmp_path)
    assert result.ok and result.stage == "ok" and "200" in result.message


def test_any_answer_counts_as_reachable_even_a_missing_page(tmp_path: Path) -> None:
    result, _ = served(tmp_path, "missing")
    assert result.ok and "404" in result.message


def test_a_redirect_is_not_followed(tmp_path: Path) -> None:
    result, site = served(tmp_path, "redirect")
    assert result.ok and "302" in result.message and len(site.requests) == 1


def test_the_page_can_be_compared_with_the_one_you_expect(tmp_path: Path) -> None:
    right = hashlib.sha256(BODY).hexdigest()
    assert served(tmp_path, expect_sha256=right)[0].ok
    wrong = served(tmp_path, expect_sha256="0" * 64)[0]
    assert not wrong.ok and wrong.stage == "content_changed" and "injecting" in wrong.message


def test_a_name_that_does_not_resolve_is_reported_as_a_name_problem() -> None:
    async def no_such_name(name: str, port: int) -> list[str]:
        raise OSError("no such host")

    result = asyncio.run(check_domain(DOMAIN, resolve=no_such_name, check_wildcard=False))
    assert not result.ok and result.stage == "dns_failed" and "resolve" in result.message


def test_a_name_that_resolves_to_the_wrong_address_looks_like_poisoning() -> None:
    result = asyncio.run(
        check_domain(
            DOMAIN,
            resolve=resolve_locally,
            expect=frozenset({"203.0.113.9"}),
            check_wildcard=False,
        )
    )
    assert not result.ok and result.stage == "dns_unexpected" and "127.0.0.1" in result.message


def test_a_missing_wildcard_is_told_apart_from_a_missing_domain(tmp_path: Path) -> None:
    async def only_the_domain(name: str, port: int) -> list[str]:
        if name != DOMAIN:
            raise OSError("no such host")
        return ["127.0.0.1"]

    result, _ = served(tmp_path, resolve=only_the_domain, check_wildcard=True)
    assert not result.ok and result.stage == "wildcard_dns_failed"


def test_the_wildcard_is_asked_about_with_a_new_name_every_time() -> None:
    asked: list[str] = []

    async def record(name: str, port: int) -> list[str]:
        asked.append(name)
        raise OSError("stop here")

    async def twice() -> None:
        async def one(name: str, port: int) -> list[str]:
            if name == DOMAIN:
                return ["127.0.0.1"]
            return await record(name, port)

        await check_domain(DOMAIN, resolve=one, check_wildcard=True)
        await check_domain(DOMAIN, resolve=one, check_wildcard=True)

    asyncio.run(twice())
    assert len(asked) == 2 and asked[0] != asked[1]
    assert all(name.endswith(f".{DOMAIN}") for name in asked)


def test_a_closed_port_is_a_connection_problem() -> None:
    result = asyncio.run(
        check_domain(
            DOMAIN, port=free_port(), resolve=resolve_locally, timeout=3.0, check_wildcard=False
        )
    )
    assert not result.ok and result.stage == "tcp_failed"


def test_an_address_that_drops_packets_is_a_timeout() -> None:
    async def blackhole(name: str, port: int) -> list[str]:
        return ["203.0.113.1"]  # a documentation address: nothing answers there

    result = asyncio.run(check_domain(DOMAIN, resolve=blackhole, timeout=0.4, check_wildcard=False))
    assert not result.ok and result.stage == "tcp_failed"


def test_a_connection_cut_during_the_handshake_looks_like_blocking_by_name(
    tmp_path: Path,
) -> None:
    result, _ = served(tmp_path, "plain-close")
    assert not result.ok and result.stage == "tls_failed" and "handshake" in result.message


def test_a_server_that_never_answers_the_hello_is_reported(tmp_path: Path) -> None:
    result, _ = served(tmp_path, "silent", timeout=0.5)
    assert not result.ok and result.stage == "tls_failed" and "answer" in result.message


def test_a_certificate_for_another_name_is_reported_as_interception(tmp_path: Path) -> None:
    async def scenario() -> Reach:
        async with Site(tmp_path, "page", names=("other.example",)) as site:
            return await check_domain(
                DOMAIN,
                port=site.port,
                resolve=resolve_locally,
                tls_context=trusting(site.cert),
                timeout=3.0,
                check_wildcard=False,
            )

    result = asyncio.run(scenario())
    assert not result.ok and result.stage == "tls_failed" and "certificate" in result.message


def test_a_server_that_takes_the_request_and_says_nothing_is_a_page_problem(
    tmp_path: Path,
) -> None:
    result, _ = served(tmp_path, "no-reply")
    assert not result.ok and result.stage == "http_failed"


def test_a_page_that_never_ends_does_not_hang_the_check(tmp_path: Path) -> None:
    result, _ = served(tmp_path, "huge")
    assert not result.ok and result.stage == "http_failed" and "large" in result.message


# --- what it sends -------------------------------------------------------------------------------


def test_the_check_asks_for_the_front_page_and_says_nothing_else(tmp_path: Path) -> None:
    _, site = served(tmp_path)
    request = site.requests[0].decode("ascii").split(CRLF.decode("ascii"))
    assert request[0] == "GET / HTTP/1.1"
    names = {line.split(":", 1)[0].lower() for line in request[1:] if line}
    assert names == {"host", "user-agent", "accept", "connection"}
    assert f"host: {DOMAIN}" in [line.lower() for line in request]


# --- the command ---------------------------------------------------------------------------------


def fake_check(results: dict[str, Reach]) -> Any:
    async def fake(domain: str, **options: Any) -> Reach:
        return results[domain]

    return fake


def test_the_command_succeeds_when_every_domain_is_reachable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    good = Reach("a.example.net", "ok", True, "reachable, answered 200")
    monkeypatch.setattr(reach, "check_domain", fake_check({"a.example.net": good}))
    assert run(["domains", "check", "--domain", "a.example.net"]) == 0
    assert "ok" in capsys.readouterr().out


def test_the_command_fails_and_says_where_each_failure_is(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    results = {
        "a.example.net": Reach("a.example.net", "ok", True, "reachable, answered 200"),
        "b.example.net": Reach("b.example.net", "tls_failed", False, "reset during handshake"),
    }
    monkeypatch.setattr(reach, "check_domain", fake_check(results))
    assert run(["domains", "check", "--domain", "a.example.net", "--domain", "b.example.net"]) == 1
    shown = capsys.readouterr().out
    assert "FAIL" in shown and "b.example.net" in shown and "tls_failed" in shown


def test_the_command_checks_every_domain_in_a_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(Layout(tmp_path))
    names = ("gateway.example.org", "a.example.net", "b.example.net")
    results = {n: Reach(n, "ok", True, "reachable, answered 200") for n in names}
    monkeypatch.setattr(reach, "check_domain", fake_check(results))
    assert run(["domains", "check", "--config", str(config)]) == 0
    shown = capsys.readouterr().out
    assert all(name in shown for name in names)


def test_the_command_needs_something_to_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["domains", "check"]) == 2
    assert "--domain" in capsys.readouterr().err


@pytest.mark.parametrize("timeout", ["0", "-1", "1000", "soon"])
def test_a_bad_timeout_is_refused(timeout: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        run(["domains", "check", "--domain", "a.example.net", "--timeout", timeout])
    assert "timeout" in capsys.readouterr().err


def test_a_domain_that_is_not_a_domain_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["domains", "check", "--domain", "not a domain"]) == 2
    assert "domain" in capsys.readouterr().err


def test_the_entry_type_is_used_for_names_only() -> None:
    assert Entry("a", "a.example.net", 8081, None, "x").domain == "a.example.net"
