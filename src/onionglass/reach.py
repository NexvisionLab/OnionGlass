# SPDX-License-Identifier: AGPL-3.0-only
"""Reachability: where a connection to a domain fails.

A censor can interfere at four places, and each shows differently: the name lookup, the TCP
connection, the TLS handshake, and the page. Telling them apart tells an operator what is being
done to a domain, and whether a new domain would fare any better.

The check asks for the front page once, as a browser would, and nothing else. It sends no cookie,
no account and no identifier, follows no redirect, and reads at most a megabyte. It does connect to
the domain, so running it from inside a country is a risk to whoever does it.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import socket
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import h11

from onionglass import httpexchange as exchange

MAX_PAGE_BYTES = 1_000_000
USER_AGENT = b"Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0"

Resolver = Callable[[str, int], Awaitable[list[str]]]


@dataclass(frozen=True, slots=True)
class Reach:
    """What happened when a domain was tried: where it stopped, and whether that is a success."""

    domain: str
    stage: str  # ok, dns_failed, dns_unexpected, wildcard_dns_failed, tcp_failed, tls_failed,
    #             http_failed or content_changed
    ok: bool
    message: str


async def system_resolver(name: str, port: int) -> list[str]:
    """The addresses this machine's own resolver gives for a name, in its order."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(name, port, type=socket.SOCK_STREAM)
    found: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in found:
            found.append(address)
    return found


def _failed(domain: str, stage: str, message: str) -> Reach:
    return Reach(domain, stage, False, message)


async def check_domain(  # noqa: PLR0913 - what to try, how to reach it and what to expect
    domain: str,
    *,
    port: int = 443,
    expect: frozenset[str] | None = None,
    expect_sha256: str | None = None,
    timeout: float = 10.0,
    resolve: Resolver | None = None,
    tls_context: ssl.SSLContext | None = None,
    check_wildcard: bool = True,
) -> Reach:
    """Try a domain, stage by stage, and say where it stopped.

    ``expect`` is the set of addresses the domain should resolve to, so that a poisoned answer
    shows. ``expect_sha256`` is the hash of the front page, so that a page injected on the way
    shows. ``check_wildcard`` also looks up a made-up session host name under the domain.
    """
    lookup = resolve or system_resolver
    try:
        addresses = await asyncio.wait_for(lookup(domain, port), timeout)
    except (OSError, TimeoutError):
        addresses = []
    if not addresses:
        return _failed(
            domain,
            "dns_failed",
            "the name does not resolve. It may be blocked or poisoned, or not set up yet.",
        )
    if expect is not None and not set(addresses) <= expect:
        return _failed(
            domain,
            "dns_unexpected",
            f"the name resolves to {', '.join(addresses)}, which is not what you expect. "
            "That is typical of DNS poisoning.",
        )
    if check_wildcard:
        session_host = f"probe-{secrets.token_hex(4)}.{domain}"
        try:
            wildcard = await asyncio.wait_for(lookup(session_host, port), timeout)
        except (OSError, TimeoutError):
            wildcard = []
        if not wildcard:
            return _failed(
                domain,
                "wildcard_dns_failed",
                "the domain resolves but a session host name under it does not. The wildcard "
                "record may be missing, or blocked.",
            )
    first: Reach | None = None
    for address in addresses:
        result = await _try_address(
            domain,
            address,
            port,
            expect_sha256=expect_sha256,
            timeout=timeout,
            tls_context=tls_context,
        )
        if result.ok or result.stage == "content_changed":
            return result
        first = first or result
    return first or _failed(domain, "dns_failed", "there was no address to try.")


async def _try_address(  # noqa: PLR0913 - one address, and everything the stages need
    domain: str,
    address: str,
    port: int,
    *,
    expect_sha256: str | None,
    timeout: float,
    tls_context: ssl.SSLContext | None,
) -> Reach:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
    except TimeoutError:
        return _failed(
            domain,
            "tcp_failed",
            f"the connection to {address} timed out. Dropped packets like this are typical of "
            "an address block.",
        )
    except OSError as exc:
        return _failed(
            domain,
            "tcp_failed",
            f"the connection to {address} failed ({type(exc).__name__}). A refusal or a reset "
            "can mean the address is blocked, or that nothing is listening.",
        )
    try:
        stopped = await _handshake(domain, writer, timeout, tls_context)
        if stopped is not None:
            return stopped
        return await _fetch(domain, reader, writer, expect_sha256, timeout)
    finally:
        writer.close()


async def _handshake(
    domain: str, writer: asyncio.StreamWriter, timeout: float, tls_context: ssl.SSLContext | None
) -> Reach | None:
    context = tls_context or ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        await asyncio.wait_for(
            writer.start_tls(context, server_hostname=domain, ssl_handshake_timeout=timeout),
            timeout,
        )
    except ssl.SSLCertVerificationError:
        return _failed(
            domain,
            "tls_failed",
            "the certificate is not valid for this name. The connection may be intercepted, or "
            "the domain may be set up wrongly.",
        )
    except TimeoutError:
        return _failed(
            domain,
            "tls_failed",
            "there was no answer to the TLS hello. Silence after the hello is typical of "
            "packets being dropped.",
        )
    except (ssl.SSLError, OSError, EOFError):
        return _failed(
            domain,
            "tls_failed",
            "the connection was cut during the TLS handshake. A reset right after the hello is "
            "typical of blocking by server name.",
        )
    return None


async def _fetch(
    domain: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    expect_sha256: str | None,
    timeout: float,
) -> Reach:
    connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=16_384)
    headers = [
        (b"host", domain.encode("ascii")),
        (b"user-agent", USER_AGENT),
        (b"accept", b"text/html"),
        (b"connection", b"close"),
    ]
    try:
        writer.write(connection.send(h11.Request(method="GET", target="/", headers=headers)))
        writer.write(connection.send(h11.EndOfMessage()))
        await writer.drain()
        status, _, body = await asyncio.wait_for(
            exchange.read_reply(reader, connection, MAX_PAGE_BYTES), timeout
        )
    except exchange.ExchangeError as exc:
        return _failed(domain, "http_failed", f"TLS works but the page could not be read: {exc}.")
    except (TimeoutError, OSError, ssl.SSLError, h11.ProtocolError):
        return _failed(domain, "http_failed", "TLS works but there was no usable reply.")
    if expect_sha256 and hashlib.sha256(body).hexdigest() != expect_sha256.lower():
        return _failed(
            domain,
            "content_changed",
            "the page is not the one you expect, so something on the way may be injecting its "
            "own page.",
        )
    return Reach(
        domain, "ok", True, f"reachable: the name resolves, TLS works and it answered {status}."
    )
