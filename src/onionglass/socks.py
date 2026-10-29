# SPDX-License-Identifier: AGPL-3.0-only
"""A small SOCKS5 client for talking to Tor.

Why not use a general-purpose library: Tor reports why an onion connection failed in extended
SOCKS reply codes (site offline, introduction failed, authorisation needed). General clients
turn those into a generic error. This client keeps them, so visitors get a useful message.

Isolation: the user name and password are sent to Tor, which keeps connections that use
different credentials on different circuits. The gateway uses one credential per visitor
session, so two visitors never share a circuit (property P4 and the visitor's privacy).

The target is always sent as a host name, never an address, so Tor does the name lookup.
"""

from __future__ import annotations

import asyncio

SOCKS_VERSION = 5
AUTH_VERSION = 1
METHOD_USERNAME_PASSWORD = 0x02
COMMAND_CONNECT = 0x01
ADDRESS_DOMAIN = 0x03

REPLY_KINDS: dict[int, str] = {
    0x01: "general_failure",
    0x02: "not_allowed",
    0x03: "network_unreachable",
    0x04: "host_unreachable",
    0x05: "connection_refused",
    0x06: "ttl_expired",
    0x07: "command_not_supported",
    0x08: "address_type_not_supported",
    # Extended errors, sent by Tor when its SOCKS port has ExtendedErrors turned on.
    0xF0: "descriptor_not_found",
    0xF1: "descriptor_invalid",
    0xF2: "introduction_failed",
    0xF3: "rendezvous_failed",
    0xF4: "auth_required",
    0xF5: "auth_wrong",
    0xF6: "invalid_address",
    0xF7: "introduction_timeout",
}


class SocksError(Exception):
    """The SOCKS exchange failed. ``kind`` says why, in terms the gateway can explain."""

    def __init__(self, kind: str, code: int | None = None) -> None:
        super().__init__(kind)
        self.kind = kind
        self.code = code


async def _read_exactly(reader: asyncio.StreamReader, count: int) -> bytes:
    try:
        return await reader.readexactly(count)
    except asyncio.IncompleteReadError as exc:
        raise SocksError("proxy_closed") from exc


def _credential(value: str, name: str) -> bytes:
    if not value.isascii():
        raise ValueError(f"{name} must be 1 to 255 ASCII bytes")
    raw = value.encode("ascii")
    if not 1 <= len(raw) <= 255:
        raise ValueError(f"{name} must be 1 to 255 ASCII bytes")
    return raw


async def socks5_connect(
    target_host: str,
    target_port: int,
    *,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 9050,
    username: str,
    password: str = "x",
    proxy_connect_timeout: float = 10.0,
    connect_timeout: float = 60.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a connection to ``target_host:target_port`` through a SOCKS5 proxy.

    ``connect_timeout`` covers the whole exchange, which for an onion site includes finding the
    site and building circuits, so it is long. Returns the open streams on success.
    """
    user = _credential(username, "username")
    secret = _credential(password, "password")
    if not target_host.isascii() or not 1 <= len(target_host) <= 255:
        raise ValueError("target host must be 1 to 255 ASCII characters")
    if not 1 <= target_port <= 65535:
        raise ValueError("target port out of range")
    try:
        async with asyncio.timeout(proxy_connect_timeout):
            reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    except (OSError, TimeoutError) as exc:
        raise SocksError("proxy_unreachable") from exc
    try:
        async with asyncio.timeout(connect_timeout):
            await _handshake(reader, writer, target_host, target_port, user, secret)
    except TimeoutError as exc:
        writer.close()
        raise SocksError("connect_timeout") from exc
    except BaseException:
        writer.close()
        raise
    return reader, writer


async def _handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    user: bytes,
    secret: bytes,
) -> None:
    writer.write(bytes([SOCKS_VERSION, 1, METHOD_USERNAME_PASSWORD]))
    await writer.drain()
    version, method = await _read_exactly(reader, 2)
    if version != SOCKS_VERSION or method != METHOD_USERNAME_PASSWORD:
        raise SocksError("proxy_refused_auth_method")
    writer.write(bytes([AUTH_VERSION, len(user)]) + user + bytes([len(secret)]) + secret)
    await writer.drain()
    auth_version, status = await _read_exactly(reader, 2)
    if auth_version != AUTH_VERSION or status != 0:
        raise SocksError("proxy_rejected_credentials")
    name = host.encode("ascii")
    request = bytes([SOCKS_VERSION, COMMAND_CONNECT, 0, ADDRESS_DOMAIN, len(name)]) + name
    writer.write(request + port.to_bytes(2, "big"))
    await writer.drain()
    version, reply, _reserved, address_type = await _read_exactly(reader, 4)
    if version != SOCKS_VERSION:
        raise SocksError("proxy_protocol_error")
    if reply != 0:
        raise SocksError(REPLY_KINDS.get(reply, "unknown_failure"), reply)
    if address_type == 0x01:
        await _read_exactly(reader, 4 + 2)
    elif address_type == 0x04:
        await _read_exactly(reader, 16 + 2)
    elif address_type == ADDRESS_DOMAIN:
        (length,) = await _read_exactly(reader, 1)
        await _read_exactly(reader, length + 2)
    else:
        raise SocksError("proxy_protocol_error")
