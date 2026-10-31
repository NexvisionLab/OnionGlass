# SPDX-License-Identifier: AGPL-3.0-only
"""One HTTP/1.1 POST on a new connection, for the services the gateway calls.

The signed hooks and the translation service both need the same careful exchange: a new
connection for every call, TLS checked when it is used, no redirects followed, and a limit on how
much of a reply is read. Each caller decides what its own errors are called.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl

import h11


class ExchangeError(Exception):
    """The reply could not be read: it was too large, or it ended early."""


async def post(  # noqa: PLR0913 - a call needs where it goes, how it is sent and its limit
    host: str,
    port: int,
    tls: ssl.SSLContext | None,
    path: str,
    *,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
    max_reply: int,
) -> tuple[int, dict[str, str], bytes]:
    """Send ``body`` and return the status, the reply headers (lower-cased) and the reply."""
    reader, writer = await asyncio.open_connection(
        host, port, ssl=tls, server_hostname=host if tls is not None else None
    )
    try:
        connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=16_384)
        writer.write(connection.send(h11.Request(method="POST", target=path, headers=headers)))
        writer.write(connection.send(h11.Data(data=body)))
        writer.write(connection.send(h11.EndOfMessage()))
        await writer.drain()
        return await read_reply(reader, connection, max_reply)
    finally:
        writer.close()
        with contextlib.suppress(TimeoutError, OSError, ssl.SSLError):
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)


async def read_reply(
    reader: asyncio.StreamReader, connection: h11.Connection, max_reply: int
) -> tuple[int, dict[str, str], bytes]:
    status = 0
    reply_headers: dict[str, str] = {}
    received = bytearray()
    while True:
        event = connection.next_event()
        if event is h11.NEED_DATA:
            chunk = await reader.read(65_536)
            connection.receive_data(chunk)
            if not chunk and connection.their_state not in (h11.DONE, h11.CLOSED):
                # receive_data(b"") told h11 the peer closed; the next event reports it
                continue
        elif isinstance(event, h11.InformationalResponse):
            continue
        elif isinstance(event, h11.Response):
            status = event.status_code
            reply_headers = {
                name.decode("latin-1").lower(): value.decode("latin-1")
                for name, value in event.headers
            }
        elif isinstance(event, h11.Data):
            received += event.data
            if len(received) > max_reply:
                raise ExchangeError("reply is too large")
        elif isinstance(event, h11.EndOfMessage):
            return status, reply_headers, bytes(received)
        else:
            raise ExchangeError("reply ended unexpectedly")
