# SPDX-License-Identifier: AGPL-3.0-only
"""A fake Tor SOCKS5 port and a fake onion web server, so tests need no real Tor."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

Handler = Callable[[bytes, asyncio.StreamWriter], Awaitable[None]]


def static_response(*chunks: bytes) -> Handler:
    """A handler that writes the given bytes and closes the connection."""

    async def handler(_request: bytes, writer: asyncio.StreamWriter) -> None:
        for chunk in chunks:
            writer.write(chunk)
            await writer.drain()

    return handler


def http_response(
    body: bytes = b"",
    *,
    status: str = "200 OK",
    headers: tuple[tuple[str, str], ...] = (),
    length: bool = True,
) -> bytes:
    lines = [f"HTTP/1.1 {status}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    if length:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


async def read_http_request(reader: asyncio.StreamReader) -> bytes:
    head = await reader.readuntil(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    return head + (await reader.readexactly(length) if length else b"")


class FakeOnionServer:
    """Speaks HTTP like an onion site. Records every request it receives."""

    def __init__(self, handler: Handler, *, ssl_context: ssl.SSLContext | None = None) -> None:
        self._handler = handler
        self._ssl = ssl_context
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self.requests: list[bytes] = []

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def __aenter__(self) -> FakeOnionServer:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0, ssl=self._ssl)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await _bounded_wait_closed(self._server)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        try:
            request = await read_http_request(reader)
            self.requests.append(request)
            await self._handler(request, writer)
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            ssl.SSLError,
            asyncio.LimitOverrunError,
        ):
            pass
        finally:
            self._tasks.discard(task)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)


@dataclass
class Seen:
    """What the fake Tor port saw from one client."""

    methods: bytes = b""
    username: str = ""
    password: str = ""
    address_type: int = 0
    host: str = ""
    port: int = 0
    raw: list[bytes] = field(default_factory=list)


class FakeTor:
    """A SOCKS5 server that records the exchange and relays to a fake onion server."""

    def __init__(
        self,
        relay_port: int | None = None,
        *,
        reply: int = 0,
        bound_address_type: int = 1,
        method_reply: int = 2,
        auth_status: int = 0,
        stall_connect: bool = False,
        close_after_greeting: bool = False,
        close_after_auth: bool = False,
    ) -> None:
        self.relay_port = relay_port
        self.reply = reply
        self.bound_address_type = bound_address_type
        self.method_reply = method_reply
        self.auth_status = auth_status
        self.stall_connect = stall_connect
        self.close_after_greeting = close_after_greeting
        self.close_after_auth = close_after_auth
        self.seen: list[Seen] = []
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def __aenter__(self) -> FakeTor:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await _bounded_wait_closed(self._server)

    def _bound_address(self) -> bytes:
        if self.bound_address_type == 1:
            return bytes([1]) + b"\x00" * 4 + b"\x00\x00"
        if self.bound_address_type == 4:
            return bytes([4]) + b"\x00" * 16 + b"\x00\x00"
        return bytes([3, 4]) + b"fake" + b"\x00\x00"

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        try:
            await self._socks(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._tasks.discard(task)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)

    async def _socks(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen = Seen()
        self.seen.append(seen)
        _version, count = await reader.readexactly(2)
        seen.methods = await reader.readexactly(count)
        if self.close_after_greeting:
            return
        writer.write(bytes([5, self.method_reply]))
        await writer.drain()
        if self.method_reply == 0xFF:
            return
        _auth_version, user_length = await reader.readexactly(2)
        seen.username = (await reader.readexactly(user_length)).decode("ascii")
        (password_length,) = await reader.readexactly(1)
        seen.password = (await reader.readexactly(password_length)).decode("ascii")
        writer.write(bytes([1, self.auth_status]))
        await writer.drain()
        if self.auth_status != 0 or self.close_after_auth:
            return
        _v, _command, _reserved, seen.address_type = await reader.readexactly(4)
        if seen.address_type == 3:
            (length,) = await reader.readexactly(1)
            seen.host = (await reader.readexactly(length)).decode("ascii")
        seen.port = int.from_bytes(await reader.readexactly(2), "big")
        if self.stall_connect:
            await asyncio.sleep(3600)
        writer.write(bytes([5, self.reply, 0]) + self._bound_address())
        await writer.drain()
        if self.reply != 0 or self.relay_port is None:
            return
        upstream_reader, upstream_writer = await asyncio.open_connection(
            "127.0.0.1", self.relay_port
        )
        try:
            await asyncio.gather(_pipe(reader, upstream_writer), _pipe(upstream_reader, writer))
        finally:
            upstream_writer.close()


async def _bounded_wait_closed(server: asyncio.Server) -> None:
    """Server.wait_closed can hang on Windows after a connection reset, so bound it."""
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(server.wait_closed(), timeout=2.0)


async def _pipe(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
    try:
        while data := await source.read(65536):
            sink.write(data)
            await sink.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        with contextlib.suppress(Exception):
            sink.write_eof()


def make_certificate(directory: Path) -> tuple[ssl.SSLContext, bytes]:
    """A self-signed certificate. Returns a server context and the certificate's DER bytes."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_file = directory / "cert.pem"
    key_file = directory / "key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    return context, certificate.public_bytes(serialization.Encoding.DER)
