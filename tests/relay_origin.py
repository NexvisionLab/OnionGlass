# SPDX-License-Identifier: AGPL-3.0-only
"""A stand-in for the gateway behind a relay: a small web server that writes down exactly what it
was sent, and can be told to behave badly."""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

import h11
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class Seen:
    """One request as the gateway received it."""

    method: str
    target: str
    headers: list[tuple[str, str]]
    body: bytes
    raw_head: bytes

    def all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name.lower()]

    def one(self, name: str) -> str:
        values = self.all(name)
        assert len(values) == 1, (name, values)
        return values[0]


@dataclass
class Reply:
    """What the fake gateway answers."""

    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    chunks: list[bytes] | None = None  # sent chunked, one piece each, when set
    stall: float = 0.0  # seconds to wait before answering
    raw: bytes | None = None  # send exactly this and nothing else
    hang_up_after_head: bool = False
    short_by: int = 0  # promise this many more bytes than are sent, then hang up
    chunk_delay: float = 0.0  # seconds between the pieces of a chunked answer


def certificate(folder: Path) -> tuple[Path, Path, str]:
    """A self-signed certificate for the tests, with the SHA-256 a relay would pin."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = folder / "origin.crt", folder / "origin.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return cert_file, key_file, hashlib.sha256(der).hexdigest()


class FakeOrigin:
    """Serves on a free local port. ``behave`` decides each answer from what was sent."""

    def __init__(
        self,
        behave: Callable[[Seen], Reply] | None = None,
        *,
        tls: tuple[Path, Path] | None = None,
        early: bool = False,
    ) -> None:
        self._behave = behave or (lambda _seen: Reply(body=b"ok"))
        self._tls = tls
        self._early = early  # answer as soon as the head arrives, without reading the body
        self.seen: list[Seen] = []
        self.connections = 0
        self.port = 0
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> FakeOrigin:
        context = None
        if self._tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*self._tls)
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0, ssl=context)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        connection = h11.Connection(h11.SERVER)
        raw = b""
        head: h11.Request | None = None
        body = b""
        try:
            while True:
                event = connection.next_event()
                if event is h11.NEED_DATA:
                    data = await reader.read(65536)
                    if not data:
                        return
                    if head is None:
                        raw += data
                    connection.receive_data(data)
                elif isinstance(event, h11.Request):
                    head = event
                    if self._early:
                        seen = self._seen(head, b"", raw)
                        self.seen.append(seen)
                        await self._answer(writer, self._behave(seen), seen.method)
                        return
                elif isinstance(event, h11.Data):
                    body += bytes(event.data)
                elif isinstance(event, h11.EndOfMessage):
                    break
            assert head is not None
            seen = self._seen(head, body, raw)
            self.seen.append(seen)
            await self._answer(writer, self._behave(seen), seen.method)
        except (ConnectionError, h11.ProtocolError, ssl.SSLError):
            pass
        finally:
            writer.close()

    @staticmethod
    def _seen(head: h11.Request, body: bytes, raw: bytes) -> Seen:
        headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in head.headers]
        return Seen(
            head.method.decode("ascii"),
            head.target.decode("ascii"),
            headers,
            body,
            raw.split(b"\r\n\r\n", 1)[0],
        )

    @staticmethod
    async def _answer(writer: asyncio.StreamWriter, reply: Reply, method: str) -> None:
        if reply.stall:
            await asyncio.sleep(reply.stall)
        if reply.raw is not None:
            writer.write(reply.raw)
            await writer.drain()
            return
        lines = [f"HTTP/1.1 {reply.status} Reason".encode("ascii")]
        for name, value in reply.headers:
            lines.append(f"{name}: {value}".encode("latin-1"))
        names = {name.lower() for name, _ in reply.headers}
        if reply.chunks is not None:
            if "transfer-encoding" not in names:
                lines.append(b"Transfer-Encoding: chunked")
        elif "content-length" not in names and method != "HEAD":
            lines.append(f"Content-Length: {len(reply.body) + reply.short_by}".encode("ascii"))
        writer.write(b"\r\n".join(lines) + b"\r\n\r\n")
        await writer.drain()
        if reply.hang_up_after_head:
            return
        if reply.chunks is not None:
            for piece in reply.chunks:
                writer.write(f"{len(piece):x}\r\n".encode("ascii") + piece + b"\r\n")
                await writer.drain()
                if reply.chunk_delay:
                    await asyncio.sleep(reply.chunk_delay)
            writer.write(b"0\r\n\r\n")
        elif method != "HEAD":
            writer.write(reply.body)
        await writer.drain()
