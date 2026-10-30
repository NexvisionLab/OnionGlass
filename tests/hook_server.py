# SPDX-License-Identifier: AGPL-3.0-only
"""A fake hook service for the tests: it checks signatures and can misbehave on demand.

It verifies requests with its own code, written separately from the gateway's, so the tests prove
that what the gateway sends can be checked by someone who only has the written description.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import h11
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def request_base(key_id: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """What a receiver rebuilds from the written description, and nothing else."""
    digest = hashlib.sha256(body).hexdigest()
    return (
        b"onionglass hook request v1\x00"
        + "\n".join([key_id, "POST", path, timestamp, nonce, digest]).encode()
    )


def response_base(key_id: str, nonce: str, status: int, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return (
        b"onionglass hook response v1\x00"
        + "\n".join([key_id, nonce, str(status), digest]).encode()
    )


@dataclass
class Seen:
    path: str
    headers: dict[str, str]
    payload: dict[str, Any]
    valid: bool
    nonce: str = ""


@dataclass
class HookServer:
    gateway_key_id: str
    gateway_public: Ed25519PublicKey
    service_signer: Ed25519PrivateKey
    service_key_id: str = "svc1"
    tls: ssl.SSLContext | None = None
    handler: Callable[[str, dict[str, Any]], dict[str, Any]] = lambda _path, _payload: {
        "allow": True
    }
    mode: str = "normal"
    seen: list[Seen] = field(default_factory=list)
    port: int = 0
    _loop: asyncio.AbstractEventLoop | None = None
    _thread: threading.Thread | None = None
    _server: asyncio.Server | None = None
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)
    _nonces: set[str] = field(default_factory=set)

    # --- running it -------------------------------------------------------------------------

    def start(self) -> HookServer:
        ready = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            async def boot() -> None:
                self._server = await asyncio.start_server(
                    self._connection, "127.0.0.1", 0, ssl=self.tls
                )
                self.port = self._server.sockets[0].getsockname()[1]

            loop.run_until_complete(boot())
            ready.set()
            loop.run_forever()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(10), "the fake hook server did not start"
        return self

    def stop(self) -> None:
        loop = self._loop
        if loop is None or self._thread is None:
            return

        def shutdown() -> None:
            if self._server is not None:
                self._server.close()
            for task in list(self._tasks):
                task.cancel()
            loop.call_later(0.05, loop.stop)

        loop.call_soon_threadsafe(shutdown)
        self._thread.join(5)
        self._loop = None

    @property
    def url(self) -> str:
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self.port}"

    # --- one connection ---------------------------------------------------------------------

    async def _connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        try:
            await self._serve(reader, writer)
        except (OSError, h11.ProtocolError, asyncio.CancelledError, ssl.SSLError):
            pass
        finally:
            self._tasks.discard(task)
            writer.close()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection = h11.Connection(h11.SERVER)
        target = ""
        headers: dict[str, str] = {}
        body = bytearray()
        while True:
            event = connection.next_event()
            if event is h11.NEED_DATA:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                connection.receive_data(chunk)
            elif isinstance(event, h11.Request):
                target = event.target.decode()
                headers = {k.decode().lower(): v.decode() for k, v in event.headers}
            elif isinstance(event, h11.Data):
                body += event.data
            elif isinstance(event, h11.EndOfMessage):
                break
        valid = self._check(target, headers, bytes(body))
        try:
            payload = json.loads(body)
        except ValueError:
            payload = {}
        self.seen.append(
            Seen(target, headers, payload, valid, headers.get("x-onionglass-nonce", ""))
        )
        await self._answer(connection, writer, target, headers, payload, valid)

    def _check(self, path: str, headers: dict[str, str], body: bytes) -> bool:
        try:
            key_id = headers["x-onionglass-key"]
            timestamp = headers["x-onionglass-timestamp"]
            nonce = headers["x-onionglass-nonce"]
            if key_id != self.gateway_key_id or headers.get("x-onionglass-version") != "1":
                return False
            if abs(time.time() - int(timestamp)) > 60 or nonce in self._nonces:
                return False
            if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
                return False
            self.gateway_public.verify(
                unb64(headers["x-onionglass-signature"]),
                request_base(key_id, path, timestamp, nonce, body),
            )
        except (KeyError, ValueError, InvalidSignature):
            return False
        self._nonces.add(nonce)
        return True

    async def _answer(  # noqa: PLR0917 - one connection's worth of state
        self,
        connection: h11.Connection,
        writer: asyncio.StreamWriter,
        path: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        valid: bool,
    ) -> None:
        nonce = headers.get("x-onionglass-nonce", "")
        mode = self.mode
        if mode == "hang":
            await asyncio.sleep(60)
        if mode == "close":
            return
        status = 200 if valid else 401
        reply = self.handler(path, payload) if valid else {"error": "bad signature"}
        body = json.dumps(reply).encode()
        if mode == "garbage":
            body = b"not json at all"
        elif mode == "list":
            body = b"[1,2,3]"
        elif mode == "huge":
            body = json.dumps({"allow": True, "pad": "x" * 100_000}).encode()
        if mode in ("status500", "status404", "redirect"):
            status = {"status500": 500, "status404": 404, "redirect": 302}[mode]
        key_id, signed_nonce, signed_body = self.service_key_id, nonce, body
        reply_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"connection", b"close"),
        ]
        if mode == "redirect":
            reply_headers.append((b"location", b"http://evil.example/"))
        if mode == "wrong_nonce":
            signed_nonce = "0" * 32
        if mode == "tampered":
            signed_body = body + b" "  # signed something other than what is sent
        signature = self.service_signer.sign(
            response_base(key_id, signed_nonce, status, signed_body)
        )
        if mode == "bad_signature":
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        if mode == "unknown_key":
            key_id = "nobody"
        if mode != "unsigned":
            reply_headers += [
                (b"x-onionglass-key", key_id.encode()),
                (b"x-onionglass-signature", b64(signature).encode()),
            ]
        writer.write(connection.send(h11.Response(status_code=status, headers=reply_headers)))
        writer.write(connection.send(h11.Data(data=body)))
        writer.write(connection.send(h11.EndOfMessage()))
        await writer.drain()


def make_certificate(
    directory: Path, names: tuple[str, ...] = ("localhost",), *, with_ip: bool = True
) -> tuple[Path, Path]:
    """A self-signed certificate that a client can trust as its own authority."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(UTC)
    alternatives: list[x509.GeneralName] = [x509.DNSName(n) for n in names]
    if with_ip:
        alternatives.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path
