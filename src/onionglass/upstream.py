# SPDX-License-Identifier: AGPL-3.0-only
"""Fetching a page from an onion site through Tor.

Everything about talking to the onion site is in this module, and it is deliberately narrow:

* P5: it only connects to a validated onion origin, and refuses anything else
* P4: it sends only an allowlisted set of headers, built by ``headers.upstream_request_headers``
* every request gets its own isolation credential, so visitors never share a Tor circuit
* it never follows redirects. Each hop goes back through the gateway's policy checks
* size and time limits apply to every part of the exchange
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field

import h11
from cryptography import x509

from onionglass.headers import ALLOWED_METHODS, authority
from onionglass.onion import OnionOrigin
from onionglass.socks import SocksError, socks5_connect

_ALLOWED_REQUEST_HEADERS = frozenset(
    {
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "cookie",
        "referer",
        "origin",
        "content-type",
    }
)
_ISOLATION_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_READ_SIZE = 65536
_CLOSE_WAIT_SECONDS = 2.0


class UpstreamError(Exception):
    """The onion site could not be fetched. ``kind`` says why, for the error page and the log."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class TorConfig:
    socks_host: str = "127.0.0.1"
    socks_ports: tuple[int, ...] = (9050,)
    proxy_connect_timeout: float = 10.0
    connect_timeout: float = 60.0
    read_timeout: float = 60.0
    total_timeout: float = 120.0
    max_body_bytes: int = 25_000_000
    max_request_body_bytes: int = 10_000_000
    max_header_bytes: int = 65_536
    min_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    def __post_init__(self) -> None:
        if not self.socks_ports:
            raise ValueError("at least one SOCKS port is needed")


@dataclass(frozen=True, slots=True)
class TlsInfo:
    """What the onion site's certificate looked like. It is recorded, never trusted."""

    protocol: str
    cipher: str
    fingerprint_sha256: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    self_signed: bool


@dataclass(frozen=True, slots=True)
class UpstreamRequest:
    origin: OnionOrigin
    method: str
    target: str
    headers: Mapping[str, str]
    isolation_key: str
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed: float
    tls: TlsInfo | None = field(default=None)

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key == lowered:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers if key == lowered]


def _validate(request: UpstreamRequest, config: TorConfig) -> dict[str, str]:
    """Check a request before anything is sent. Returns the validated headers."""
    if request.method not in ALLOWED_METHODS:
        raise UpstreamError("bad_request")
    target = request.target
    clean = target.isascii() and not any(ord(c) <= 0x20 or ord(c) == 0x7F for c in target)
    if not target.startswith("/") or not clean or len(target) > 8192:
        raise UpstreamError("bad_request")
    if not request.origin.host.hostname.endswith(".onion"):
        raise UpstreamError("bad_request")
    if not request.isolation_key or not set(request.isolation_key) <= _ISOLATION_CHARS:
        raise UpstreamError("bad_request")
    if len(request.isolation_key) > 200:
        raise UpstreamError("bad_request")
    if request.body and request.method != "POST":
        raise UpstreamError("bad_request")
    if len(request.body) > config.max_request_body_bytes:
        raise UpstreamError("too_large")
    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        lowered = name.lower()
        bad_value = not value.isascii() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
        if lowered not in _ALLOWED_REQUEST_HEADERS or bad_value:
            raise UpstreamError("bad_request")
        headers[lowered] = value
    if headers.get("host") != authority(request.origin):
        raise UpstreamError("bad_request")
    return headers


def _tls_context(config: TorConfig) -> ssl.SSLContext:
    # Onion sites authenticate by their address, so a certificate chain proves nothing here. The
    # certificate is still recorded as evidence.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = config.min_tls_version
    return context


def _tls_info(writer: asyncio.StreamWriter) -> TlsInfo | None:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    der = ssl_object.getpeercert(binary_form=True)
    cipher = ssl_object.cipher()
    if not der:
        return None
    certificate = x509.load_der_x509_certificate(der)
    return TlsInfo(
        protocol=str(ssl_object.version()),
        cipher=str(cipher[0]) if cipher else "",
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        not_before=certificate.not_valid_before_utc.isoformat(),
        not_after=certificate.not_valid_after_utc.isoformat(),
        self_signed=certificate.subject == certificate.issuer,
    )


class TorFetcher:
    """Fetches pages from onion sites through one or more local Tor SOCKS ports."""

    def __init__(self, config: TorConfig | None = None) -> None:
        self._config = config or TorConfig()

    def _port_for(self, isolation_key: str) -> int:
        ports = self._config.socks_ports
        return ports[zlib.crc32(isolation_key.encode("ascii")) % len(ports)]

    async def fetch(
        self, request: UpstreamRequest, *, max_body_bytes: int | None = None
    ) -> UpstreamResponse:
        headers = _validate(request, self._config)
        limit = self._config.max_body_bytes if max_body_bytes is None else max_body_bytes
        started = time.monotonic()
        writer: asyncio.StreamWriter | None = None
        tls: TlsInfo | None = None
        try:
            async with asyncio.timeout(self._config.total_timeout):
                reader, writer = await socks5_connect(
                    request.origin.host.hostname,
                    request.origin.port,
                    proxy_host=self._config.socks_host,
                    proxy_port=self._port_for(request.isolation_key),
                    username=f"og-{request.isolation_key}",
                    proxy_connect_timeout=self._config.proxy_connect_timeout,
                    connect_timeout=self._config.connect_timeout,
                )
                if request.origin.scheme == "https":
                    try:
                        await writer.start_tls(
                            _tls_context(self._config),
                            server_hostname=request.origin.host.hostname,
                        )
                    except (ssl.SSLError, OSError) as exc:
                        raise UpstreamError("tls_failed") from exc
                    tls = _tls_info(writer)
                status, reason, response_headers, body = await self._exchange(
                    reader, writer, request, headers, limit
                )
        except SocksError as exc:
            raise UpstreamError(exc.kind) from exc
        except TimeoutError as exc:
            raise UpstreamError("timeout") from exc
        finally:
            if writer is not None:
                writer.close()
                # Waiting for the close is bounded: on some platforms a connection reset leaves
                # the "closed" signal unsent, and a fetch must never hang on that.
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), timeout=_CLOSE_WAIT_SECONDS)
        return UpstreamResponse(
            status=status,
            reason=reason,
            headers=response_headers,
            body=body,
            elapsed=time.monotonic() - started,
            tls=tls,
        )

    async def _exchange(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: UpstreamRequest,
        headers: Mapping[str, str],
        limit: int,
    ) -> tuple[int, str, tuple[tuple[str, str], ...], bytes]:
        connection = h11.Connection(
            h11.CLIENT, max_incomplete_event_size=self._config.max_header_bytes
        )
        wire = [(name.encode("ascii"), value.encode("ascii")) for name, value in headers.items()]
        wire.append((b"connection", b"close"))
        if request.body:
            wire.append((b"content-length", str(len(request.body)).encode("ascii")))
        try:
            writer.write(
                connection.send(
                    h11.Request(
                        method=request.method.encode("ascii"),
                        target=request.target.encode("ascii"),
                        headers=wire,
                    )
                )
            )
            if request.body:
                writer.write(connection.send(h11.Data(data=request.body)))
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
        except (h11.LocalProtocolError, OSError) as exc:
            raise UpstreamError("bad_request") from exc
        status = 0
        reason = ""
        response_headers: tuple[tuple[str, str], ...] = ()
        chunks: list[bytes] = []
        size = 0
        while True:
            try:
                event = connection.next_event()
            except h11.RemoteProtocolError as exc:
                raise UpstreamError("protocol_error") from exc
            if event is h11.NEED_DATA:
                try:
                    data = await asyncio.wait_for(
                        reader.read(_READ_SIZE), timeout=self._config.read_timeout
                    )
                except TimeoutError as exc:
                    raise UpstreamError("timeout") from exc
                except (ConnectionError, ssl.SSLError, OSError) as exc:
                    raise UpstreamError("connection_closed") from exc
                connection.receive_data(data)
            elif isinstance(event, h11.InformationalResponse):
                continue
            elif isinstance(event, h11.Response):
                status = event.status_code
                reason = event.reason.decode("latin-1")
                response_headers = tuple(
                    (name.decode("latin-1").lower(), value.decode("latin-1"))
                    for name, value in event.headers
                )
            elif isinstance(event, h11.Data):
                size += len(event.data)
                if size > limit:
                    raise UpstreamError("too_large")
                chunks.append(bytes(event.data))
            elif isinstance(event, h11.EndOfMessage):
                return status, reason, response_headers, b"".join(chunks)
            elif isinstance(event, h11.ConnectionClosed):
                raise UpstreamError("connection_closed")
