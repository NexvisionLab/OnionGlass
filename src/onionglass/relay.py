# SPDX-License-Identifier: AGPL-3.0-only
"""An entry relay: a small forwarder that stands in front of a hidden gateway.

A censor blocks by address and by domain. One gateway has one address. A relay is something an
operator can put on many cheap hosts, point the entry domain at, and throw away when one is
blocked. The gateway stays out of sight and answers only requests a relay has signed.

What a relay does, and nothing else:

* It accepts a request only for the domains it was set up for, and answers any other host as a
  missing page, so it is not an open door to the gateway.
* It signs each request with its own key (``relayauth.py``) and sends it on over an encrypted
  connection to the gateway, which it checks against a pinned fingerprint.
* It sends the reply back unchanged, a piece at a time.

What it must not do, and the tests hold it to:

* Pass on anything that names the visitor. The gateway never learns a visitor's address, and the
  relay writes none in a log.
* Keep anything. It has no session, no cookie jar and no cache. Restarting it loses nothing.

A relay that ends the visitor's TLS can read every page, because the pages are plain HTTPS. It
must therefore be run by the operator and never by a volunteer (``docs/relays.md``).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import logging
import ssl
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any

import h11

from onionglass.cover import NOT_FOUND_PAGE
from onionglass.headers import HeaderPolicy, cover_headers
from onionglass.hosts import GatewayHosts
from onionglass.relayauth import CHECK_HEADER, RelaySigner
from onionglass.relayauth import HEADER as RELAY_HEADER

_log = logging.getLogger("onionglass.relay")

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"})
MAX_TARGET_CHARS = 8192
MAX_HEADERS = 100
MAX_HEADER_BYTES = 16_384
MAX_HEAD_BYTES = 65_536
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_IDLE_TIMEOUT = 60.0
DEFAULT_MAX_REQUEST_SECONDS = 300.0
_READ_CHUNK = 65_536
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
_SHUTDOWN_SECONDS = 3.0  # how long to wait for the gateway to finish closing a TLS connection
# What belongs to one connection and not to the message, so it is never passed on.
_HOP_BY_HOP = frozenset(
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
        "te", "trailer", "transfer-encoding", "upgrade",
    }
)  # fmt: skip
# The request headers a relay passes on: the ones an ordinary browser sends, and nothing else.
# A list of what is allowed cannot be got round by a header nobody thought of, which a list of
# what is forbidden can. Nothing here names the visitor, and the gateway reads few of them.
_ALLOWED = frozenset(
    {
        "accept", "accept-encoding", "accept-language", "cache-control", "content-type", "cookie",
        "dnt", "if-match", "if-modified-since", "if-none-match", "if-range", "if-unmodified-since",
        "origin", "pragma", "priority", "range", "referer", "sec-gpc", "upgrade-insecure-requests",
        "user-agent",
    }
)  # fmt: skip
_ALLOWED_PREFIXES = ("sec-fetch-", "sec-ch-")
# What the gateway's own server adds. The relay's server adds its own, so these are not repeated.
_REPLY_DROPPED = _HOP_BY_HOP | {"server", "date", "via", "alt-svc"}


def _page(status: int, title: str) -> bytes:
    return (
        f"<html><head><title>{status} {title}</title></head><body><h1>{title}</h1></body></html>"
    ).encode("ascii")


# What the relay says for itself. A request it cannot forward as asked, such as a malformed target
# or a body over the limit, is not on this list: it gets the missing page that the gateway gives
# a stranger, so that one probe cannot tell a relay from the gateway behind it. What is here takes
# a slow visitor or a crowd to bring about, and says so.
_PAGES = {
    408: _page(408, "Request Timeout"),
    429: _page(429, "Too Many Requests"),
    502: _page(502, "Bad Gateway"),
    503: _page(503, "Service Unavailable"),
}


@dataclass(frozen=True, slots=True)
class _Request:
    """A visitor's request, ready to send on: what is asked for, the headers to send, and how the
    body is framed (``"length"``, ``"chunked"`` or None)."""

    method: str
    target: str
    headers: list[tuple[bytes, bytes]]
    body: str | None


@dataclass(frozen=True, slots=True)
class Origin:
    """Where the gateway is, and how to know it is the gateway."""

    host: str
    port: int
    tls: bool = True
    # The gateway certificate's SHA-256, as lower-case hex. Several may be given, and any one of
    # them will do, so that a certificate can be renewed by adding the new fingerprint to every
    # relay first and taking the old one out afterwards.
    pin_sha256: str | tuple[str, ...] | None = None
    allow_plain: bool = False  # an unencrypted hop, only for a network the operator trusts
    pins: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        if not _valid_host(self.host) or not 1 <= self.port <= 65535:
            raise ValueError("the origin needs a host that is a name or an address, and a port")
        given = self.pin_sha256
        pins = () if given is None else (given,) if isinstance(given, str) else tuple(given)
        if given is not None and (not pins or not all(_valid_pin(pin) for pin in pins)):
            raise ValueError("pin_sha256 is 64 lower-case hexadecimal digits, or a list of them")
        if self.tls and given is None:
            raise ValueError("an https origin needs pin_sha256, 64 hexadecimal digits")
        if not self.tls and not (self.allow_plain or is_loopback(self.host)):
            raise ValueError(
                "an unencrypted origin is only allowed on this machine, unless allow_plain is "
                "set for a network you trust"
            )
        object.__setattr__(self, "pins", pins)


def _valid_pin(pin: str) -> bool:
    return len(pin) == 64 and all(char in "0123456789abcdef" for char in pin)


def _valid_host(host: str) -> bool:
    """A name made of letters, digits and dashes in labels, or an address. Nothing else, so that
    what is written into a file and handed to the resolver is what it looks like."""
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return True
    if not host or len(host) > 253:
        return False
    return all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and all(char.isascii() and (char.isalnum() or char == "-") for char in label)
        for label in host.split(".")
    )


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class RelaySettings:
    domains: tuple[str, ...]
    origin: Origin
    signer: RelaySigner
    max_concurrent: int = 200
    max_per_client: int = 20
    max_request_body: int = 1_000_000
    max_response_body: int = 200_000_000
    max_request_seconds: float = DEFAULT_MAX_REQUEST_SECONDS
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT
    trust_forwarded: bool = False  # take the visitor's address for limits from a proxy in front

    def __post_init__(self) -> None:
        if not self.domains:
            raise ValueError("a relay needs at least one domain")
        for domain in self.domains:
            GatewayHosts(domain)  # raises ValueError for a domain that is not acceptable
        counts = (self.max_concurrent, self.max_per_client, self.max_request_body)
        if any(not 1 <= number <= 100_000_000 for number in counts):
            raise ValueError("a relay limit is out of range")
        if not 1 <= self.max_response_body <= 10_000_000_000:
            raise ValueError("max_response_body is out of range")
        if not (0 < self.connect_timeout <= 120 and 0 < self.idle_timeout <= 600):
            raise ValueError("a relay timeout is out of range")
        if not 0 < self.max_request_seconds <= 3600:
            raise ValueError("max_request_seconds is out of range")


class _Refuse(Exception):
    """A request the relay answers itself, with this status."""

    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _Failed(Exception):
    """The gateway could not be reached or did not answer as a web server does."""


class _Gone(Exception):
    """The visitor went away, so there is nobody to answer."""


class _VisitorSlow(Exception):
    """The visitor did not take the answer in time, which is the visitor's doing."""


class ConnectionAbort(Exception):
    """Raised when an answer has begun and cannot be finished. It makes the server drop the
    visitor's connection, where ending the answer would make half a page look like all of it."""


@dataclass
class _Hop:
    """The connection to the gateway for one request, and how far the request has got."""

    connection: h11.Connection
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    body_sent: bool = False


def _tls_context() -> ssl.SSLContext:
    # The gateway proves itself by its pinned fingerprint, so there is no chain to check. That is
    # also why a certificate the operator made for the purpose is fine.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class Relay:
    """The ASGI application. Hand it to a server that ends TLS, or run it behind one."""

    def __init__(self, settings: RelaySettings) -> None:
        self.settings = settings
        self._context = _tls_context() if settings.origin.tls else None
        self._policy = HeaderPolicy("https", settings.domains[0])
        self._active = 0
        self._by_client: dict[str, int] = {}

    def busy(self) -> tuple[int, int]:
        """How many requests are in flight, and for how many visitors. For tests and metrics."""
        return self._active, len(self._by_client)

    # --- the server's entry point ----------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "lifespan":
            await self._lifespan(receive, send)
        elif kind == "http":
            await self._http(scope, receive, send)
        else:  # a web socket, which the gateway does not use
            await send({"type": "websocket.close", "code": 1008})

    @staticmethod
    async def _lifespan(receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    # --- one request -----------------------------------------------------------------------

    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            host = self._served_host(scope)
            method = scope["method"]
            if method not in METHODS:
                raise _Refuse(404)
            target = _target(scope)
            body = _framing(scope, self.settings.max_request_body)
            headers = _forwarded(scope, host, (method, target), self.settings.signer, body)
            request = _Request(method, target, headers, body)
        except _Refuse as refusal:
            await self._answer(send, refusal.status)
            return
        client = self._client(scope)
        if self._active >= self.settings.max_concurrent:
            await self._answer(send, 503, retry_after=5)
            return
        if self._by_client.get(client, 0) >= self.settings.max_per_client:
            await self._answer(send, 429, retry_after=5)
            return
        self._active += 1
        self._by_client[client] = self._by_client.get(client, 0) + 1
        try:
            await self._exchange(receive, send, request)
        finally:
            self._active -= 1
            left = self._by_client[client] - 1
            if left:
                self._by_client[client] = left
            else:
                del self._by_client[client]

    def _served_host(self, scope: Scope) -> str:
        """The ``Host`` the visitor asked for, if it is one of this relay's domains or a name under
        one. Anything else is a missing page, and nothing is sent on."""
        values = [v for k, v in scope["headers"] if k == b"host"]
        if len(values) != 1:
            raise _Refuse(404)
        try:
            host: str = values[0].decode("ascii")
        except UnicodeDecodeError:
            raise _Refuse(404) from None
        name, separator, port = host.rpartition(":")
        if not separator:
            name = host
        elif not port.isdigit() or len(port) > 5:
            raise _Refuse(404)
        name = name.lower().removesuffix(".")
        if not set(name) <= _HOST_CHARS:  # a name has letters, digits, dots and dashes, no more
            raise _Refuse(404)
        for domain in self.settings.domains:
            if name == domain or name.endswith("." + domain):
                return host
        raise _Refuse(404)

    def _client(self, scope: Scope) -> str:
        """Who is asking, for the limits only. It is held while the request lasts and is never
        written anywhere or passed on."""
        peer = scope.get("client")
        address = str(peer[0]) if peer else "unknown"
        if self.settings.trust_forwarded and is_loopback(address):
            # The proxy writes the visitor's address at the end, so the last line, and the last
            # address on it, is the proxy's own word. Anything before it came from the visitor.
            lines = [v for k, v in scope["headers"] if k == b"x-forwarded-for"]
            if lines:
                last = lines[-1].decode("latin-1").split(",")[-1].strip()
                if _parse_address(last) is not None:
                    return _bucket(last)
        return _bucket(address)

    async def _answer(self, send: Send, status: int, *, retry_after: int | None = None) -> None:
        if status in (400, 413):
            status = 404
        page = NOT_FOUND_PAGE if status == 404 else _PAGES[status]
        headers = {name.lower(): value for name, value in cover_headers(self._policy).items()}
        headers["content-length"] = str(len(page))
        if retry_after is not None:
            headers["retry-after"] = str(retry_after)
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(k.encode("ascii"), v.encode("ascii")) for k, v in headers.items()],
            }
        )
        await send({"type": "http.response.body", "body": page, "more_body": False})

    # --- the hop to the gateway ------------------------------------------------------------

    async def _exchange(self, receive: Receive, send: Send, request: _Request) -> None:
        started = False
        hop: _Hop | None = None
        try:
            async with asyncio.timeout(self.settings.max_request_seconds):
                hop = await self._connect()
                reply = await self._request_and_head(hop, receive, request)
                started = True
                await self._give(
                    send,
                    {
                        "type": "http.response.start",
                        "status": reply.status_code,
                        "headers": _reply_headers(list(reply.headers)),
                    },
                )
                await self._unless_visitor_leaves(self._pass_body(hop, send), receive)
        except _Gone:
            pass  # nobody is there to answer, and there is nothing to say about it
        except (
            _Refuse,
            _VisitorSlow,
            _Failed,
            h11.ProtocolError,
            OSError,
            TimeoutError,
            UnicodeError,
            asyncio.IncompleteReadError,
        ) as error:
            # What is only the visitor's doing is not worth a line: a slow reader, a stalled upload,
            # a request that took longer than the total time. A line is for the gateway's faults.
            visitor = isinstance(error, _Refuse | _VisitorSlow) or (
                isinstance(error, TimeoutError)
                and hop is not None
                and (started or not hop.body_sent)
            )
            if not visitor:
                _log.warning("the gateway could not be reached or gave a bad answer")
            if started:  # the answer has begun and cannot be taken back, so cut it off
                raise ConnectionAbort from None
            if isinstance(error, _Refuse):
                await self._answer(send, error.status)
            else:
                await self._answer(send, 408 if visitor else 502)
        finally:
            if hop is not None:
                await _close(hop)

    async def _give(self, send: Send, message: dict[str, Any]) -> None:
        """Hand the visitor's server a piece of the answer. A visitor who does not take it within
        the idle time is not served any more, so that nobody can hold a place by not reading."""
        try:
            await asyncio.wait_for(send(message), self.settings.idle_timeout)
        except TimeoutError:
            raise _VisitorSlow from None

    async def _connect(self) -> _Hop:
        origin = self.settings.origin
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    origin.host,
                    origin.port,
                    ssl=self._context,
                    ssl_shutdown_timeout=_SHUTDOWN_SECONDS if self._context is not None else None,
                ),
                self.settings.connect_timeout,
            )
        except TimeoutError:
            raise _Failed from None
        if origin.tls:
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
            seen = hashlib.sha256(der).hexdigest() if der else ""
            if not any(hmac.compare_digest(seen, pin) for pin in origin.pins):
                writer.close()
                _log.warning("the gateway's certificate is not the one that was pinned")
                raise _Failed
        connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=MAX_HEAD_BYTES)
        return _Hop(connection, reader, writer)

    async def _request_and_head(self, hop: _Hop, receive: Receive, request: _Request) -> Any:
        """Send the request, and read the gateway's answer as soon as it begins.

        A gateway may answer before it has read a large upload, and then close, so the answer is
        listened for while the upload goes on. But a gateway says nothing until it has the whole
        body, so no idle clock runs on its silence while the visitor is still sending: a slow
        upload that keeps coming is not a fault. The clock starts when the upload is over.
        """
        sender = asyncio.ensure_future(self._send_request(hop, receive, request))
        first = asyncio.ensure_future(hop.reader.read(_READ_CHUNK))
        try:
            await asyncio.wait({sender, first}, return_when=asyncio.FIRST_COMPLETED)
            if not first.done():
                error = sender.exception()
                if error is not None and not isinstance(error, OSError):
                    raise error
                # Sent, or the gateway shut the connection while it was being sent. Either way
                # its answer is what is left to wait for, and the visitor may leave meanwhile.
                if await self._unless_visitor_leaves(self._within_idle(first), receive):
                    raise _Gone
            hop.connection.receive_data(first.result())
            return await self._read_head(hop)
        finally:
            for task in (sender, first):
                if not task.done():
                    task.cancel()
            await asyncio.gather(sender, first, return_exceptions=True)

    async def _within_idle(self, waiting: asyncio.Future[bytes]) -> None:
        """Wait for something the gateway has not said yet, for as long as the idle time."""
        try:
            await asyncio.wait_for(waiting, self.settings.idle_timeout)
        except TimeoutError:
            raise _Failed from None

    async def _unless_visitor_leaves(self, work: Awaitable[None], receive: Receive) -> bool:
        """Do the work, but stop at once if the visitor goes, so that the relay does not go on
        pulling an answer from the gateway for nobody. True if the visitor went first."""
        job = asyncio.ensure_future(work)
        watcher = asyncio.ensure_future(_wait_for_disconnect(receive))
        try:
            await asyncio.wait({job, watcher}, return_when=asyncio.FIRST_COMPLETED)
            if job.done():
                job.result()  # raises what went wrong, if anything did
                return False
            return True
        finally:
            for task in (job, watcher):
                if not task.done():
                    task.cancel()
            await asyncio.gather(job, watcher, return_exceptions=True)

    async def _flush(self, hop: _Hop) -> None:
        try:
            await asyncio.wait_for(hop.writer.drain(), self.settings.idle_timeout)
        except TimeoutError:
            raise _Failed from None  # the gateway is not taking what is sent

    async def _send_request(self, hop: _Hop, receive: Receive, request: _Request) -> None:
        try:
            pending: bytes | None = hop.connection.send(
                h11.Request(method=request.method, target=request.target, headers=request.headers)
            )
        except h11.LocalProtocolError:
            raise _Refuse(400) from None
        # The head waits for the first piece of the body and goes with it in one write. A gateway
        # that answers at once and closes then has no part of the request left unread, which would
        # make the connection reset and the answer lost on its way back.
        received = 0
        while request.body is not None:
            try:  # a visitor who goes quiet must not hold a place for ever
                message = await asyncio.wait_for(receive(), self.settings.idle_timeout)
            except TimeoutError:
                raise _Refuse(408) from None
            if message["type"] != "http.request":
                raise _Gone
            data = message.get("body", b"")
            received += len(data)
            if received > self.settings.max_request_body:
                raise _Refuse(413)
            if data:
                pending = (pending or b"") + (hop.connection.send(h11.Data(data=data)) or b"")
            if pending:
                hop.writer.write(pending)
                pending = None
                await self._flush(hop)
            if not message.get("more_body", False):
                break
        hop.writer.write((pending or b"") + (hop.connection.send(h11.EndOfMessage()) or b""))
        await self._flush(hop)
        hop.body_sent = True

    async def _next(self, hop: _Hop) -> Any:
        """The next thing the gateway said, reading more from it when needed."""
        while True:
            event = hop.connection.next_event()
            if event is not h11.NEED_DATA:
                return event
            try:
                data = await asyncio.wait_for(
                    hop.reader.read(_READ_CHUNK), self.settings.idle_timeout
                )
            except TimeoutError:
                raise _Failed from None  # the gateway went quiet
            hop.connection.receive_data(data)

    async def _read_head(self, hop: _Hop) -> h11.Response:
        while True:
            event = await self._next(hop)
            if isinstance(event, h11.Response):
                # h11 limits a head that is still incomplete, but one large read can finish it.
                if sum(len(k) + len(v) for k, v in event.headers) > MAX_HEAD_BYTES:
                    raise _Failed
                names = {k for k, _ in event.headers}
                if b"content-length" in names and b"transfer-encoding" in names:
                    raise _Failed  # two ways to say where the body ends, so neither is believed
                return event
            if not isinstance(event, h11.InformationalResponse):  # h11 itself stops at a 101
                raise _Failed

    async def _pass_body(self, hop: _Hop, send: Send) -> None:
        passed = 0
        while True:
            event = await self._next(hop)
            if isinstance(event, h11.Data):
                passed += len(event.data)
                if passed > self.settings.max_response_body:
                    raise _Failed
                await self._give(
                    send,
                    {"type": "http.response.body", "body": bytes(event.data), "more_body": True},
                )
            elif isinstance(event, h11.EndOfMessage):
                end = {"type": "http.response.body", "body": b"", "more_body": False}
                await self._give(send, end)
                return
            else:
                raise _Failed


async def _close(hop: _Hop) -> None:
    """Close the connection to the gateway without waiting for ever. A gateway that has stopped
    reading leaves data in the buffer, and closing then waits for it to be taken."""
    transport = hop.writer.transport
    if transport.get_write_buffer_size():
        transport.abort()
    else:
        hop.writer.close()
    with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
        await asyncio.wait_for(hop.writer.wait_closed(), _SHUTDOWN_SECONDS)
    transport.abort()  # nothing more to wait for, whatever the gateway does


async def _wait_for_disconnect(receive: Receive) -> None:
    """Return when the visitor's connection is gone. Anything else the server says is ignored."""
    while True:
        if (await receive())["type"] == "http.disconnect":
            return


def _target(scope: Scope) -> str:
    """The path and query as the visitor sent them. Only plain printable ASCII goes on."""
    raw = scope.get("raw_path")
    path = bytes(raw) if raw else str(scope["path"]).encode("utf-8", "replace")
    query = scope.get("query_string", b"")
    joined = path + (b"?" + bytes(query) if query else b"")
    try:
        target = joined.decode("ascii")
    except UnicodeDecodeError:
        raise _Refuse(400) from None
    if (
        not target.startswith("/")
        or target.startswith("//")
        or len(target) > MAX_TARGET_CHARS
        or any(not "!" <= char <= "~" for char in target)
    ):
        raise _Refuse(400)
    return target


def _framing(scope: Scope, limit: int) -> str | None:
    """How the visitor's body is framed: ``"length"``, ``"chunked"`` or None for no body. A
    body that is too large is refused before anything is sent on."""
    lengths = [v for k, v in scope["headers"] if k == b"content-length"]
    chunked = any(
        k == b"transfer-encoding" and b"chunked" in v.lower() for k, v in scope["headers"]
    )
    if len(lengths) > 1 or (lengths and chunked):
        raise _Refuse(400)
    if lengths:
        text = lengths[0].decode("ascii", "replace")
        if not text.isascii() or not text.isdigit() or len(text) > 12:
            raise _Refuse(400)
        if int(text) > limit:
            raise _Refuse(413)
        return "length" if int(text) else None
    return "chunked" if chunked else None


def _forwarded(
    scope: Scope,
    host: str,
    line: tuple[str, str],
    signer: RelaySigner,
    body: str | None,
) -> list[tuple[bytes, bytes]]:
    """The headers to send on: the visitor's ordinary browser headers and nothing else, with the
    host kept as asked and the signature added. ``line`` is the method and the target."""
    raw: list[tuple[bytes, bytes]] = list(scope["headers"])
    if len(raw) > MAX_HEADERS or any(len(k) + len(v) > MAX_HEADER_BYTES for k, v in raw):
        raise _Refuse(400)
    kept: list[tuple[bytes, bytes]] = []
    for key, value in raw:
        name = key.decode("latin-1").lower()
        if name in _ALLOWED or name.startswith(_ALLOWED_PREFIXES):
            kept.append((name.encode("latin-1"), value))
    try:
        signature = signer.sign(line[0], host, line[1])
    except ValueError:
        raise _Refuse(400) from None
    kept.append((b"host", host.encode("ascii")))
    kept.append((RELAY_HEADER.encode("ascii"), signature.encode("ascii")))
    kept.append((b"connection", b"close"))
    if scope.get("onionglass.check"):  # only the operator's own check sets this, never a visitor
        kept.append((CHECK_HEADER.encode("ascii"), b"1"))
    if body == "chunked":
        kept.append((b"transfer-encoding", b"chunked"))
    elif body == "length":
        length = next(v for k, v in scope["headers"] if k == b"content-length")
        kept.append((b"content-length", length))
    elif line[0] in ("POST", "PUT", "PATCH"):
        kept.append((b"content-length", b"0"))  # some servers answer 411 to a post with no length
    return kept


def _parse_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _bucket(address: str) -> str:
    """Who counts as one visitor for the limits. An IPv4 address written in its IPv6 form is the
    same visitor, and so is anyone in the same IPv6 network of 2**64 addresses, which is what one
    subscriber is given, so that no one gets a new allowance by changing the end of an address."""
    parsed = _parse_address(address)
    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        return str(ipaddress.ip_network(f"{parsed}/64", strict=False))
    return str(parsed) if parsed is not None else address


def _reply_headers(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    named = {
        token.strip().lower()
        for key, value in headers
        if key.lower() == b"connection"
        for token in value.decode("latin-1").split(",")
    }
    return [
        (key.lower(), value)
        for key, value in headers
        if key.decode("latin-1").lower() not in _REPLY_DROPPED
        and key.decode("latin-1").lower() not in named
    ]


async def probe(relay: Relay, host: str, target: str) -> tuple[int, bytes]:
    """Ask for one page the way a visitor would, through the relay's own code, and return the
    status and the body. It is how an operator checks that the gateway knows the relay."""
    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": target,
        "raw_path": target.encode("ascii"),
        "query_string": b"",
        "headers": [(b"host", host.encode("ascii"))],
        "client": ("127.0.0.1", 0),
        "onionglass.check": True,
    }
    status = 0
    body = bytearray()

    async def receive() -> dict[str, Any]:
        await asyncio.Event().wait()  # this visitor stays until the answer has come
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
        else:
            body.extend(message.get("body", b""))

    await relay(scope, receive, send)
    return status, bytes(body)
