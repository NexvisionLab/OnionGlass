# SPDX-License-Identifier: AGPL-3.0-only
"""Signed HTTP hooks: policy, audit and quota served by another program.

The built-in policy, audit log and quota meter are enough for one person or a small team. An
operator who already has accounts, a case system or a rule service can run those three as a
separate service and have the gateway ask it over HTTP. The service is a different program: the
gateway never loads its code, so nothing here makes it part of this one.

Both directions are signed with Ed25519, and a request that is not signed correctly, or a reply
that is not, is refused. A reply is checked because a policy that says "allow" is the one answer an
attacker on the network would most like to forge.

Request (POST, JSON, ``Connection: close``)::

    X-Onionglass-Version:    1
    X-Onionglass-Key:        <key id of the gateway's signing key>
    X-Onionglass-Timestamp:  <seconds since the epoch>
    X-Onionglass-Nonce:      <32 hex characters, new for every request>
    X-Onionglass-Signature:  <unpadded base64url Ed25519 signature>

The signature covers, one per line: the request context string, the key id, the method, the path,
the timestamp, the nonce and the SHA-256 of the body in hex. The receiver should reject a
timestamp more than a minute out and a nonce it has seen.

Reply (status 200, JSON, at most 64 KiB)::

    X-Onionglass-Key:        <key id of the service's signing key>
    X-Onionglass-Signature:  <unpadded base64url Ed25519 signature>

The reply signature covers the reply context string, the key id, the request's nonce, the status
and the SHA-256 of the body. Tying it to the nonce stops a recorded "allow" being played back for
a different question.

If a hook cannot be reached, answers late, answers wrongly or answers without a valid signature,
the gateway refuses the request. There is no fallback to the built-in policy.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import json
import secrets
import ssl
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

import h11
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onionglass.audit import ADDRESS_FORMS, AddressForm, AuditEvent, in_address_form
from onionglass.policy import Decision, PolicyRequest
from onionglass.tickets import KeyRing, is_valid_key_id

HOOK_VERSION = 1
REQUEST_CONTEXT = b"onionglass hook request v1\x00"
RESPONSE_CONTEXT = b"onionglass hook response v1\x00"
MAX_RESPONSE_BYTES = 65_536
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
_RULE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
MAX_RULE = 64


class HookError(Exception):
    """A hook could not be used. The gateway treats every kind of failure the same way."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    if not text.isascii() or len(text) > 200:
        raise HookError("bad signature encoding")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise HookError("bad signature encoding") from exc


def request_signing_input(  # noqa: PLR0913, PLR0917 - the six things the signature covers
    key_id: str, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    lines = [key_id, method, path, timestamp, nonce, hashlib.sha256(body).hexdigest()]
    return REQUEST_CONTEXT + "\n".join(lines).encode("utf-8")


def response_signing_input(key_id: str, nonce: str, status: int, body: bytes) -> bytes:
    lines = [key_id, nonce, str(status), hashlib.sha256(body).hexdigest()]
    return RESPONSE_CONTEXT + "\n".join(lines).encode("utf-8")


@dataclass(frozen=True, slots=True)
class HookTarget:
    scheme: str
    host: str
    port: int
    prefix: str


def _plain(text: str) -> bool:
    """True if every character is a printable ASCII one other than a space."""
    return all(0x21 <= ord(char) <= 0x7E for char in text)


def parse_hook_url(url: str, *, allow_plain_http: bool = False) -> HookTarget:
    """Check a hook address. HTTPS is required, except to this machine or when allowed."""
    if not _plain(url):  # urlsplit would quietly drop tabs and line breaks from inside it
        raise ValueError(
            "the hook address must be plain ASCII, with no spaces or control characters"
        )
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ValueError("the hook address is not a valid URL") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("a hook address must be an http or https URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("a hook address cannot carry credentials, a query or a fragment")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK and not allow_plain_http:
        raise ValueError(
            "a hook must use https, unless it is on this machine or plain http is allowed"
        )
    if port == 0:
        raise ValueError("the hook port cannot be 0")
    if not _plain(parts.hostname):
        raise ValueError("the hook host name must be plain ASCII")
    prefix = parts.path.rstrip("/")
    if prefix and not _plain(prefix):
        raise ValueError("the hook path must be plain ASCII, with no spaces or control characters")
    return HookTarget(
        parts.scheme, parts.hostname, port or (443 if parts.scheme == "https" else 80), prefix
    )


class HookClient:
    """Makes one signed call at a time per request, with a new connection for each."""

    def __init__(  # noqa: PLR0913 - a client needs its address, both keys and its limits
        self,
        url: str,
        *,
        signing_key: Ed25519PrivateKey,
        key_id: str,
        response_keys: KeyRing,
        timeout: float = 2.0,
        allow_plain_http: bool = False,
        tls_context: ssl.SSLContext | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._target = parse_hook_url(url, allow_plain_http=allow_plain_http)
        if not is_valid_key_id(key_id):
            raise ValueError("the hook key id must be 1 to 32 letters, digits, - or _")
        self._key = signing_key
        self._key_id = key_id
        self._response_keys = response_keys
        self._timeout = timeout
        self._clock = clock
        self._tls: ssl.SSLContext | None = None
        if self._target.scheme == "https":
            context = tls_context or ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._tls = context

    async def call(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Send a signed request and return the verified JSON object in the reply."""
        body = json.dumps(
            {"v": HOOK_VERSION, **payload}, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        full_path = f"{self._target.prefix}{path}"
        timestamp = str(int(self._clock()))
        nonce = secrets.token_hex(16)
        signature = self._key.sign(
            request_signing_input(self._key_id, "POST", full_path, timestamp, nonce, body)
        )
        headers = [
            (b"host", self._host_header().encode("ascii")),
            (b"user-agent", b"onionglass-hook/1"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"connection", b"close"),
            (b"x-onionglass-version", str(HOOK_VERSION).encode("ascii")),
            (b"x-onionglass-key", self._key_id.encode("ascii")),
            (b"x-onionglass-timestamp", timestamp.encode("ascii")),
            (b"x-onionglass-nonce", nonce.encode("ascii")),
            (b"x-onionglass-signature", _b64(signature).encode("ascii")),
        ]
        try:
            status, reply_headers, reply = await asyncio.wait_for(
                self._exchange(full_path, headers, body), timeout=self._timeout
            )
        except (TimeoutError, OSError, ssl.SSLError, h11.ProtocolError) as exc:
            raise HookError(f"the hook could not be reached: {type(exc).__name__}") from exc
        return self._verify(nonce, status, reply_headers, reply)

    def _host_header(self) -> str:
        target = self._target
        default = 443 if target.scheme == "https" else 80
        host = f"[{target.host}]" if ":" in target.host else target.host
        return host if target.port == default else f"{host}:{target.port}"

    async def _exchange(
        self, path: str, headers: list[tuple[bytes, bytes]], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        target = self._target
        reader, writer = await asyncio.open_connection(
            target.host,
            target.port,
            ssl=self._tls,
            server_hostname=target.host if self._tls is not None else None,
        )
        try:
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=16_384)
            writer.write(connection.send(h11.Request(method="POST", target=path, headers=headers)))
            writer.write(connection.send(h11.Data(data=body)))
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
            return await self._read_reply(reader, connection)
        finally:
            writer.close()
            with contextlib.suppress(TimeoutError, OSError, ssl.SSLError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

    @staticmethod
    async def _read_reply(
        reader: asyncio.StreamReader, connection: h11.Connection
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
                if len(received) > MAX_RESPONSE_BYTES:
                    raise HookError("the hook's reply is too large")
            elif isinstance(event, h11.EndOfMessage):
                return status, reply_headers, bytes(received)
            else:
                raise HookError("the hook's reply ended unexpectedly")

    def _verify(
        self, nonce: str, status: int, headers: dict[str, str], body: bytes
    ) -> dict[str, Any]:
        if status != 200:
            raise HookError(f"the hook answered with status {status}")
        key_id = headers.get("x-onionglass-key", "")
        public_key = self._response_keys.get(key_id) if key_id else None
        if public_key is None:
            raise HookError("the hook's reply is not signed with a trusted key")
        signature = _unb64(headers.get("x-onionglass-signature", ""))
        try:
            public_key.verify(signature, response_signing_input(key_id, nonce, status, body))
        except InvalidSignature as exc:
            raise HookError("the hook's reply has a bad signature") from exc
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise HookError("the hook's reply is not JSON") from exc
        if not isinstance(data, dict):
            raise HookError("the hook's reply is not a JSON object")
        return data


def _expect_bool(data: dict[str, Any], key: str, *, default: bool | None = None) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise HookError(f"the hook's reply has no true or false {key}")
    return value


def _expect_count(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HookError(f"the hook's reply has no valid {key}")
    return value


class HttpPolicy:
    """A policy that asks a service. Answers can be kept for a short time to save calls."""

    def __init__(
        self,
        client: HookClient,
        *,
        cache_seconds: float = 0.0,
        max_cached: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._ttl = cache_seconds
        self._max = max_cached
        self._clock = clock
        self._cache: dict[tuple[str, ...], tuple[float, Decision]] = {}

    async def decide(self, request: PolicyRequest) -> Decision:
        origin = request.origin
        key = (
            origin.key,
            request.profile,
            request.group,
            request.subject,
            request.action,
        )
        now = self._clock()
        cached = self._cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]
        data = await self._client.call(
            "/policy",
            {
                "origin": {
                    "scheme": origin.scheme,
                    "address": origin.host.address,
                    "host": origin.host.hostname,
                    "port": origin.port,
                },
                "profile": request.profile,
                "group": request.group,
                "subject": request.subject,
                "action": request.action,
            },
        )
        decision = self._decision(data)
        if self._ttl > 0:
            if len(self._cache) >= self._max:
                self._cache.clear()
            self._cache[key] = (now + self._ttl, decision)
        return decision

    @staticmethod
    def _decision(data: dict[str, Any]) -> Decision:
        allowed = _expect_bool(data, "allow")
        rule = data.get("rule", "hook")
        if (
            not isinstance(rule, str)
            or not 1 <= len(rule) <= MAX_RULE
            or not set(rule) <= _RULE_CHARS
        ):
            raise HookError("the hook's reply has an invalid rule name")
        text_only = _expect_bool(data, "text_only", default=False)
        if not allowed:
            return Decision.deny(rule)
        return Decision.allow(rule, text_only=text_only)


class HttpAudit:
    """An audit sink that sends every event to a service, which must confirm it."""

    def __init__(
        self,
        client: HookClient,
        *,
        address_form: AddressForm = "origin",
        salt: bytes | None = None,
    ) -> None:
        if address_form not in ADDRESS_FORMS:
            raise ValueError(f"address form must be one of {ADDRESS_FORMS}")
        self._client = client
        self._form = address_form
        self._salt = salt or secrets.token_bytes(32)

    @property
    def address_form(self) -> AddressForm:
        return self._form

    async def write(self, event: AuditEvent) -> None:
        """Send the event, naming the onion site only in the form the operator chose."""
        shown = in_address_form(event, self._form, self._salt)
        data = await self._client.call("/audit", {"event": asdict(shown)})
        if not _expect_bool(data, "ok"):
            raise HookError("the audit service did not accept the event")


class HttpQuota:
    """A quota meter that asks a service how much an account has used today."""

    def __init__(self, client: HookClient) -> None:
        self._client = client

    async def used(self, subject: str, profile: str) -> int:
        data = await self._client.call("/quota/used", {"subject": subject, "profile": profile})
        return _expect_count(data, "used")

    async def charge(self, subject: str, profile: str, units: int) -> int:
        data = await self._client.call(
            "/quota/charge", {"subject": subject, "profile": profile, "units": units}
        )
        return _expect_count(data, "used")

    async def reserve(self, subject: str, profile: str, units: int, limit: int) -> bool:
        data = await self._client.call(
            "/quota/reserve",
            {"subject": subject, "profile": profile, "units": units, "limit": limit},
        )
        return _expect_bool(data, "ok")
