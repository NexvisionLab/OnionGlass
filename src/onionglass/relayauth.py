# SPDX-License-Identifier: AGPL-3.0-only
"""The signature a relay puts on every request it sends to a gateway.

A gateway that sits behind relays serves only requests that carry a valid signature, so a censor
that finds the gateway's address and asks it for a page is treated like any other stranger. Each
relay has its own key, so one that is burned can be cut off without touching the others.

The signature covers the method, the host and the target of the request, a time and a random
number, so it is good for one request only. It does not cover the body. The hop between relay and
gateway must therefore be encrypted, which the relay checks for (``relay.py``). The key is
Ed25519, and the gateway holds only public keys, so a gateway that is broken into gives away no
way to speak as a relay, unless the key was made on it and a copy was left behind.
"""

from __future__ import annotations

import base64
import binascii
import os
import time
from collections import deque
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onionglass.tickets import KeyRing, is_valid_key_id

HEADER = "x-og-relay"
# Added by the relay's own check and never by a visitor, because the relay passes on no header a
# visitor made up. The gateway answers the relay check only when it is there.
CHECK_HEADER = "x-og-check"
SIGNING_CONTEXT = b"onionglass relay v1\x00"
MAX_HEADER_CHARS = 256
DEFAULT_SKEW_SECONDS = 60
DEFAULT_MEMORY = 50_000
_NONCE_BYTES = 16
_SIGNATURE_BYTES = 64
_URLSAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_MAX_TIME_DIGITS = 12


class RelayAuthError(Exception):
    """A request that does not carry a good relay signature. ``reason`` is one short word and is
    for the gateway's own counters. It is never shown to the sender."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(text: str, length: int) -> bytes:
    """Only the canonical unpadded form, and only of the length asked for."""
    if not text or not set(text) <= _URLSAFE:
        raise RelayAuthError("malformed")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise RelayAuthError("malformed") from exc
    if len(data) != length or _encode(data) != text:
        raise RelayAuthError("malformed")
    return data


def _printable(text: str) -> bool:
    return bool(text) and text.isascii() and all("!" <= char <= "~" for char in text)


def _signing_input(key_id: str, moment: int, nonce: str, request: tuple[str, str, str]) -> bytes:
    """What is signed: who, when, a number used once, and the method, host and target asked for."""
    parts = (key_id, str(moment), nonce, *request)
    return SIGNING_CONTEXT + b"\x00".join(part.encode("ascii") for part in parts)


def _request_parts(method: str, host: str, target: str) -> None:
    if not (method.isascii() and method.isalpha() and method.isupper() and len(method) <= 16):
        raise ValueError("a request method is capital letters only")
    if not _printable(host) or not _printable(target):
        raise ValueError("the host and the target must be plain printable text")


class RelaySigner:
    """Held by a relay. Signs each request it forwards."""

    def __init__(
        self,
        key_id: str,
        key: Ed25519PrivateKey,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not is_valid_key_id(key_id):
            raise ValueError("a relay key id is 1 to 32 letters, digits, - or _")
        self._key_id = key_id
        self._key = key
        self._clock = clock

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, method: str, host: str, target: str) -> str:
        _request_parts(method, host, target)
        moment = int(self._clock())
        nonce = _encode(os.urandom(_NONCE_BYTES))
        signature = self._key.sign(
            _signing_input(self._key_id, moment, nonce, (method, host, target))
        )
        return f"{self._key_id}.{moment}.{nonce}.{_encode(signature)}"


class RelayVerifier:
    """Held by the gateway. Accepts a request only if a relay it knows signed exactly this request
    a moment ago and no one has used that signature before."""

    def __init__(
        self,
        ring: KeyRing,
        *,
        skew: int = DEFAULT_SKEW_SECONDS,
        capacity: int = DEFAULT_MEMORY,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if skew < 1 or capacity < 1:
            raise ValueError("the allowed clock difference and the memory must be above zero")
        self._ring = ring
        self._skew = skew
        self._capacity = capacity
        self._clock = clock
        self._used: dict[tuple[str, str], None] = {}
        self._order: deque[tuple[tuple[str, str], int]] = deque()

    def remembered(self) -> int:
        """How many used signatures are being remembered."""
        return len(self._used)

    def _forget_old(self, now: float) -> None:
        while self._order and self._order[0][1] < now:
            self._used.pop(self._order.popleft()[0], None)

    def _remember(self, entry: tuple[str, str], until: int) -> None:
        while len(self._order) >= self._capacity:
            self._used.pop(self._order.popleft()[0], None)
        self._used[entry] = None
        self._order.append((entry, until))

    def verify(self, value: str, method: str, host: str, target: str) -> str:
        """The id of the relay that signed this request, or ``RelayAuthError``."""
        if len(value) > MAX_HEADER_CHARS or not value.isascii():
            raise RelayAuthError("malformed")
        parts = value.split(".")
        if len(parts) != 4:
            raise RelayAuthError("malformed")
        key_id, stamp, nonce, signature = parts
        if not is_valid_key_id(key_id):
            raise RelayAuthError("malformed")
        if (
            not (stamp.isascii() and stamp.isdigit())
            or len(stamp) > _MAX_TIME_DIGITS
            or stamp[0] == "0"
        ):
            raise RelayAuthError("malformed")
        _decode(nonce, _NONCE_BYTES)
        raw_signature = _decode(signature, _SIGNATURE_BYTES)
        key = self._ring.get(key_id)
        if key is None:
            raise RelayAuthError("unknown_key")
        now = self._clock()
        moment = int(stamp)
        if abs(now - moment) > self._skew:
            raise RelayAuthError("stale")
        try:
            _request_parts(method, host, target)
            key.verify(raw_signature, _signing_input(key_id, moment, nonce, (method, host, target)))
        except (InvalidSignature, ValueError) as exc:
            raise RelayAuthError("bad_signature") from exc
        self._forget_old(now)
        entry = (key_id, nonce)
        if entry in self._used:
            raise RelayAuthError("replayed")
        self._remember(entry, moment + self._skew)
        return key_id
