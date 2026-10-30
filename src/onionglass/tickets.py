# SPDX-License-Identifier: AGPL-3.0-only
"""Signed, short-lived, single-use sign-in tickets.

Security property P9: tickets cannot be forged, replayed after use, or used after expiry.

A ticket is created by whatever signs visitors in: the built-in local accounts, an OpenID
Connect bridge, or an outside service. The gateway only holds public keys, so a stolen gateway
cannot mint tickets. Keys carry identifiers so they can be rotated without downtime.

Wire format: ``og1.<key id>.<payload>.<signature>`` where payload and signature are unpadded
base64url. The signature covers a fixed context string, the key id and the exact payload bytes,
so a signature made for another purpose or key id can never be accepted here.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from onionglass.onion import InvalidOnionError, normalise_address
from onionglass.store import SessionStore

FORMAT_PREFIX = "og1"
SIGNING_CONTEXT = b"onionglass ticket v1\x00"
MAX_TOKEN_LENGTH = 4096
MAX_LIFETIME_SECONDS = 300
CLOCK_SKEW_SECONDS = 30

_KEY_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_B64URL_CHARS = _KEY_ID_CHARS
_PRINTABLE_ASCII = frozenset(chr(c) for c in range(0x21, 0x7F))
_CLAIM_KEYS = frozenset({"sub", "grp", "prf", "jti", "iat", "exp", "aud", "onion"})
_REQUIRED_KEYS = _CLAIM_KEYS - {"onion"}


class TicketError(Exception):
    """A ticket was rejected. The message is generic on purpose; ``reason`` is for audit logs."""

    def __init__(self, reason: str) -> None:
        super().__init__("ticket rejected")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class TicketClaims:
    subject: str
    group: str
    profile: str
    ticket_id: str
    issued_at: int
    expires_at: int
    audience: str
    onion: str | None = None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    """Strict decoding: only canonical unpadded base64url is accepted."""
    if not text or not text.isascii() or not set(text) <= _B64URL_CHARS:
        raise TicketError("malformed")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise TicketError("malformed") from exc
    if _b64url_encode(data) != text:
        raise TicketError("malformed")
    return data


def is_valid_key_id(key_id: str) -> bool:
    return 1 <= len(key_id) <= 32 and set(key_id) <= _KEY_ID_CHARS


def _signing_input(key_id: str, payload: bytes) -> bytes:
    return SIGNING_CONTEXT + key_id.encode("ascii") + b"\x00" + payload


def generate_key() -> Ed25519PrivateKey:
    """A new signing key. Only the issuing side ever holds this."""
    return Ed25519PrivateKey.generate()


class KeyRing:
    """The public keys the gateway trusts, by key id."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add(self, key_id: str, public_key: Ed25519PublicKey | bytes) -> None:
        if not is_valid_key_id(key_id):
            raise ValueError("invalid key id")
        if isinstance(public_key, bytes):
            public_key = Ed25519PublicKey.from_public_bytes(public_key)
        self._keys[key_id] = public_key

    def remove(self, key_id: str) -> None:
        self._keys.pop(key_id, None)

    def get(self, key_id: str) -> Ed25519PublicKey | None:
        return self._keys.get(key_id)

    def ids(self) -> list[str]:
        """The key ids the ring holds, in the order they were added."""
        return list(self._keys)


class TicketIssuer:
    """Signs tickets. Used by the built-in sign-in and by tests; integrators may use their own."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        key_id: str,
        audience: str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not is_valid_key_id(key_id):
            raise ValueError("invalid key id")
        self._key = private_key
        self._key_id = key_id
        self._audience = audience
        self._clock = clock

    def issue(
        self,
        *,
        subject: str,
        group: str,
        profile: str,
        lifetime: int = 60,
        onion: str | None = None,
    ) -> str:
        if not 1 <= lifetime <= MAX_LIFETIME_SECONDS:
            raise ValueError("lifetime out of range")
        now = int(self._clock())
        claims: dict[str, Any] = {
            "sub": subject,
            "grp": group,
            "prf": profile,
            "jti": secrets.token_urlsafe(16),
            "iat": now,
            "exp": now + lifetime,
            "aud": self._audience,
        }
        if onion is not None:
            claims["onion"] = normalise_address(onion)
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = self._key.sign(_signing_input(self._key_id, payload))
        return ".".join(
            (FORMAT_PREFIX, self._key_id, _b64url_encode(payload), _b64url_encode(signature))
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _text(claims: dict[str, Any], key: str, *, max_length: int = 128) -> str:
    value = claims[key]
    if not isinstance(value, str) or not 1 <= len(value) <= max_length:
        raise TicketError("bad_claims")
    if not set(value) <= _PRINTABLE_ASCII:
        raise TicketError("bad_claims")
    return value


def _integer(claims: dict[str, Any], key: str) -> int:
    value = claims[key]
    if type(value) is not int or not 0 <= value <= 4_102_444_800:
        raise TicketError("bad_claims")
    return value


def _parse_claims(payload: bytes) -> TicketClaims:
    try:
        raw = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TicketError("bad_claims") from exc
    if not isinstance(raw, dict):
        raise TicketError("bad_claims")
    keys = set(raw)
    if not _REQUIRED_KEYS <= keys <= _CLAIM_KEYS:
        raise TicketError("bad_claims")
    onion: str | None = None
    if "onion" in raw:
        try:
            onion = normalise_address(_text(raw, "onion", max_length=56))
        except InvalidOnionError as exc:
            raise TicketError("bad_claims") from exc
    ticket_id = _text(raw, "jti", max_length=64)
    if len(ticket_id) < 16:
        raise TicketError("bad_claims")
    return TicketClaims(
        subject=_text(raw, "sub", max_length=256),
        group=_text(raw, "grp"),
        profile=_text(raw, "prf"),
        ticket_id=ticket_id,
        issued_at=_integer(raw, "iat"),
        expires_at=_integer(raw, "exp"),
        audience=_text(raw, "aud"),
        onion=onion,
    )


class TicketVerifier:
    """Checks tickets. Holds public keys only."""

    def __init__(
        self,
        keys: KeyRing,
        audience: str,
        *,
        max_lifetime: int = MAX_LIFETIME_SECONDS,
        skew: int = CLOCK_SKEW_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keys = keys
        self._audience = audience
        self._max_lifetime = max_lifetime
        self._skew = skew
        self._clock = clock

    def verify(self, token: str) -> TicketClaims:
        """Check signature, claims, audience and time window. Does not consume the ticket."""
        if len(token) > MAX_TOKEN_LENGTH or not token.isascii():
            raise TicketError("malformed")
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != FORMAT_PREFIX:
            raise TicketError("malformed")
        _, key_id, payload_text, signature_text = parts
        if not is_valid_key_id(key_id):
            raise TicketError("malformed")
        payload = _b64url_decode(payload_text)
        signature = _b64url_decode(signature_text)
        public_key = self._keys.get(key_id)
        if public_key is None:
            raise TicketError("unknown_key")
        try:
            public_key.verify(signature, _signing_input(key_id, payload))
        except InvalidSignature as exc:
            raise TicketError("bad_signature") from exc
        # Only now is the payload trusted enough to parse.
        claims = _parse_claims(payload)
        if claims.audience != self._audience:
            raise TicketError("wrong_audience")
        if (
            claims.expires_at <= claims.issued_at
            or claims.expires_at - claims.issued_at > self._max_lifetime
        ):
            raise TicketError("bad_lifetime")
        now = self._clock()
        if claims.issued_at - self._skew > now:
            raise TicketError("not_yet_valid")
        if claims.expires_at + self._skew <= now:
            raise TicketError("expired")
        return claims

    async def redeem(self, token: str, store: SessionStore) -> TicketClaims:
        """Verify the ticket and mark it used. A second redemption of the same ticket fails."""
        claims = self.verify(token)
        remaining = claims.expires_at - self._clock() + 2 * self._skew
        if not await store.add_if_absent(f"jti:{claims.ticket_id}", "1", max(remaining, 1.0)):
            raise TicketError("replayed")
        return claims
