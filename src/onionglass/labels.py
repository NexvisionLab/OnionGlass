# SPDX-License-Identifier: AGPL-3.0-only
"""Opaque per-session host labels.

Security property P11: the onion address a visitor opens never appears in DNS lookups, TLS
server names or URLs. Instead the gateway gives each (session, onion) pair a random label and
serves the content from ``<label>.<gateway domain>``. Only the server can map a label back.

Labels carry no information about the onion. They are 128 random bits, base32 encoded.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass

from onionglass.onion import InvalidOnionError, normalise_address
from onionglass.store import SessionStore

LABEL_BYTES = 16
LABEL_LENGTH = 26
_LABEL_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_SESSION_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_ATTEMPTS = 5


class LabelError(RuntimeError):
    """A label could not be created. Callers must fail closed."""


def new_label() -> str:
    """A fresh random label: 26 lower-case base32 characters."""
    raw = secrets.token_bytes(LABEL_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def is_valid_label(label: str) -> bool:
    return len(label) == LABEL_LENGTH and label.isascii() and set(label) <= _LABEL_ALPHABET


def is_valid_session_id(session_id: str) -> bool:
    """Session ids are limited to a safe alphabet so they cannot collide with key separators."""
    return 8 <= len(session_id) <= 64 and set(session_id) <= _SESSION_ID_CHARS


@dataclass(frozen=True, slots=True)
class LabelTarget:
    """What a label stands for."""

    session_id: str
    address: str


class LabelBook:
    """Creates labels for (session, onion) pairs and resolves them back."""

    def __init__(self, store: SessionStore, *, ttl: float) -> None:
        self._store = store
        self._ttl = ttl

    async def label_for(self, session_id: str, address: str) -> str:
        """The label for this session and onion. Created on first use, stable afterwards."""
        if not is_valid_session_id(session_id):
            raise LabelError("invalid session id")
        try:
            normalised = normalise_address(address)
        except InvalidOnionError as exc:
            raise LabelError("invalid onion address") from exc
        forward_key = f"lbl:{session_id}:{normalised}"
        existing = await self._store.get(forward_key)
        if existing is not None:
            return existing
        reverse_value = json.dumps([session_id, normalised], separators=(",", ":"))
        for _ in range(_ATTEMPTS):
            candidate = new_label()
            if not await self._store.add_if_absent(f"rev:{candidate}", reverse_value, self._ttl):
                continue
            if await self._store.add_if_absent(forward_key, candidate, self._ttl):
                return candidate
            # Another request created a label for this pair first. Use theirs.
            await self._store.delete(f"rev:{candidate}")
            winner = await self._store.get(forward_key)
            if winner is not None:
                return winner
        raise LabelError("could not allocate a label")

    async def resolve(self, label: str) -> LabelTarget | None:
        """The session and onion behind a label, or None if unknown or expired."""
        if not is_valid_label(label):
            return None
        raw = await self._store.get(f"rev:{label}")
        if raw is None:
            return None
        try:
            session_id, address = json.loads(raw)
            return LabelTarget(session_id=session_id, address=normalise_address(address))
        except (ValueError, TypeError, InvalidOnionError):
            return None
