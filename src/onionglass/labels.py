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

from onionglass.onion import InvalidOnionError, OnionOrigin, parse_origin_key
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
    origin: OnionOrigin


class LabelBook:
    """Creates labels for (session, onion) pairs and resolves them back."""

    def __init__(
        self, store: SessionStore, *, ttl: float, max_per_session: int | None = None
    ) -> None:
        self._store = store
        self._ttl = ttl
        self._max_per_session = max_per_session

    async def peek(self, session_id: str, origin: OnionOrigin) -> str | None:
        """The label this session already has for the origin, without making one."""
        if not is_valid_session_id(session_id):
            return None
        return await self._store.get(f"lbl:{session_id}:{origin.key}")

    async def label_for(
        self, session_id: str, origin: OnionOrigin, *, reserved: bool = False
    ) -> str:
        """The label for this session and onion origin. Created on first use, stable after."""
        if not is_valid_session_id(session_id):
            raise LabelError("invalid session id")
        forward_key = f"lbl:{session_id}:{origin.key}"
        existing = await self._store.get(forward_key)
        if existing is not None:
            return existing
        count_key = f"lblcount:{session_id}"
        used = int(await self._store.get(count_key) or 0)
        # Each session gets a fixed number of labels for links. Labels for addresses the visitor
        # types are reserved: a hostile page that names endless sites can use up the allowance
        # for links, but not for what the visitor opens themselves.
        if not reserved and self._max_per_session is not None and used >= self._max_per_session:
            raise LabelError("too many sites in this session")
        reverse_value = json.dumps([session_id, origin.key], separators=(",", ":"))
        for _ in range(_ATTEMPTS):
            candidate = new_label()
            if not await self._store.add_if_absent(f"rev:{candidate}", reverse_value, self._ttl):
                continue
            if await self._store.add_if_absent(forward_key, candidate, self._ttl):
                if not reserved:
                    await self._store.put(count_key, str(used + 1), self._ttl)
                return candidate
            # Another request created a label for this pair first. Use theirs.
            await self._store.delete(f"rev:{candidate}")
            winner = await self._store.get(forward_key)
            if winner is not None:
                return winner
        raise LabelError("could not allocate a label")

    async def resolve(self, label: str) -> LabelTarget | None:
        """The session and onion origin behind a label, or None if unknown or expired."""
        if not is_valid_label(label):
            return None
        raw = await self._store.get(f"rev:{label}")
        if raw is None:
            return None
        try:
            session_id, origin_key = json.loads(raw)
            return LabelTarget(session_id=session_id, origin=parse_origin_key(origin_key))
        except (ValueError, TypeError, InvalidOnionError):
            return None
