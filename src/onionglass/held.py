# SPDX-License-Identifier: AGPL-3.0-only
"""The held list: onion sites that are not served until a person has looked at them.

When the name gate refuses a page, the site is added here. Every later request to that site is
refused, whoever asks, until someone removes its line from the file. The file is also the review
queue: each line has the address, when it was held and why, so whoever reviews it can see what is
waiting. Nothing is sent anywhere, and nothing about the page is kept except the reason.

Format, one site per line, ``#`` starts a comment::

    <56 character address> <time> <reason>

Like the kill file, the file is read at most every couple of seconds, and a file that exists but
cannot be read or understood holds everything. A line added in memory stays held until the
gateway restarts even if it could not be written to the file.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from onionglass.onion import InvalidOnionError
from onionglass.policy import address_of

MAX_FILE_BYTES = 8_000_000
BROKEN = "held-list-unreadable"


class HeldError(Exception):
    """The held list could not be written."""


class HeldList:
    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        refresh: float = 2.0,
    ) -> None:
        self._path = Path(path)
        self._clock = clock
        self._wall = wall
        self._refresh = refresh
        self._checked_at: float | None = None
        self._from_file: frozenset[str] = frozenset()
        self._broken = False
        self._added: set[str] = set()
        self._lock = asyncio.Lock()

    def _load(self) -> tuple[frozenset[str], bool]:
        try:
            data = self._path.read_bytes()
        except FileNotFoundError:
            return frozenset(), False
        except OSError:
            return frozenset(), True
        if len(data) > MAX_FILE_BYTES:
            return frozenset(), True
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return frozenset(), True
        found: set[str] = set()
        for line in text.splitlines():
            content = line.split("#", 1)[0].strip()
            if not content:
                continue
            try:
                found.add(address_of(content.split(None, 1)[0]))
            except InvalidOnionError:
                return frozenset(), True
        return frozenset(found), False

    def _current(self) -> None:
        now = self._clock()
        if self._checked_at is None or now - self._checked_at >= self._refresh:
            self._from_file, self._broken = self._load()
            self._checked_at = now

    def reason_for(self, address: str) -> str | None:
        """The rule that holds this address, or None if it is not held.

        An unreadable file holds every address, with ``held-list-unreadable`` as the rule.
        """
        self._current()
        if self._broken:
            return BROKEN
        if address in self._added or address in self._from_file:
            return "held"
        return None

    def _append(self, line: str) -> None:
        descriptor = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            handle.write(line.encode("utf-8") + b"\n")
            handle.flush()

    async def hold(self, address: str, reason: str) -> None:
        """Hold an address from now on. Raises ``HeldError`` if the file could not be written.

        The address is held in memory either way.
        """
        self._added.add(address)
        stamp = datetime.fromtimestamp(self._wall(), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        clean = " ".join(reason.split())[:200] or "held"
        try:
            async with self._lock:
                await asyncio.to_thread(self._append, f"{address} {stamp} {clean}")
        except OSError as exc:
            raise HeldError("the held list could not be written") from exc
