# SPDX-License-Identifier: AGPL-3.0-only
"""The held list: onion sites that are not served until a person has looked at them.

When the name gate refuses a page, or enough visitors report a site, it is added here. Every later
request to that site is refused, whoever asks, until someone releases it. The file is also the
review queue: each line has the address, when it was held and why, so whoever reviews it can see
what is waiting. Nothing is sent anywhere, and nothing about the page is kept except the reason.

The file only ever grows. A site is held by a line with its address, and released by a later line
that starts with the word ``release``. Nothing is rewritten, so the gateway and an operator can
both add to it at the same moment without either losing a line. Format, ``#`` starts a comment::

    <56 character address> <time> <reason>
    release <56 character address> <time>

Like the kill file, the file is read again at most every couple of seconds, and only when it has
changed. A file that exists but cannot be read or understood holds everything. A last line that was
cut off by a crash is not trusted either way and does not make the file unreadable. A site held in
memory because the file could not be written stays held until the file shows it or the gateway
restarts.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from onionglass.files import append_line, tail_is_torn
from onionglass.onion import InvalidOnionError
from onionglass.policy import address_of

MAX_FILE_BYTES = 8_000_000
BROKEN = "held-list-unreadable"
RELEASE = "release"


class HeldError(Exception):
    """The held list could not be written."""


def parse_line(line: str) -> tuple[str, str] | None:
    """What one line says: ``("hold", address)``, ``("release", address)``, or None for a blank
    line or a comment. Raises ``InvalidOnionError`` if the line makes no sense."""
    content = line.split("#", 1)[0].strip()
    if not content:
        return None
    first, _, rest = content.partition(" ")
    if first == RELEASE:
        return RELEASE, address_of(rest.split(None, 1)[0] if rest.strip() else "")
    return "hold", address_of(first)


def is_held_line(line: str) -> bool:
    """True if the line is a whole record, a comment or blank."""
    try:
        parse_line(line)
    except InvalidOnionError:
        return False
    return True


def parse_held(text: str, *, torn_tail: bool = False) -> frozenset[str]:
    """The sites a held file holds, replaying holds and releases in order."""
    lines = text.splitlines()
    if torn_tail:
        lines = lines[:-1]
    held: set[str] = set()
    for line in lines:
        parsed = parse_line(line)
        if parsed is None:
            continue
        action, address = parsed
        if action == RELEASE:
            held.discard(address)
        else:
            held.add(address)
    return frozenset(held)


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
        self._stamp: tuple[int, int] | None = None
        self._from_file: frozenset[str] = frozenset()
        self._broken = False
        self._pending: set[str] = set()
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
        try:
            return parse_held(text, torn_tail=tail_is_torn(data, is_held_line)), False
        except InvalidOnionError:
            return frozenset(), True

    def _file_stamp(self) -> tuple[int, int] | None:
        try:
            info = self._path.stat()
        except OSError:
            return None
        return info.st_mtime_ns, info.st_size

    def _current(self) -> None:
        now = self._clock()
        if self._checked_at is not None and now - self._checked_at < self._refresh:
            return
        self._checked_at = now
        stamp = self._file_stamp()
        if stamp is not None and stamp == self._stamp and not self._broken:
            return  # the file has not changed since it was last read
        self._from_file, self._broken = self._load()
        self._stamp = stamp

    def reason_for(self, address: str) -> str | None:
        """The rule that holds this address, or None if it is not held.

        An unreadable file holds every address, with ``held-list-unreadable`` as the rule.
        """
        self._current()
        if self._broken:
            return BROKEN
        if address in self._pending or address in self._from_file:
            return "held"
        return None

    async def hold(self, address: str, reason: str) -> None:
        """Hold an address from now on. Raises ``HeldError`` if the file could not be written.

        The address is held in memory either way.
        """
        self._pending.add(address)
        stamp = datetime.fromtimestamp(self._wall(), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        clean = " ".join(reason.split())[:200] or "held"
        try:
            async with self._lock:
                await asyncio.to_thread(
                    append_line, self._path, f"{address} {stamp} {clean}", is_held_line
                )
        except OSError as exc:
            raise HeldError("the held list could not be written") from exc
        self._pending.discard(address)  # the file now says so, and a release can undo it
        self._stamp = None  # read the file again at the next look
        self._checked_at = None


def release_line(address: str, wall: Callable[[], float] = time.time) -> str:
    """The line that releases a site."""
    stamp = datetime.fromtimestamp(wall(), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{RELEASE} {address} {stamp}"


def hold_line(address: str, reason: str, wall: Callable[[], float] = time.time) -> str:
    stamp = datetime.fromtimestamp(wall(), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    clean = " ".join(reason.split())[:200] or "held"
    return f"{address} {stamp} {clean}"
