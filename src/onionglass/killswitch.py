# SPDX-License-Identifier: AGPL-3.0-only
"""Kill switches: stop serving without restarting the gateway.

An operator stops the gateway, one profile or one onion address by editing a small file. The
gateway looks at the file at most once a second. A file that exists but cannot be read, or that
holds a line nobody understands, counts as a stop for everything. A typo in an emergency file is
far more likely to mean "stop" than "carry on".

File format, one scope per line, ``#`` starts a comment::

    all
    profile restricted
    onion <56 character address>

The file does not need to exist. Deleting it, or emptying it, ends the stop.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from onionglass.onion import InvalidOnionError
from onionglass.policy import address_of

MAX_FILE_BYTES = 65_536
BROKEN = "unreadable"


@dataclass(frozen=True, slots=True)
class _State:
    everything: bool = False
    profiles: frozenset[str] = frozenset()
    onions: frozenset[str] = frozenset()
    broken: bool = False


def parse_kill_file(text: str) -> _State:
    """Read the scopes in a kill file. Anything not understood marks the whole file broken."""
    everything = False
    profiles: set[str] = set()
    onions: set[str] = set()
    for line in text.splitlines():
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        word, _, rest = content.partition(" ")
        rest = rest.strip()
        if word == "all" and not rest:
            everything = True
        elif word == "profile" and rest and " " not in rest:
            profiles.add(rest)
        elif word == "onion" and rest:
            try:
                onions.add(address_of(rest))
            except InvalidOnionError:
                return _State(broken=True)
        else:
            return _State(broken=True)
    return _State(everything, frozenset(profiles), frozenset(onions))


class KillSwitch:
    """Reads a kill file and says whether a request is stopped, and by which scope."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.monotonic,
        refresh: float = 1.0,
    ) -> None:
        self._path = Path(path)
        self._clock = clock
        self._refresh = refresh
        self._checked_at: float | None = None
        self._state = _State()

    def _load(self) -> _State:
        try:
            data = self._path.read_bytes()
        except FileNotFoundError:
            return _State()
        except OSError:
            return _State(broken=True)
        if len(data) > MAX_FILE_BYTES:
            return _State(broken=True)
        try:
            return parse_kill_file(data.decode("utf-8"))
        except UnicodeDecodeError:
            return _State(broken=True)

    def _current(self) -> _State:
        now = self._clock()
        if self._checked_at is None or now - self._checked_at >= self._refresh:
            self._state = self._load()
            self._checked_at = now
        return self._state

    def engaged(self, *, profile: str, address: str) -> str | None:
        """The scope that stops this request, or None if nothing does.

        The result is for the audit log, for example ``all`` or ``profile:restricted``.
        """
        state = self._current()
        if state.broken:
            return BROKEN
        if state.everything:
            return "all"
        if profile in state.profiles:
            return f"profile:{profile}"
        if address in state.onions:
            return "onion"
        return None
