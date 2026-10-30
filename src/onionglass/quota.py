# SPDX-License-Identifier: AGPL-3.0-only
"""Daily allowances, counted per account and per profile.

What counts is the operator's choice, through two costs on each profile: ``open_cost`` is taken
when a visitor opens an address, and ``page_cost`` for every web page that comes back. Opens per
day is ``open_cost=1, page_cost=0``. Pages per day is the other way round. Any mix is allowed.
The day is a UTC day, and counts start again at midnight UTC.

``LocalQuota`` is the built-in meter. With a file it keeps a journal that survives a restart, so
restarting the gateway does not hand everyone a fresh allowance. If a meter cannot be read or
written the gateway refuses the request, because an allowance nobody can count is no allowance.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

SECONDS_PER_DAY = 86_400
MAX_JOURNAL_BYTES = 64_000_000


class QuotaError(Exception):
    """The meter could not be read or written."""


class QuotaMeter(Protocol):
    """Counts what each account has used today. Failing makes the gateway refuse."""

    async def used(self, subject: str, profile: str) -> int: ...

    async def charge(self, subject: str, profile: str, units: int) -> int:
        """Add ``units`` to today's count and return the new total."""
        ...


class LocalQuota:
    """Counts in memory, and in a journal file when given one."""

    def __init__(
        self, path: str | Path | None = None, *, clock: Callable[[], float] = time.time
    ) -> None:
        self._clock = clock
        self._path = Path(path) if path is not None else None
        self._lock = asyncio.Lock()
        self._day = self._today()
        self._used: dict[tuple[str, str], int] = {}
        if self._path is not None:
            self._load()

    def _today(self) -> int:
        return int(self._clock() // SECONDS_PER_DAY)

    def _roll(self) -> None:
        today = self._today()
        if today != self._day:
            self._day = today
            self._used = {}

    def _load(self) -> None:
        """Replay today's lines from the journal. Older days are dropped from the file."""
        assert self._path is not None  # noqa: S101 - only called with a path
        try:
            data = self._path.read_bytes()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise QuotaError(f"cannot read {self._path}: {exc.strerror}") from exc
        if len(data) > MAX_JOURNAL_BYTES:
            raise QuotaError(f"{self._path} is too large")
        kept: list[str] = []
        for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                day, subject, profile, units = (
                    int(record["d"]),
                    str(record["s"]),
                    str(record["p"]),
                    int(record["n"]),
                )
            except (ValueError, KeyError, TypeError) as exc:
                raise QuotaError(f"{self._path}: line {number} is not a quota record") from exc
            if day == self._day:
                key = (subject, profile)
                self._used[key] = self._used.get(key, 0) + units
                kept.append(line)
        if len(kept) != len(data.splitlines()):
            self._rewrite(kept)

    def _rewrite(self, lines: list[str]) -> None:
        assert self._path is not None  # noqa: S101
        temporary = self._path.with_name(self._path.name + ".tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"))
            os.replace(temporary, self._path)
        except OSError as exc:
            raise QuotaError(f"cannot write {self._path}: {exc.strerror}") from exc

    def _append(self, line: str) -> None:
        assert self._path is not None  # noqa: S101
        descriptor = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            handle.write(line.encode("utf-8") + b"\n")
            handle.flush()

    async def used(self, subject: str, profile: str) -> int:
        self._roll()
        return self._used.get((subject, profile), 0)

    async def charge(self, subject: str, profile: str, units: int) -> int:
        if units < 0:
            raise ValueError("units cannot be negative")
        async with self._lock:
            self._roll()
            if units and self._path is not None:
                line = json.dumps(
                    {"d": self._day, "s": subject, "p": profile, "n": units},
                    separators=(",", ":"),
                )
                try:
                    await asyncio.to_thread(self._append, line)
                except OSError as exc:
                    raise QuotaError("the quota journal could not be written") from exc
            key = (subject, profile)
            self._used[key] = self._used.get(key, 0) + units
            return self._used[key]
