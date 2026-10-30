# SPDX-License-Identifier: AGPL-3.0-only
"""The report queue: visitors tell the operator about a site.

A signed-in visitor can report the site they are looking at, choosing one reason from a short list.
There is no free text. That keeps the queue free of other people's personal details, of
instructions aimed at whoever reads it, and of anything that would be a harm to read.

Each report is one line in a file: the time, the onion address, the reason and who reported it.
That is all the abuse procedure says to keep, and no page content is ever stored. A visitor can
report a site once. With ``hold_after`` set, a site that enough different visitors have reported
is put on the held list, so it stops being served until a person has looked at it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from onionglass.files import append_line, tail_is_torn
from onionglass.held import HeldList

_log = logging.getLogger("onionglass.reports")
CATEGORIES: tuple[str, ...] = ("illegal", "harmful", "scam", "other")
MAX_FILE_BYTES = 64_000_000
MAX_SUBJECT = 200


class ReportError(Exception):
    """The report file could not be read or written."""


def _report_of(line: str) -> tuple[str, str]:
    record = json.loads(line)
    return str(record["address"]), str(record["subject"])


def _is_report(line: str) -> bool:
    try:
        _report_of(line)
    except (ValueError, KeyError, TypeError):
        return False
    return True


class ReportQueue:
    def __init__(
        self,
        path: str | Path,
        *,
        held: HeldList | None = None,
        hold_after: int | None = None,
        wall: Callable[[], float] = time.time,
    ) -> None:
        if hold_after is not None:
            if hold_after < 1:
                raise ValueError("hold_after must be at least 1")
            if held is None:
                raise ValueError("hold_after needs a held list to put sites on")
        self._path = Path(path)
        self._held = held
        self._hold_after = hold_after
        self._wall = wall
        self._lock = asyncio.Lock()
        self._reporters: dict[str, set[str]] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = self._path.read_bytes()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ReportError(f"cannot read {self._path}: {exc.strerror}") from exc
        if len(data) > MAX_FILE_BYTES:
            raise ReportError(f"{self._path} is too large")
        lines = data.decode("utf-8", errors="replace").splitlines()
        if tail_is_torn(data, _is_report):
            lines = lines[:-1]  # a report cut off by a crash was never finished
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                address, subject = _report_of(line)
            except (ValueError, KeyError, TypeError) as exc:
                raise ReportError(f"{self._path}: line {number} is not a report") from exc
            self._reporters.setdefault(address, set()).add(subject)

    def reporters_of(self, address: str) -> int:
        """How many different visitors have reported this address."""
        return len(self._reporters.get(address, ()))

    async def submit(
        self, address: str, category: str, subject: str
    ) -> Literal["received", "duplicate"]:
        """Record a report. A visitor's second report of the same site is not recorded again."""
        if category not in CATEGORIES:
            raise ValueError("unknown reason")
        who = subject[:MAX_SUBJECT]
        async with self._lock:
            if who in self._reporters.get(address, ()):
                return "duplicate"
            line = json.dumps(
                {
                    "time": datetime.fromtimestamp(self._wall(), UTC).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "address": address,
                    "category": category,
                    "subject": who,
                },
                separators=(",", ":"),
            )
            try:
                await asyncio.to_thread(append_line, self._path, line, _is_report)
            except OSError as exc:
                raise ReportError("the report could not be recorded") from exc
            self._reporters.setdefault(address, set()).add(who)
            count = len(self._reporters[address])
        await self._maybe_hold(address, count)
        return "received"

    async def _maybe_hold(self, address: str, count: int) -> None:
        if self._hold_after is None or self._held is None or count < self._hold_after:
            return
        if self._held.reason_for(address) is not None:
            return
        try:
            await self._held.hold(address, f"reports:{count}")
        except Exception:
            _log.warning("the held list could not be written, the site is held in memory")
