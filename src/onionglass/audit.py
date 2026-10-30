# SPDX-License-Identifier: AGPL-3.0-only
"""The audit log: who opened what, never what they saw.

Every request that reaches an onion site is recorded before it goes out, and its outcome is
recorded when it comes back. If the log cannot be written, the gateway refuses the request
(property P7), so nothing happens that is not on record. What is recorded:

* when, what happened, and which rule decided it
* the visitor's profile, group and subject, exactly as the sign-in service gave them
* the onion site, in the form the operator chose (see ``address_form``), and the status

What is never recorded: page or form bodies, headers, cookies, and the visitor's network address,
which the gateway does not keep at all (property P10).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

AddressForm = Literal["full", "origin", "hash", "none"]
ADDRESS_FORMS: tuple[str, ...] = ("full", "origin", "hash", "none")
MAX_FIELD = 200


class AuditError(Exception):
    """The event could not be recorded."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    kind: str  # "allowed", "refused", "response" or "failed"
    action: str  # "open" or "fetch"
    rule: str
    profile: str
    group: str
    subject: str
    origin: str  # scheme://host:port of the onion site
    path: str  # path and query, only recorded when the address form is "full"
    status: int | None = None
    time: float | None = None  # seconds since the epoch, filled in when it is written


class AuditSink(Protocol):
    """Anything that can record an event. Failing to do so makes the gateway refuse."""

    async def write(self, event: AuditEvent) -> None: ...


class MemoryAudit:
    """Keeps events in memory. For tests and for embedding the gateway in another program."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def write(self, event: AuditEvent) -> None:
        self.events.append(event)


def _clip(value: str) -> str:
    return value[:MAX_FIELD]


def in_address_form(event: AuditEvent, form: AddressForm, salt: bytes) -> AuditEvent:
    """The event with the onion site named only as the operator chose.

    ``full`` keeps the path, ``origin`` drops it, ``hash`` replaces the whole address with a keyed
    hash that is stable for one salt, and ``none`` leaves no trace of the site at all.
    """
    if form == "full":
        return event
    if form == "origin":
        return replace(event, path="")
    if form == "hash":
        digest = hmac.new(salt, event.origin.encode("utf-8"), hashlib.sha256)
        return replace(event, origin="h:" + digest.hexdigest()[:16], path="")
    return replace(event, origin="", path="")


class JsonLinesAudit:
    """Appends one JSON object per line to a file.

    The file is opened for every event, so moving it away for rotation just works. It is created
    readable by its owner only.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        address_form: AddressForm = "origin",
        salt: bytes | None = None,
    ) -> None:
        if address_form not in ADDRESS_FORMS:
            raise ValueError(f"address form must be one of {ADDRESS_FORMS}")
        self._path = Path(path)
        self._form = address_form
        # Without a salt of the operator's own, hashes are only comparable until a restart.
        self._salt = salt or secrets.token_bytes(32)
        self._lock = asyncio.Lock()

    def render(self, event: AuditEvent) -> str:
        record: dict[str, object] = {
            "time": datetime.fromtimestamp(event.time or time.time(), UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "kind": event.kind,
            "action": event.action,
            "rule": _clip(event.rule),
            "profile": _clip(event.profile),
            "group": _clip(event.group),
            "subject": _clip(event.subject),
            "status": event.status,
        }
        shown = in_address_form(event, self._form, self._salt)
        if self._form != "none":
            record["target"] = _clip(shown.origin) + shown.path[:1000]
        return json.dumps(record, separators=(",", ":"), sort_keys=True)

    def _append(self, line: str) -> None:
        descriptor = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            handle.write(line.encode("utf-8") + b"\n")
            handle.flush()

    async def write(self, event: AuditEvent) -> None:
        line = self.render(event)
        try:
            async with self._lock:
                await asyncio.to_thread(self._append, line)
        except OSError as exc:
            raise AuditError("the audit log could not be written") from exc
