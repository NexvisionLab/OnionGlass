# SPDX-License-Identifier: AGPL-3.0-only
"""Who may open what.

A policy answers one question for every request that would reach an onion site: may this visitor,
under this profile, open this address? The gateway asks before every fetch. If the policy cannot
answer in time, or fails in any way, the gateway refuses (property P7). A policy never changes
what a page looks like. That is the rewriter's job and it does not take instructions from here.

``StaticPolicy`` is the built-in one: a blocklist and an optional allowlist of onion addresses.
Anything else, such as a service that knows more about a site, plugs in through the same
``Policy`` interface.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from onionglass.onion import InvalidOnionError, OnionOrigin, parse_onion_url

MAX_LIST_BYTES = 8_000_000


class PolicyConfigError(ValueError):
    """A list or setting is wrong. Raised at start-up so a typo is never silently ignored."""


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """What the policy is told. It is never told the visitor's address, only who they are."""

    origin: OnionOrigin
    profile: str
    group: str
    subject: str
    action: str  # "open" for an address a visitor typed or was sent to, "fetch" for every request


@dataclass(frozen=True, slots=True)
class Decision:
    """The answer. ``rule`` names what decided it, for the audit log, and is never shown."""

    allowed: bool
    rule: str = "default"

    @classmethod
    def allow(cls, rule: str = "default") -> Decision:
        return cls(True, rule)

    @classmethod
    def deny(cls, rule: str) -> Decision:
        return cls(False, rule)


class Policy(Protocol):
    """Anything that can decide. It may be slow or fail, and the gateway then refuses."""

    async def decide(self, request: PolicyRequest) -> Decision: ...


def address_of(text: str) -> str:
    """The 56 character address named by ``text``, which may carry ``.onion`` or sub-domains.

    Raises ``InvalidOnionError`` if it is not a valid version 3 address.
    """
    candidate = text.strip().lower()
    if not candidate.endswith(".onion"):
        candidate = f"{candidate}.onion"
    return parse_onion_url(f"http://{candidate}/").origin.host.address


def parse_address_list(text: str) -> frozenset[str]:
    """Read a list with one onion address per line. ``#`` starts a comment.

    A line may be the bare address or a host name that ends in ``.onion``. A sub-domain names its
    whole address, since all of them are one site.
    """
    found: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        try:
            found.add(address_of(content))
        except InvalidOnionError as exc:
            raise PolicyConfigError(f"line {number}: not a valid onion address") from exc
    return frozenset(found)


def load_address_list(path: str | Path) -> frozenset[str]:
    """Read an address list from a file. A missing or unreadable file is an error."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyConfigError(f"cannot read {path}: {exc.strerror}") from exc
    if len(data) > MAX_LIST_BYTES:
        raise PolicyConfigError(f"{path} is too large")
    try:
        return parse_address_list(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PolicyConfigError(f"{path} is not valid UTF-8") from exc


class StaticPolicy:
    """A blocklist, and optionally an allowlist that everything else must be on."""

    def __init__(
        self,
        *,
        blocked: Iterable[str] = (),
        allowed: Iterable[str] | None = None,
    ) -> None:
        self._blocked = frozenset(address_of(a) for a in blocked)
        self._allowed = None if allowed is None else frozenset(address_of(a) for a in allowed)

    async def decide(self, request: PolicyRequest) -> Decision:
        address = request.origin.host.address
        if address in self._blocked:
            return Decision.deny("blocklist")
        if self._allowed is not None and address not in self._allowed:
            return Decision.deny("not-on-allowlist")
        return Decision.allow("static")
