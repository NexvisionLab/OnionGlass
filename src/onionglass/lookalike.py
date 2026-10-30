# SPDX-License-Identifier: AGPL-3.0-only
"""Warn before opening an address that imitates a well-known one.

Onion addresses cannot be read by people, so a copycat of a popular site is made by searching for
an address that starts like the real one. That search is cheap for a few characters and costs more
with every extra one. The last characters cannot be chosen at all, because they are a checksum. So
the only imitation that can be made is one that shares the start, and that is what is checked.

The operator keeps a short list of sites people are likely to mean, each with a name. An address
that starts like one of them, and is not it, gets a warning page before anything is fetched.
A genuine address never starts the same way by chance: six characters are 30 bits, so the chance
that a given unrelated site shares them with a given listed one is about one in a billion.

What this does not do: it knows only the sites on the list, it looks at addresses people type and
not at links on pages, and it cannot tell which of two similar addresses is the real one. It says
that they are different and shows the listed one, and the visitor decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from onionglass.onion import InvalidOnionError
from onionglass.policy import PolicyConfigError, address_of

MIN_SHARED_PREFIX = 6
MAX_ENTRIES = 10_000
MAX_LIST_BYTES = 1_000_000
MAX_NAME = 80
DEFAULT_NAME = "a well-known site"


@dataclass(frozen=True, slots=True)
class KnownSite:
    address: str
    name: str


def _name_ok(name: str) -> bool:
    return 0 < len(name) <= MAX_NAME and name.isprintable() and name.isascii()


class KnownSites:
    """The sites people are likely to mean, and the check against them."""

    def __init__(self, sites: list[KnownSite]) -> None:
        if len(sites) > MAX_ENTRIES:
            raise PolicyConfigError("the known sites list is too long")
        self._by_address = {site.address: site for site in sites}
        self._by_prefix: dict[str, list[KnownSite]] = {}
        for site in self._by_address.values():
            self._by_prefix.setdefault(site.address[:MIN_SHARED_PREFIX], []).append(site)

    def __len__(self) -> int:
        return len(self._by_address)

    def lookalike_of(self, address: str) -> KnownSite | None:
        """The listed site this address imitates, or None. A listed address itself is no copy."""
        if address in self._by_address:
            return None
        matches = self._by_prefix.get(address[:MIN_SHARED_PREFIX])
        return matches[0] if matches else None


def parse_known_sites(text: str) -> KnownSites:
    """One site per line: the address, then a name. ``#`` starts a comment."""
    sites: list[KnownSite] = []
    for number, line in enumerate(text.splitlines(), start=1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        address_text, _, name = content.partition(" ")
        name = " ".join(name.split()) or DEFAULT_NAME
        try:
            address = address_of(address_text)
        except InvalidOnionError as exc:
            raise PolicyConfigError(f"line {number}: not a valid onion address") from exc
        if not _name_ok(name):
            raise PolicyConfigError(
                f"line {number}: the name must be plain printable ASCII, at most {MAX_NAME} long"
            )
        sites.append(KnownSite(address, name))
    return KnownSites(sites)


def load_known_sites(path: str | Path) -> KnownSites:
    """Read the list from a file. A missing or unreadable file is an error."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyConfigError(f"cannot read {path}: {exc.strerror}") from exc
    if len(data) > MAX_LIST_BYTES:
        raise PolicyConfigError(f"{path} is too large")
    try:
        return parse_known_sites(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PolicyConfigError(f"{path} is not valid UTF-8") from exc
