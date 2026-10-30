# SPDX-License-Identifier: AGPL-3.0-only
"""The name gate: refuse a page whose title or headings name something the operator forbids.

Some onion sites name what they hold in their title. The gate looks at the page title and the
first few headings of every page that comes back, and when one of them contains a listed phrase
the page is refused and the site is put on the held list until someone reviews it (see
``held.py``).

The list is the operator's own. The project ships none, and the repository never holds one: what
belongs on it is a legal and operational decision, and the words themselves are not something to
publish. A phrase matches whole words only, so a word inside a longer, innocent word is not a hit.
A single word may end in ``*`` to match any word that starts with it.

What it does not do: it does not read the body of the page, it does not understand images, and a
page in a script or spelling the list does not cover gets through. It is one layer, next to the
address blocklist and the held list, not a substitute for review.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from pathlib import Path

from onionglass.policy import PolicyConfigError

MAX_PATTERNS = 100_000
MAX_LIST_BYTES = 8_000_000
_LOOKALIKES = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)


def _words(text: str, *, lookalikes: bool = False) -> list[str]:
    """Lower-case words with accents, width variants and invisible characters removed."""
    kept: list[str] = []
    for char in unicodedata.normalize("NFKD", text):
        if unicodedata.category(char) in ("Mn", "Cf"):
            continue  # accents and zero-width characters, which could split or hide a word
        kept.append(char.casefold())
    flat = "".join(kept)
    if lookalikes:
        flat = flat.translate(_LOOKALIKES)
    words: list[str] = []
    current: list[str] = []
    for char in flat:
        if char.isalnum():
            current.append(char)
        elif current:
            words.append("".join(current))
            current = []
    if current:
        words.append("".join(current))
    return words


class NameGate:
    """Checks short texts against a list of forbidden phrases."""

    def __init__(self, phrases: Iterable[str]) -> None:
        self._phrases: set[tuple[str, ...]] = set()
        self._prefixes: set[str] = set()
        self._longest = 1
        for number, raw in enumerate(phrases, start=1):
            text = raw.strip()
            prefix = text.endswith("*")
            words = tuple(_words(text.rstrip("*")))
            if not words:
                raise PolicyConfigError(f"entry {number}: nothing to match")
            if prefix and len(words) != 1:
                raise PolicyConfigError(f"entry {number}: only a single word can end in *")
            if prefix:
                self._prefixes.add(words[0])
            else:
                self._phrases.add(words)
                self._longest = max(self._longest, len(words))
        if len(self._phrases) + len(self._prefixes) > MAX_PATTERNS:
            raise PolicyConfigError("the name list is too long")

    def _hit(self, words: list[str]) -> bool:
        for word in words:
            if any(word[:size] in self._prefixes for size in range(1, len(word) + 1)):
                return True
        for start in range(len(words)):
            for size in range(1, self._longest + 1):
                if tuple(words[start : start + size]) in self._phrases:
                    return True
        return False

    def check(self, *texts: str) -> bool:
        """True if any of the texts contains a listed phrase."""
        for text in texts:
            if not text:
                continue
            if self._hit(_words(text)) or self._hit(_words(text, lookalikes=True)):
                return True
        return False


def parse_name_list(text: str) -> list[str]:
    """One phrase per line. ``#`` starts a comment."""
    phrases = []
    for line in text.splitlines():
        content = line.split("#", 1)[0].strip()
        if content:
            phrases.append(content)
    return phrases


def load_name_gate(path: str | Path) -> NameGate:
    """Read a name list from a file. A missing or unreadable file is an error."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyConfigError(f"cannot read {path}: {exc.strerror}") from exc
    if len(data) > MAX_LIST_BYTES:
        raise PolicyConfigError(f"{path} is too large")
    try:
        return NameGate(parse_name_list(data.decode("utf-8")))
    except UnicodeDecodeError as exc:
        raise PolicyConfigError(f"{path} is not valid UTF-8") from exc
