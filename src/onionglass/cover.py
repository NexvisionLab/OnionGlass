# SPDX-License-Identifier: AGPL-3.0-only
"""Cover mode: what a visitor who has not signed in is shown.

A censor that visits a gateway's domain to see what it is should learn nothing. With cover mode on,
the gateway answers a stranger with a plain page at ``/`` and the same missing-page answer
everywhere else, as a small web server would. Only a valid sign-in link opens the gateway.

The pages here say nothing about what the gateway is. An operator can swap the front page for
their own, one self-contained file with its styles inline, which is served under a policy that
lets it load nothing and run nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

MAX_PAGE_BYTES = 200_000

DEFAULT_PAGE = (
    b'<!DOCTYPE html>\n<html lang="en">\n<head><meta charset="utf-8"><title>Welcome</title>'
    b"</head>\n<body><h1>Welcome</h1><p>This site is under construction.</p></body>\n</html>\n"
)
NOT_FOUND_PAGE = (
    b"<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n"
    b"<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body>\n"
    b"</html>\n"
)


@dataclass(frozen=True, slots=True)
class Cover:
    """The two pages a stranger can see: the front page, and the answer for everything else."""

    page: bytes = DEFAULT_PAGE
    not_found: bytes = NOT_FOUND_PAGE


def load_cover(path: Path) -> Cover:
    """A cover with the operator's own front page. Raises ``ValueError`` for a page that cannot be
    used, so a mistake stops the start and never silently shows the default."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"the cover page cannot be read: {path.name}") from exc
    if len(data) > MAX_PAGE_BYTES:
        raise ValueError(f"the cover page is too large (over {MAX_PAGE_BYTES} bytes)")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("the cover page must be UTF-8 text") from exc
    if not text.strip() or "\x00" in text:
        raise ValueError("the cover page is empty or not text")
    return Cover(page=data)
