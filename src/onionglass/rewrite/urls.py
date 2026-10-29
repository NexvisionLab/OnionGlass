# SPDX-License-Identifier: AGPL-3.0-only
"""Turning the references in a page into gateway URLs.

Security property P2: a rewritten page never makes the visitor's browser contact any host other
than the gateway. Every reference found in a page goes through ``resolve_reference``, which
returns one of four outcomes and nothing else:

* ``onion``: the reference points at an onion origin and became a URL on the gateway
* ``external``: it points at the normal internet and became the gateway's warning page
* ``local``: it points inside the current page (empty or fragment only)
* ``dropped``: it is unsafe, malformed or not a web link, and the attribute must be removed
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import quote, urljoin, urlsplit

from onionglass.onion import InvalidOnionError, OnionOrigin, OnionUrl, parse_onion_url

MAX_EXTERNAL_LENGTH = 2048
_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.")
_ENCODE_SAFE = "!#$%&'()*+,/:;=?@[]~-._"
_NON_WEB_SCHEMES = frozenset(
    {"mailto", "tel", "sms", "magnet", "bitcoin", "monero", "ethereum", "litecoin", "xmpp", "irc"}
)

Kind = Literal["onion", "external", "local", "dropped"]


class UrlMapper(Protocol):
    """How the rewriter learns where things live on the gateway."""

    def onion(self, origin: OnionOrigin) -> str:
        """The gateway origin that serves this onion origin, like ``https://<label>.example``.

        No trailing slash.
        """
        ...

    def external(self, url: str) -> str:
        """The URL of the gateway's warning page for a link that leaves Tor."""
        ...

    def owns(self, url: str) -> bool:
        """True if ``url`` is something this mapper produced, or a safe local reference."""
        ...


@dataclass(frozen=True, slots=True)
class Resolved:
    kind: Kind
    url: str = ""
    reason: str = ""


def _dropped(reason: str) -> Resolved:
    return Resolved("dropped", "", reason)


def _clean(reference: str) -> str | None:
    """Apply what browsers do before parsing a reference, or None if it cannot be trusted.

    Leading and trailing control characters and spaces go, tabs and line breaks inside the text
    go, and a backslash before the query means a slash. Anything else that is a control character
    makes the reference unusable.
    """
    text = reference.strip("".join(chr(c) for c in range(0x21)))
    text = text.replace("\t", "").replace("\n", "").replace("\r", "")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return None
    cut = len(text)
    for marker in ("?", "#"):
        position = text.find(marker)
        if position != -1:
            cut = min(cut, position)
    head = text[:cut].replace("\\", "/")
    tail = text[cut:].replace("\\", "%5C")
    return quote(head + tail, safe=_ENCODE_SAFE)


def _scheme(text: str) -> str | None:
    colon = text.find(":")
    if colon <= 0:
        return None
    candidate = text[:colon]
    if candidate[0].isalpha() and candidate.isascii() and set(candidate) <= _SCHEME_CHARS:
        return candidate.lower()
    return None


def _onion_result(parsed: OnionUrl, fragment: str, mapper: UrlMapper) -> Resolved:
    url = mapper.onion(parsed.origin) + parsed.path
    if parsed.query:
        url += "?" + parsed.query
    if fragment:
        url += "#" + fragment
    return Resolved("onion", url)


def resolve_reference(reference: str, base: OnionUrl, mapper: UrlMapper) -> Resolved:
    """Decide what a reference found on the page at ``base`` becomes."""
    text = _clean(reference)
    if text is None:
        return _dropped("control_characters")
    if text == "":
        return Resolved("local", "")
    if text.startswith("#"):
        return Resolved("local", text)
    scheme = _scheme(text)
    if scheme is not None and scheme not in ("http", "https"):
        return _dropped("non_web_link" if scheme in _NON_WEB_SCHEMES else "unsafe_scheme")
    try:
        joined = urljoin(base.url, text)
        parts = urlsplit(joined)
    except ValueError:
        return _dropped("unparseable")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return _dropped("not_a_web_url")
    try:
        parsed = parse_onion_url(joined)
    except InvalidOnionError:
        host = parts.hostname.lower()
        if host == "onion" or host.endswith(".onion"):
            return _dropped("invalid_onion_url")
        return _external(parts.netloc, joined, mapper)
    return _onion_result(parsed, parts.fragment, mapper)


def _external(netloc: str, joined: str, mapper: UrlMapper) -> Resolved:
    without_fragment = joined.split("#", 1)[0]
    if "@" in netloc:
        # Never show or follow user information; it is a common way to disguise a destination.
        host_and_port = netloc.rsplit("@", 1)[1]
        without_fragment = without_fragment.replace(netloc, host_and_port, 1)
    if len(without_fragment) > MAX_EXTERNAL_LENGTH or not without_fragment.isascii():
        return _dropped("external_url_too_long")
    return Resolved("external", mapper.external(without_fragment))
