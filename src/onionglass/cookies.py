# SPDX-License-Identifier: AGPL-3.0-only
"""A server-side cookie jar, one per visitor session and onion origin.

Security property P4: cookies set by an onion site never reach the visitor's browser. The gateway
keeps them here and attaches them to later requests to the same origin. This also keeps one
onion's cookies away from another's (P3), and means a visitor's browser holds nothing about the
sites they have looked at beyond the gateway's own session cookie.

Rules are those of RFC 6265, simplified for this setting:

* a cookie belongs to the exact origin that set it, so ``Domain`` can only ever name that host
  or a parent of it inside the same onion address, and is then treated as host-only
* every onion connection is encrypted end to end, so ``Secure`` is not used to hold cookies back
* ``SameSite`` is honoured. The gateway cannot see which site a visitor's browser is on, but it can
  see how the browser described each request (``Sec-Fetch-Site`` and friends), so it applies the
  same rules a browser would: a page on one onion cannot make the browser send a visitor's
  cookies for another onion unless that onion's cookie says ``SameSite=None``
* sizes and counts are limited so a site cannot fill the store
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from onionglass.onion import OnionOrigin
from onionglass.store import SessionStore

MAX_COOKIE_BYTES = 4096
MAX_COOKIES_PER_ORIGIN = 30
MAX_JAR_BYTES = 32_768
MAX_HEADER_BYTES = 8192
MAX_LIFETIME_SECONDS = 8 * 3600
_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~"
)


@dataclass(frozen=True, slots=True)
class Cookie:
    name: str
    value: str
    path: str
    expires: float | None  # seconds since the epoch, or None for a session cookie
    created: float
    same_site: str = "lax"  # "strict", "lax" or "none", as a browser would treat it


@dataclass(frozen=True, slots=True)
class RequestContext:
    """How the visitor's browser described a request, which decides which cookies go with it.

    ``same_origin`` is true when the request came from a page on the same onion origin, or from the
    visitor typing an address. ``navigation`` is true for a visitor-initiated navigation that uses
    a safe method (a link click), which is the only cross-origin case where ``Lax`` cookies go.
    The defaults describe an ordinary request from the site's own page.
    """

    same_origin: bool = True
    navigation: bool = False


@dataclass(frozen=True, slots=True)
class Deletion:
    """A ``Set-Cookie`` that asks for a cookie to be removed."""

    name: str
    path: str


def _valid_name(name: str) -> bool:
    return bool(name) and len(name) <= 256 and set(name) <= _NAME_CHARS


def _valid_value(value: str) -> bool:
    return value.isascii() and not any(
        ord(c) < 0x20 or ord(c) == 0x7F or c in ' ",;\\' for c in value
    )


def _default_path(request_path: str) -> str:
    path = urlsplit(request_path).path
    if not path.startswith("/") or path.count("/") <= 1:
        return "/"
    return path[: path.rindex("/")] or "/"


def _expiry(attributes: dict[str, str], now: float) -> tuple[bool, float | None]:
    """Whether the cookie is already expired, and otherwise when it expires (None: session)."""
    max_age = attributes.get("max-age")
    if max_age is not None:
        digits = max_age[1:] if max_age.startswith("-") else max_age
        if digits.isascii() and digits.isdigit() and len(digits) <= 12:
            seconds = int(max_age)
            if seconds <= 0:
                return True, None
            return False, now + min(seconds, MAX_LIFETIME_SECONDS)
    expires = attributes.get("expires")
    if expires is not None:
        try:
            parsed = parsedate_to_datetime(expires)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)  # "-0000" means UTC, not this machine's zone
            moment = parsed.timestamp()
        except (TypeError, ValueError, IndexError, OverflowError, OSError):
            return False, None
        if moment <= now:
            return True, None
        return False, min(moment, now + MAX_LIFETIME_SECONDS)
    return False, None


def parse_set_cookie(
    header: str, origin: OnionOrigin, request_path: str, now: float
) -> Cookie | Deletion | None:
    """Parse one ``Set-Cookie`` header.

    Returns a Cookie to store, a Deletion if it asks for a cookie to be removed, or ``None`` if
    the header must be ignored.
    """
    if len(header) > MAX_COOKIE_BYTES or not header.isascii():
        return None
    if any((ord(c) < 0x20 and c != "\t") or ord(c) == 0x7F for c in header):
        return None
    first, *rest = header.split(";")
    name, equals, value = first.partition("=")
    name, value = name.strip(), value.strip()
    if not equals or not _valid_name(name) or not _valid_value(value):
        return None
    attributes: dict[str, str] = {}
    for item in rest:
        key, _, val = item.partition("=")
        attributes[key.strip().lower()] = val.strip()
    domain = attributes.get("domain")
    if domain:
        wanted = domain.lstrip(".").lower()
        host = origin.host.hostname
        if wanted != host and not host.endswith("." + wanted):
            return None
        if not wanted.endswith(f"{origin.host.address}.onion"):
            return None  # a cookie may be shared up to the onion address and no further
    path = attributes.get("path", "")
    if not path.startswith("/") or not path.isascii():
        path = _default_path(request_path)
    expired, expires = _expiry(attributes, now)
    if expired:
        return Deletion(name=name, path=path)
    same_site = attributes.get("samesite", "").lower()
    if same_site not in ("strict", "lax", "none"):
        same_site = "lax"  # what current browsers do when the attribute is missing
    return Cookie(
        name=name, value=value, path=path, expires=expires, created=now, same_site=same_site
    )


def _sent_in(cookie: Cookie, context: RequestContext) -> bool:
    """The SameSite rule: which cookies a browser would attach to this kind of request."""
    if context.same_origin or cookie.same_site == "none":
        return True
    return cookie.same_site == "lax" and context.navigation


def _path_matches(cookie_path: str, request_path: str) -> bool:
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


class CookieJar:
    """Stores cookies in the session store, keyed by session and origin."""

    def __init__(
        self,
        store: SessionStore,
        *,
        ttl: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._ttl = ttl
        self._clock = clock

    @staticmethod
    def _key(session_id: str, origin: OnionOrigin) -> str:
        return f"jar:{session_id}:{origin.key}"

    async def _load(self, session_id: str, origin: OnionOrigin) -> list[Cookie]:
        raw = await self._store.get(self._key(session_id, origin))
        if raw is None:
            return []
        try:
            now = self._clock()
            cookies = [Cookie(**item) for item in json.loads(raw)]
        except (ValueError, TypeError):
            return []
        return [c for c in cookies if c.expires is None or c.expires > now]

    async def _save(self, session_id: str, origin: OnionOrigin, cookies: list[Cookie]) -> None:
        ordered = sorted(cookies, key=lambda c: c.created)
        payload = json.dumps([asdict(c) for c in ordered], separators=(",", ":"))
        while len(payload) > MAX_JAR_BYTES and ordered:
            ordered.pop(0)  # make room by dropping the oldest cookie
            payload = json.dumps([asdict(c) for c in ordered], separators=(",", ":"))
        await self._store.put(self._key(session_id, origin), payload, self._ttl)

    async def store_from_response(
        self,
        session_id: str,
        origin: OnionOrigin,
        request_path: str,
        set_cookie_headers: list[str],
    ) -> int:
        """Apply the ``Set-Cookie`` headers of a response. Returns how many cookies changed."""
        if not set_cookie_headers:
            return 0
        now = self._clock()
        cookies = await self._load(session_id, origin)
        changed = 0
        for header in set_cookie_headers[:MAX_COOKIES_PER_ORIGIN]:
            parsed = parse_set_cookie(header, origin, request_path, now)
            if parsed is None:
                continue
            before = len(cookies)
            cookies = [c for c in cookies if not (c.name == parsed.name and c.path == parsed.path)]
            if isinstance(parsed, Cookie):
                cookies.append(parsed)
                changed += 1
            else:
                changed += before - len(cookies)
        if len(cookies) > MAX_COOKIES_PER_ORIGIN:
            cookies = sorted(cookies, key=lambda c: c.created)[-MAX_COOKIES_PER_ORIGIN:]
        if changed:
            await self._save(session_id, origin, cookies)
        return changed

    async def header_for(
        self,
        session_id: str,
        origin: OnionOrigin,
        request_target: str,
        context: RequestContext | None = None,
    ) -> str | None:
        """The ``Cookie`` header to send with a request, or None if there is nothing to send."""
        context = context or RequestContext()
        path = urlsplit(request_target).path or "/"
        cookies = [
            c
            for c in await self._load(session_id, origin)
            if _path_matches(c.path, path) and _sent_in(c, context)
        ]
        if not cookies:
            return None
        # When the header would be too long, keep the most specific and the newest cookies: the
        # newest is the one most likely to be a fresh session. Then put them in the usual order.
        kept: list[Cookie] = []
        size = 0
        for cookie in sorted(cookies, key=lambda c: (-len(c.path), -c.created)):
            piece = len(cookie.name) + len(cookie.value) + 3
            if size + piece <= MAX_HEADER_BYTES:
                kept.append(cookie)
                size += piece
        kept.sort(key=lambda c: (-len(c.path), c.created))
        return "; ".join(f"{c.name}={c.value}" for c in kept) or None

    async def clear(self, session_id: str, origin: OnionOrigin) -> None:
        await self._store.delete(self._key(session_id, origin))
