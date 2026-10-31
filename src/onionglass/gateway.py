# SPDX-License-Identifier: AGPL-3.0-only
"""The gateway web application.

Two kinds of host name reach it. The main domain serves the entry form, sign-in and the warning
page. Every other name is an opaque label that stands for one onion origin in one visitor
session, and serves that onion's pages after they have been made safe.

Everything a request needs is checked in this order: the host is the main domain or a known
label, the session is alive, the visitor is allowed to use that label, and only then is the onion
site contacted. Failures end in a short error page. Nothing that identifies a visitor or an
address is written to the log.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, quote, unquote_plus, urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

import onionglass
from onionglass import pages
from onionglass.audit import AuditEvent
from onionglass.cookies import CookieJar, RequestContext
from onionglass.decode import DecodeError, decode_body
from onionglass.entities import extract_entities
from onionglass.headers import (
    ACCEPT_ANY,
    ACCEPT_HTML,
    apex_headers,
    document_headers,
    multipart_boundary,
    normalise_multipart,
    parse_content_type,
    resource_headers,
    upstream_request_headers,
    viewer_headers,
)
from onionglass.labels import LabelBook, LabelError, is_valid_label, is_valid_session_id
from onionglass.mapper import PlaceholderMapper
from onionglass.metrics import Metrics, reason_for, token_matches
from onionglass.onion import InvalidOnionError, OnionHost, OnionOrigin, OnionUrl, parse_onion_url
from onionglass.policy import Decision, PolicyRequest
from onionglass.reports import CATEGORIES, ReportError
from onionglass.rewrite.css import CssError, CssOptions, sanitize_stylesheet, verify_stylesheet
from onionglass.rewrite.html import HtmlOptions, RewriteError, decode_document, rewrite_html
from onionglass.rewrite.urls import resolve_reference
from onionglass.settings import Profile, Settings
from onionglass.store import InMemoryStore, SessionStore, StoreFullError
from onionglass.tickets import TicketError, TicketVerifier
from onionglass.upstream import Fetcher, UpstreamError, UpstreamRequest, UpstreamResponse

_log = logging.getLogger("onionglass")


class _TooBusyError(Exception):
    """Too many new sessions in a short time."""


@dataclass(frozen=True, slots=True)
class _Verdict:
    """What screening decided: an error kind if refused, else whether to show text only."""

    refusal: str | None = None
    text_only: bool = False
    rule: str = ""


@dataclass(frozen=True, slots=True)
class _Who:
    """The visitor as the sign-in service described them. Never a network address."""

    subject: str
    group: str
    profile: str


def _typed_address(text: str) -> OnionUrl | None:
    """The address a visitor typed into the entry form, or None if it is not a usable one."""
    text = text.strip()
    if not text or len(text) > 2000:
        return None
    try:
        return parse_onion_url(text if "://" in text else f"http://{text}")
    except InvalidOnionError:
        return None


def _names_a_file(header_block: bytes) -> bool:
    """True if a part's header lines name a file: ``filename`` or ``filename*`` as a parameter.

    A plain scan for the word, with a look at what is on either side, done by position and never
    by copying the text, so the time taken grows in step with the size of the block and a crafted
    block cannot make it grow faster.
    """
    lowered = header_block.lower()
    size = len(lowered)
    position = lowered.find(b"filename")
    while position != -1:
        before = position - 1
        while before >= 0 and lowered[before] in b" \t":
            before -= 1
        after = position + 8
        while after < size and lowered[after] in b" \t":
            after += 1
        if before >= 0 and lowered[before] == 0x3B and after < size and lowered[after] in b"=*":
            return True
        position = lowered.find(b"filename", position + 8)
    return False


def _has_file_part(body: bytes, content_type: str | None) -> bool:
    """True if a multipart body carries a file, whatever else it holds.

    Each part starts at a delimiter and its header lines end at the first blank line, so only
    those lines are looked at, once each. A body that cannot be read as multipart counts as
    having a file, because it cannot be shown not to.
    """
    if content_type is None or parse_content_type(content_type)[0] != "multipart/form-data":
        return False
    boundary = multipart_boundary(content_type)
    if boundary is None:
        return True
    delimiter = b"--" + boundary.encode("ascii")
    start = body.find(delimiter)
    while start != -1:
        head_start = start + len(delimiter)
        following = body.find(delimiter, head_start)
        limit = len(body) if following == -1 else following
        blank = body.find(b"\r\n\r\n", head_start, limit)
        if _names_a_file(body[head_start : limit if blank == -1 else blank]):
            return True
        start = following
    return False


_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_FONT_TYPES = frozenset(
    {
        "font/woff2",
        "font/woff",
        "font/ttf",
        "font/otf",
        "application/font-woff",
        "application/font-woff2",
        "application/x-font-ttf",
        "application/x-font-otf",
        "application/vnd.ms-fontobject",
    }
)
_IMAGE_TYPES = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/avif",
        "image/bmp",
        "image/x-icon",
        "image/vnd.microsoft.icon",
    }
)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ACCEPT_BY_DESTINATION = {
    "style": "text/css,*/*;q=0.1",
    "image": "image/avif,image/webp,image/png,image/jpeg,*/*;q=0.5",
    "font": ACCEPT_ANY,
}
_FORM_LIMIT = 8192
_NAVIGATION_DESTINATIONS = frozenset({"iframe", "document", "frame"})


class Gateway:
    """Builds the web application around a fetcher, a store and the settings."""

    def __init__(
        self,
        settings: Settings,
        *,
        fetcher: Fetcher,
        store: SessionStore | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.fetcher = fetcher
        self._clock = clock
        self.store = store or InMemoryStore()
        self.labels = LabelBook(
            self.store,
            ttl=settings.session_ttl,
            max_per_session=settings.max_labels_per_session,
            max_reserved=settings.max_opens_per_session,
        )
        self.jar = CookieJar(self.store, ttl=settings.session_ttl)
        self.verifier = (
            TicketVerifier(settings.keys, settings.audience) if settings.keys is not None else None
        )
        # What follows is per process and rebuilt on restart, which is the point: a restart
        # starts every session on a new Tor circuit, and no secret is kept on disk.
        self._isolation_secret = secrets.token_bytes(32)
        self._active_fetches = 0
        self._active_by_session: dict[str, int] = {}
        self._new_sessions: deque[float] = deque()
        self._requests: dict[str, deque[float]] = {}
        self.metrics = Metrics(pages.ERRORS)
        self.app = Starlette(
            routes=[Route("/{path:path}", self._handle, methods=["GET", "HEAD", "POST"])]
        )

    # --- helpers ---------------------------------------------------------------------------

    def _apex(
        self, body: bytes, status: int = 200, *, form: bool = False, framed: bool = False
    ) -> Response:
        headers = apex_headers(self.settings.header_policy, form=form, framed=framed)
        return Response(body, status, headers)

    def _error(self, kind: str, *, apex: bool = False) -> Response:
        status, body = pages.error_page(kind)
        if apex:
            return self._apex(body, status)
        return Response(body, status, document_headers(self.settings.header_policy))

    def _gateway_url(self, label: str, path: str = "/", query: str = "") -> str:
        port = f":{self.settings.port}" if self.settings.port is not None else ""
        suffix = f"?{query}" if query else ""
        return f"{self.settings.scheme}://{label}.{self.settings.base_domain}{port}{path}{suffix}"

    def _set_session_cookie(self, response: Response, session_id: str) -> None:
        settings = self.settings
        response.set_cookie(
            settings.cookie_name,
            session_id,
            max_age=int(settings.session_ttl),
            path="/",
            domain=None if settings.base_domain == "localhost" else settings.base_domain,
            secure=settings.scheme == "https",
            httponly=True,
            samesite="lax",
        )

    async def _create_session(self, subject: str, group: str, profile: str) -> str:
        now = self._clock()
        while self._new_sessions and now - self._new_sessions[0] > 60:
            self._new_sessions.popleft()
        if len(self._new_sessions) >= self.settings.max_new_sessions_per_minute:
            raise _TooBusyError
        self._new_sessions.append(now)
        session_id = secrets.token_urlsafe(24)
        self.metrics.inc("sessions_created_total")
        record = json.dumps({"sub": subject, "grp": group, "prf": profile})
        await self.store.put(f"sess:{session_id}", record, self.settings.session_ttl)
        return session_id

    # --- policy, kill switches and the audit log ------------------------------------------

    def _who(self, record: str | None) -> _Who:
        default = self.settings.profile.name
        try:
            data = json.loads(record or "")
            return _Who(str(data["sub"]), str(data["grp"]), str(data["prf"]))
        except (ValueError, KeyError, TypeError):
            return _Who("local", "local", default)

    async def _who_of(self, session_id: str | None) -> _Who:
        record = await self.store.get(f"sess:{session_id}") if session_id else None
        return self._who(record)

    def _count(self, kind: str, action: str, rule: str, status: int | None) -> None:
        """Count an event. Only fixed label values are used, never an address or an account."""
        metrics = self.metrics
        if kind in ("allowed", "refused"):
            metrics.inc("requests_total", action=action, outcome=kind)
            if kind == "refused":
                metrics.inc("refusals_total", reason=reason_for(rule))
        elif kind == "response" and status is not None:
            metrics.inc("upstream_responses_total", **{"class": f"{status // 100}xx"})
        elif kind == "failed":
            metrics.inc("upstream_errors_total", kind=rule)
        elif kind == "report":
            metrics.inc("reports_total", category=rule)

    async def _record(
        self,
        kind: str,
        who: _Who,
        origin: OnionOrigin,
        action: str,
        *,
        rule: str = "",
        path: str = "",
        status: int | None = None,
    ) -> bool:
        """Write an audit event. False means the sink is configured and failed."""
        self._count(kind, action, rule, status)
        sink = self.settings.audit
        if sink is None:
            return True
        event = AuditEvent(
            kind=kind,
            action=action,
            rule=rule,
            profile=who.profile,
            group=who.group,
            subject=who.subject,
            origin=origin.key,
            path=path,
            status=status,
            time=time.time(),
        )
        try:
            await asyncio.wait_for(sink.write(event), timeout=self.settings.hook_timeout)
        except Exception:
            _log.warning("the audit log could not be written")
            return False
        return True

    async def _quota_check(self, who: _Who, profile: Profile, cost: int) -> str | None:
        """The error kind if this account has no allowance left for ``cost``, else None."""
        limit = profile.daily_quota
        meter = self.settings.quota
        if limit is None or meter is None:
            return None
        try:
            used = await asyncio.wait_for(
                meter.used(who.subject, profile.name), timeout=self.settings.hook_timeout
            )
        except Exception:
            _log.warning("the quota meter could not be read, so the request was refused")
            return "quota_unavailable"
        return "quota_exhausted" if used + max(cost, 1) > limit else None

    async def _reserve(self, who: _Who, profile: Profile, units: int) -> str | None:
        """Take ``units`` from the allowance only if that leaves it within its limit.

        The check and the taking are one step in the meter, so requests that arrive together
        cannot all pass a check made before any of them was counted. None means it was taken.
        """
        limit = profile.daily_quota
        meter = self.settings.quota
        if limit is None or meter is None or units <= 0:
            return None
        try:
            taken = await asyncio.wait_for(
                meter.reserve(who.subject, profile.name, units, limit),
                timeout=self.settings.hook_timeout,
            )
        except Exception:
            _log.warning("the quota meter could not be written")
            return "quota_unavailable"
        return None if taken else "quota_exhausted"

    async def _charge(self, who: _Who, profile: Profile, units: int) -> bool:
        """Take ``units`` from the account's allowance. False means the meter failed."""
        meter = self.settings.quota
        if profile.daily_quota is None or meter is None or units <= 0:
            return True
        try:
            await asyncio.wait_for(
                meter.charge(who.subject, profile.name, units), timeout=self.settings.hook_timeout
            )
        except Exception:
            _log.warning("the quota meter could not be written")
            return False
        return True

    async def _screen(self, who: _Who, origin: OnionOrigin, action: str, path: str) -> _Verdict:
        """The kill switch, the held list and the policy, in that order. Records every refusal."""
        settings = self.settings
        address = origin.host.address
        if settings.kill is not None:
            scope = settings.kill.engaged(profile=who.profile, address=address)
            if scope is not None:
                await self._record("refused", who, origin, action, rule=f"kill:{scope}", path=path)
                return _Verdict("paused")
        if settings.held is not None:
            reason = settings.held.reason_for(address)
            if reason is not None:
                await self._record("refused", who, origin, action, rule=reason, path=path)
                return _Verdict("denied")
        if settings.policy is None:
            return _Verdict()
        request = PolicyRequest(origin, who.profile, who.group, who.subject, action)
        try:
            decision = await asyncio.wait_for(
                settings.policy.decide(request), timeout=settings.hook_timeout
            )
            if not isinstance(decision, Decision):
                raise TypeError("a policy must return a Decision")
        except Exception:
            _log.warning("the policy could not decide, so the request was refused")
            await self._record("refused", who, origin, action, rule="policy-unavailable", path=path)
            return _Verdict("policy_unavailable")
        if not decision.allowed:
            await self._record("refused", who, origin, action, rule=decision.rule, path=path)
            return _Verdict("denied")
        return _Verdict(None, decision.text_only, decision.rule)

    async def _refusal(
        self, who: _Who, profile: Profile, origin: OnionOrigin, action: str, path: str
    ) -> _Verdict:
        """Whether this request may go ahead, and if so whether the page is shown as text only.

        Order matters: the cheap and sure checks first, then the allowance, and last the audit
        record, which must be written before the request goes out.
        """
        verdict = await self._screen(who, origin, action, path)
        if verdict.refusal is not None:
            return verdict
        cost = profile.open_cost if action == "open" else 0
        # An empty allowance stops opening. It only stops fetching when pages are what is counted,
        # so a visitor who has used their opens can still read the sites they already opened.
        counted = action == "open" or profile.page_cost > 0
        exhausted = await self._quota_check(who, profile, cost) if counted else None
        if exhausted is not None:
            await self._record("refused", who, origin, action, rule="quota", path=path)
            return _Verdict(exhausted)
        if not await self._record("allowed", who, origin, action, rule=verdict.rule, path=path):
            self.metrics.inc("refusals_total", reason="audit-unavailable")
            return _Verdict("audit_unavailable")
        short = await self._reserve(who, profile, cost)
        if short is not None:
            rule = "quota" if short == "quota_exhausted" else "quota-unavailable"
            await self._record("refused", who, origin, action, rule=rule, path=path)
            return _Verdict(short)
        return verdict

    async def _admit(
        self,
        who: _Who,
        profile: Profile,
        origin: OnionOrigin,
        action: str,
        *,
        path: str = "",
        apex: bool = False,
    ) -> Response | bool:
        """The refusal to send, or whether the page is to be shown as text only."""
        verdict = await self._refusal(who, profile, origin, action, path)
        if verdict.refusal is not None:
            return self._error(verdict.refusal, apex=apex)
        return verdict.text_only

    def _take_rate_slot(self, session_id: str, profile: Profile) -> bool:
        """Count a request against the profile's per-minute limit. False means slow down."""
        limit = profile.max_requests_per_minute
        if limit is None:
            return True
        now = self._clock()
        window = self._requests.setdefault(session_id, deque())
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        if len(self._requests) > 10_000:
            for key in [k for k, v in self._requests.items() if not v or now - v[-1] > 60]:
                del self._requests[key]
        return True

    async def _current_session(self, request: Request) -> str | None:
        value = request.cookies.get(self.settings.cookie_name)
        if value and is_valid_session_id(value) and await self.store.get(f"sess:{value}"):
            return value
        return None

    @staticmethod
    async def _read_body(request: Request, limit: int) -> bytes | None:
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    def _same_origin(self, request: Request) -> bool:
        """True if a form post came from this gateway's own pages.

        Browsers say where a request came from in ``Sec-Fetch-Site``, and that is trusted when
        present. The ``Origin`` header cannot be relied on alone: with a ``no-referrer`` policy,
        which these pages use, browsers send ``Origin: null`` even for a same-origin post. Only
        browsers too old to send ``Sec-Fetch-Site`` fall back to checking ``Origin``.
        """
        site = request.headers.get("sec-fetch-site")
        if site is not None:
            return site in ("same-origin", "none")
        origin = request.headers.get("origin")
        return origin is None or origin == self.settings.apex_origin

    def _isolation_key(self, session_id: str) -> str:
        """What Tor is given to keep this session on its own circuits.

        It is derived from the session identifier with a secret, so the identifier itself, which
        is a bearer credential, never leaves the gateway. The SOCKS login is sent unencrypted to
        wherever Tor runs, and Tor may log it.
        """
        digest = hmac.new(self._isolation_secret, session_id.encode("ascii"), hashlib.sha256)
        return base64.urlsafe_b64encode(digest.digest()).decode("ascii").rstrip("=")[:32]

    def _take_fetch_slot(self, session_id: str) -> bool:
        """Limit how many onion fetches run at once, overall and for one session."""
        settings = self.settings
        if self._active_fetches >= settings.max_concurrent_fetches:
            return False
        if self._active_by_session.get(session_id, 0) >= settings.max_fetches_per_session:
            return False
        self._active_fetches += 1
        self._active_by_session[session_id] = self._active_by_session.get(session_id, 0) + 1
        return True

    def _release_fetch_slot(self, session_id: str) -> None:
        self._active_fetches -= 1
        remaining = self._active_by_session.get(session_id, 1) - 1
        if remaining > 0:
            self._active_by_session[session_id] = remaining
        else:
            self._active_by_session.pop(session_id, None)

    @staticmethod
    def _request_context(request: Request) -> RequestContext:
        """How the browser described this request, for cookie rules and the Origin header.

        A browser says in ``Sec-Fetch-Site`` whether a request came from the same origin. Anything
        else, including a browser that says nothing, is treated as coming from another site, which
        is the cautious reading.
        """
        site = request.headers.get("sec-fetch-site")
        navigation = (
            request.headers.get("sec-fetch-mode") == "navigate"
            and request.headers.get("sec-fetch-user") == "?1"
            and request.method in ("GET", "HEAD")
        )
        return RequestContext(same_origin=site in ("same-origin", "none"), navigation=navigation)

    def _upstream_referer(
        self, request: Request, label: str, origin: OnionOrigin, context: RequestContext
    ) -> str | None:
        """The onion-side address of the page that made this request, if it was on this origin."""
        referer = request.headers.get("referer")
        if not referer or not context.same_origin:
            return None
        parts = urlsplit(referer)
        if self.settings.hosts.label_from_host(parts.netloc) != label:
            return None
        return f"{origin.key}{parts.path}" + (f"?{parts.query}" if parts.query else "")

    # --- entry point -----------------------------------------------------------------------

    async def _handle(self, request: Request) -> Response:
        host = request.headers.get("host", "")
        try:
            if len(request.headers.getlist("host")) > 1:
                return self._error("bad_request")  # two Host headers: some servers read the other
            hosts = self.settings.hosts
            if hosts.is_apex(host):
                return await self._handle_apex(request)
            label = hosts.label_from_host(host)
            if label is not None:
                return await self._handle_label(request, label)
            return self._error("not_found")
        except StoreFullError:
            # The shared store is full. That is a reason to ask people to wait, not a fault.
            self.metrics.inc("refusals_total", reason="other")
            return self._error("busy", apex=self.settings.hosts.is_apex(host))
        except Exception as exc:  # unexpected trouble must end in an error page, never a crash
            _log.warning("unexpected failure: %s", type(exc).__name__)
            return self._error("internal")

    # --- the main domain -------------------------------------------------------------------

    async def _handle_apex(self, request: Request) -> Response:
        path = request.url.path
        method = request.method
        if path == "/" and method in ("GET", "HEAD"):
            session = await self._current_session(request)
            can_open = self.settings.open_mode or session is not None
            has_contact = self.settings.abuse_contact is not None
            return self._apex(
                pages.landing_page(can_open=can_open, abuse_link=has_contact), form=can_open
            )
        if path == "/abuse" and method in ("GET", "HEAD"):
            return self._apex(pages.abuse_page(self.settings.abuse_contact))
        if path == "/open" and method == "POST":
            return await self._open(request)
        if path == "/enter" and method in ("GET", "POST"):
            return await self._enter(request)
        if path == "/_og/external" and method in ("GET", "HEAD"):
            return self._external(request)
        if path == "/view" and method == "GET":
            return await self._viewer(request)
        if path == "/_og/current" and method == "GET":
            return await self._current_page(request)
        if path == "/_og/metrics" and method == "GET" and self.settings.metrics_token is not None:
            return self._metrics(request)
        if path == "/_og/report" and method == "POST" and self.settings.reports is not None:
            return await self._report(request)
        if path == "/_og/reader" and method == "POST":
            return await self._set_reader(request)
        if path == "/_og/viewer.js" and method == "GET":
            return self._viewer_script()
        if path == "/_og/blocked":
            return self._apex(pages.blocked_page(), 403)
        return self._apex_fixed(path) or self._error("not_found", apex=True)

    def _apex_fixed(self, path: str) -> Response | None:
        """The two answers that never change: the health check and the robots file."""
        headers = apex_headers(self.settings.header_policy)
        if path == "/_og/health":
            headers["Content-Type"] = "application/json"
            return Response(b'{"status":"ok"}', 200, headers)
        if path == "/robots.txt":
            headers["Content-Type"] = "text/plain; charset=utf-8"
            return Response(b"User-agent: *\nDisallow: /\n", 200, headers)
        return None

    def _external(self, request: Request) -> Response:
        target = request.query_params.get("u", "")
        usable = (
            target.isascii()
            and 0 < len(target) <= 2048
            and target.startswith(("http://", "https://"))
            and not any(ord(c) <= 0x20 or ord(c) == 0x7F for c in target)
            and "@" not in target.split("/", 3)[2 if target.count("/") >= 2 else 0]
            and bool(urlsplit(target).hostname)
        )
        if not usable:
            return self._error("bad_request", apex=True)
        return self._apex(pages.external_page(target), framed=True)

    async def _read_open_form(self, request: Request) -> OnionUrl | Response:
        """The address typed into the entry form, or the page to send instead.

        That is an error for a body that is too big or an address that is no address, and the
        warning for one that imitates a listed site and has not been confirmed.
        """
        raw = await self._read_body(request, _FORM_LIMIT)
        if raw is None:
            return self._error("payload_too_large", apex=True)
        fields = parse_qs(
            raw.decode("ascii", errors="ignore"), keep_blank_values=True, max_num_fields=10
        )
        typed = (fields.get("address") or [""])[0].strip()
        parsed = _typed_address(typed)
        if parsed is None:
            body = pages.landing_page(notice="That is not a valid version 3 onion address.")
            return self._apex(body, 400, form=True)
        return self._lookalike_warning(parsed, typed, fields) or parsed

    def _lookalike_warning(
        self, parsed: OnionUrl, typed: str, fields: dict[str, list[str]]
    ) -> Response | None:
        """The warning page for an address that imitates a listed one, unless it was confirmed.

        It is shown before the request is counted, charged or recorded, because nothing has been
        asked of anyone yet.
        """
        known = self.settings.known_sites
        if known is None or fields.get("confirm") == ["1"]:
            return None
        real = known.lookalike_of(parsed.origin.host.address)
        if real is None:
            return None
        shown = parsed.origin.host.address + ".onion"
        return self._apex(pages.lookalike_page(typed, shown, real.name, real.address), form=True)

    async def _too_many_opens(
        self, session_id: str, profile: Profile, origin: OnionOrigin
    ) -> Response | None:
        """Opening is a request like any other: it counts against the profile's limit, and a
        session can only type in so many addresses. Both are checked before anything is recorded
        or charged."""
        if not self._take_rate_slot(session_id, profile):
            self.metrics.inc("refusals_total", reason="rate-limit")
            return self._error("slow_down", apex=True)
        if await self.labels.open_cap_reached(session_id, origin):
            return self._error("session_limit", apex=True)
        return None

    async def _open(self, request: Request) -> Response:
        if not self._same_origin(request):
            return self._error("forbidden", apex=True)
        existing = await self._current_session(request)
        if existing is None and not self.settings.open_mode:
            return self._error("sign_in_required", apex=True)
        parsed = await self._read_open_form(request)
        if isinstance(parsed, Response):
            return parsed
        who = await self._who_of(existing)
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        profile = self.settings.profile_named(who.profile)
        if profile is None:
            return self._error("unknown_profile", apex=True)
        if existing is not None:
            too_many = await self._too_many_opens(existing, profile, parsed.origin)
            if too_many is not None:
                return too_many
        refusal = await self._admit(who, profile, parsed.origin, "open", path=target, apex=True)
        if isinstance(refusal, Response):
            return refusal
        try:
            session_id = existing or await self._create_session(
                "local", "local", self.settings.profile.name
            )
        except _TooBusyError:
            return self._error("busy", apex=True)
        if existing is None:
            self._take_rate_slot(session_id, profile)  # this request is the session's first
        try:
            label = await self.labels.label_for(session_id, parsed.origin, reserved=True)
        except LabelError:
            return self._error("session_limit", apex=True)
        await self.store.put(
            f"seen:{session_id}:{parsed.origin.host.address}", "1", self.settings.session_ttl
        )
        headers = apex_headers(self.settings.header_policy)
        headers["Location"] = self._viewer_url(label, parsed.path, parsed.query)
        response = Response(status_code=303, headers=headers)
        if existing is None:
            self._set_session_cookie(response, session_id)
        return response

    async def _enter(self, request: Request) -> Response:
        """A sign-in link. It asks the visitor to confirm, unless the operator turned that off.

        Looking at the confirmation page does not use the link up. Only the confirmation does, and
        only if it came from this gateway's own page, so a page elsewhere cannot send it.
        """
        if self.verifier is None:
            return self._error("not_found", apex=True)
        if request.method == "POST":
            if not self._same_origin(request):
                return self._error("forbidden", apex=True)
            raw = await self._read_body(request, _FORM_LIMIT)
            if raw is None:
                return self._error("payload_too_large", apex=True)
            fields = parse_qs(raw.decode("ascii", errors="ignore"), max_num_fields=10)
            return await self._complete_entry((fields.get("t") or [""])[0])
        token = request.query_params.get("t", "")
        if not self.settings.confirm_sign_in:
            return await self._complete_entry(token)
        try:
            claims = self.verifier.verify(token)
        except TicketError as exc:
            _log.info("ticket refused: %s", exc.reason)
            return self._error("forbidden", apex=True)
        if self.settings.profile_named(claims.profile) is None:
            self.metrics.inc("refusals_total", reason="unknown-profile")
            return self._error("unknown_profile", apex=True)
        return self._apex(pages.confirm_sign_in_page(token), form=True)

    async def _complete_entry(self, token: str) -> Response:
        """Redeem a ticket and sign the visitor in."""
        verifier = self.verifier
        if verifier is None:
            return self._error("not_found", apex=True)
        try:
            claims = await verifier.redeem(token, self.store)
        except TicketError as exc:
            _log.info("ticket refused: %s", exc.reason)
            return self._error("forbidden", apex=True)
        ticket_profile = self.settings.profile_named(claims.profile)
        if ticket_profile is None:
            self.metrics.inc("refusals_total", reason="unknown-profile")
            _log.info("ticket names a profile this gateway does not have")
            return self._error("unknown_profile", apex=True)
        ticket_origin = (
            OnionOrigin("http", OnionHost(claims.onion), 80) if claims.onion is not None else None
        )
        if ticket_origin is not None:
            who = _Who(claims.subject, claims.group, claims.profile)
            refusal = await self._admit(
                who, ticket_profile, ticket_origin, "open", path="/", apex=True
            )
            if isinstance(refusal, Response):
                return refusal
        try:
            session_id = await self._create_session(claims.subject, claims.group, claims.profile)
        except _TooBusyError:
            return self._error("busy", apex=True)
        location = f"{self.settings.apex_origin}/"
        if ticket_origin is not None:
            origin = ticket_origin
            try:
                location = self._viewer_url(
                    await self.labels.label_for(session_id, origin, reserved=True), "/", ""
                )
            except LabelError:
                return self._error("session_limit", apex=True)
            await self.store.put(
                f"seen:{session_id}:{origin.host.address}", "1", self.settings.session_ttl
            )
        headers = apex_headers(self.settings.header_policy)
        headers["Location"] = location
        response = Response(status_code=303, headers=headers)
        self._set_session_cookie(response, session_id)
        return response

    # --- the viewer ------------------------------------------------------------------------

    def _viewer_url(self, label: str, path: str, query: str) -> str:
        target = path + (f"?{query}" if query else "")
        return f"{self.settings.apex_origin}/view?l={label}&p={quote(target, safe='')}"

    async def _viewer(self, request: Request) -> Response:
        session_id = await self._current_session(request)
        if session_id is None:
            return self._error("sign_in_required", apex=True)
        label = request.query_params.get("l", "")
        path = request.query_params.get("p", "/")
        usable = (
            is_valid_label(label)
            and path.startswith("/")
            and not path.startswith("//")
            and path.isascii()
            and len(path) <= 2048
            and not any(ord(c) <= 0x20 or ord(c) == 0x7F or c in "\\#" for c in path)
        )
        if not usable:
            return self._error("bad_request", apex=True)
        target = await self.labels.resolve(label)
        if target is None or target.session_id != session_id:
            return self._error("forbidden", apex=True)
        path_only, _, query = path.partition("?")
        source = self._gateway_url(label, path_only, query)
        who = await self._who_of(session_id)
        profile = self.settings.profile_named(who.profile)
        page = pages.viewer_page(
            source,
            can_report=self.settings.reports is not None,
            can_show_entities=profile is not None and profile.show_entities,
        )
        return Response(page, 200, viewer_headers(self.settings.header_policy))

    def _viewer_script(self) -> Response:
        headers = resource_headers(self.settings.header_policy, "text/javascript; charset=utf-8")
        return Response(pages.VIEWER_SCRIPT.encode("ascii"), 200, headers)

    async def _remember_page(
        self,
        session_id: str,
        page_url: OnionUrl,
        frame_url: str,
        title: str,
        refresh: str = "",
        entities: list[dict[str, str]] | None = None,
    ) -> None:
        """What the viewer shows about the page: its address, the frame to reload, its title, and
        where the page asked to be sent. The last is shown in the toolbar, because a page can hide
        everything inside its own frame."""
        shown: dict[str, Any] = {
            "url": page_url.url,
            "frame": frame_url,
            "title": title,
            "refresh": refresh,
        }
        if entities is not None:
            shown["entities"] = entities
        record = json.dumps(shown)
        await self.store.put(f"cur:{session_id}", record, self.settings.session_ttl)

    def _metrics(self, request: Request) -> Response:
        """The metrics, for a scraper that knows the token. Off unless a token is set."""
        settings = self.settings
        header = request.headers.get("authorization", "")
        supplied = header[7:] if header[:7].lower() == "bearer " else None
        if settings.metrics_token is None or not token_matches(supplied, settings.metrics_token):
            headers = apex_headers(settings.header_policy)
            headers["WWW-Authenticate"] = "Bearer"
            return Response(b"", 401, headers)
        kill_all = 0.0
        if settings.kill is not None:
            kill_all = (
                1.0
                if settings.kill.engaged(profile="", address="") in ("all", "unreadable")
                else 0.0
            )
        gauges = {
            "active_fetches": ("Fetches in progress now.", float(self._active_fetches)),
            "fetch_capacity": (
                "The most fetches allowed at once.",
                float(settings.max_concurrent_fetches),
            ),
            "kill_all": ("1 while a kill file stops the whole gateway.", kill_all),
            "up": ("1 while the gateway is running.", 1.0),
        }
        headers = apex_headers(settings.header_policy)
        headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
        body = self.metrics.render(gauges, onionglass.__version__)
        return Response(body.encode("utf-8"), 200, headers)

    def _json(self, status: int, message: str) -> Response:
        headers = apex_headers(self.settings.header_policy)
        headers["Content-Type"] = "application/json"
        return Response(json.dumps({"message": message}).encode("utf-8"), status, headers)

    async def _report(self, request: Request) -> Response:
        """A visitor reports the site they are looking at, with one reason from a short list."""
        queue = self.settings.reports
        if queue is None or not self._same_origin(request):
            return self._json(403, "Not allowed.")
        session_id = await self._current_session(request)
        if session_id is None:
            return self._json(403, "Sign in first.")
        raw = await self._read_body(request, 1024)
        if raw is None:
            return self._json(413, "That request is too large.")
        fields = parse_qs(raw.decode("ascii", errors="ignore"), max_num_fields=5)
        category = (fields.get("category") or [""])[0]
        if category not in CATEGORIES:
            return self._json(400, "Choose a reason from the list.")
        try:
            shown = json.loads(await self.store.get(f"cur:{session_id}") or "{}")
            origin = parse_onion_url(str(shown["url"])).origin
        except (ValueError, KeyError, TypeError, InvalidOnionError):
            return self._json(400, "There is no page to report yet.")
        counter = f"rep:{session_id}"
        sent = int(await self.store.get(counter) or 0)
        if sent >= self.settings.max_reports_per_session:
            return self._json(429, "You have sent as many reports as are allowed for now.")
        who = await self._who_of(session_id)
        try:
            outcome = await queue.submit(origin.host.address, category, who.subject)
        except ReportError:
            _log.warning("a report could not be recorded")
            return self._json(503, "The report could not be recorded. Try again later.")
        if outcome == "received":
            await self.store.put(counter, str(sent + 1), 86_400)
            await self._record("report", who, origin, "report", rule=category)
        return self._json(200, pages.REPORT_MESSAGES[outcome])

    async def _reader_on(self, session_id: str) -> bool:
        """Whether this visitor asked to see pages in the reader view."""
        return await self.store.get(f"reader:{session_id}") == "1"

    async def _set_reader(self, request: Request) -> Response:
        """A visitor turns the reader view on or off. It applies to every site they open."""
        if not self._same_origin(request):
            return self._json(403, "Not allowed.")
        session_id = await self._current_session(request)
        if session_id is None:
            return self._json(403, "Sign in first.")
        raw = await self._read_body(request, 64)
        if raw is None:
            return self._json(413, "That request is too large.")
        fields = parse_qs(raw.decode("ascii", errors="ignore"), max_num_fields=3)
        choice = (fields.get("on") or [""])[0]
        if choice not in ("0", "1"):
            return self._json(400, "Choose on or off.")
        if choice == "1":
            await self.store.put(f"reader:{session_id}", "1", self.settings.session_ttl)
        else:
            await self.store.delete(f"reader:{session_id}")
        headers = apex_headers(self.settings.header_policy)
        headers["Content-Type"] = "application/json"
        return Response(json.dumps({"reader": choice == "1"}).encode("utf-8"), 200, headers)

    async def _current_page(self, request: Request) -> Response:
        headers = apex_headers(self.settings.header_policy)
        headers["Content-Type"] = "application/json"
        session_id = await self._current_session(request)
        if session_id is None:
            return Response(b"{}", 403, headers)
        try:
            shown = json.loads(await self.store.get(f"cur:{session_id}") or "{}")
        except ValueError:
            shown = {}
        shown["reader"] = await self._reader_on(session_id)
        return Response(json.dumps(shown).encode("utf-8"), 200, headers)

    async def _gate(
        self,
        session_id: str,
        who: _Who,
        profile: Profile,
        origin: OnionOrigin,
        method: str,
        target: str,
    ) -> Response | Profile:
        """The refusal to send, or the profile that applies to this request.

        That is the session's own profile, or its text-only form for a site nobody has rated.
        """
        if method == "POST" and not profile.allow_post_forms:
            await self._record("refused", who, origin, "fetch", rule="profile:post", path=target)
            return self._error("not_permitted")
        if not self._take_rate_slot(session_id, profile):
            self.metrics.inc("refusals_total", reason="rate-limit")
            return self._error("slow_down")
        # The first request to a site in a session is an open, however the visitor got there:
        # typed in, or followed from a page. Only then does it count against the open allowance.
        seen = f"seen:{session_id}:{origin.host.address}"
        action = "fetch" if await self.store.get(seen) else "open"
        admitted = await self._admit(who, profile, origin, action, path=target)
        if isinstance(admitted, Response):
            return admitted
        if action == "open":
            await self.store.put(seen, "1", self.settings.session_ttl)
        effective = profile.text_only() if admitted else profile
        if method == "POST" and not effective.allow_post_forms:
            await self._record("refused", who, origin, "fetch", rule="unrated:post", path=target)
            return self._error("not_permitted")
        return effective

    async def _post_body(
        self, request: Request, who: _Who, profile: Profile, origin: OnionOrigin, target: str
    ) -> bytes | Response:
        """The body of a post, or the refusal to send if it is too big or carries a file."""
        body = await self._read_body(request, self.settings.max_request_body)
        if body is None:
            return self._error("payload_too_large")
        if not profile.allow_uploads and _has_file_part(body, request.headers.get("content-type")):
            await self._record("refused", who, origin, "fetch", rule="profile:upload", path=target)
            return self._error("not_permitted")
        return body

    # --- onion content ---------------------------------------------------------------------

    async def _label_session(
        self, request: Request, label: str
    ) -> tuple[str, OnionOrigin, _Who, Profile] | Response:
        """Who a label host belongs to, or the refusal to send if it belongs to nobody usable."""
        settings = self.settings
        target = await self.labels.resolve(label)
        if target is None:
            return self._error("not_found")
        session_id = target.session_id
        session_record = await self.store.get(f"sess:{session_id}")
        if not session_record:
            return self._error("expired_session")
        who = self._who(session_record)
        profile = settings.profile_named(who.profile)
        if profile is None:
            self.metrics.inc("refusals_total", reason="unknown-profile")
            return self._error("unknown_profile")
        if settings.require_cookie and request.cookies.get(settings.cookie_name) != session_id:
            return self._error("forbidden")
        return session_id, target.origin, who, profile

    async def _handle_label(self, request: Request, label: str) -> Response:
        found = await self._label_session(request, label)
        if isinstance(found, Response):
            return found
        session_id, origin, who, profile = found
        method = request.method
        raw_path = request.scope.get("raw_path") or request.url.path.encode("ascii", "ignore")
        query = request.scope.get("query_string", b"")
        try:
            request_target = raw_path.decode("ascii") + (
                f"?{query.decode('ascii')}" if query else ""
            )
            page_url = parse_onion_url(
                f"{origin.key}{request_target}", allowed_ports=frozenset(range(1, 65536))
            )
        except (UnicodeDecodeError, InvalidOnionError):
            return self._error("bad_request")
        gated = await self._gate(session_id, who, profile, origin, method, request_target)
        if isinstance(gated, Response):
            return gated
        profile = gated
        body = b""
        if method == "POST":
            posted = await self._post_body(request, who, profile, origin, request_target)
            if isinstance(posted, Response):
                return posted
            body = posted
        context = self._request_context(request)
        cookie = await self.jar.header_for(session_id, origin, request_target, context)
        destination = request.headers.get("sec-fetch-dest", "")
        content_type = request.headers.get("content-type") if method == "POST" else None
        try:
            body, content_type = normalise_multipart(body, content_type)
            headers = upstream_request_headers(
                origin,
                method=method,
                cookie=cookie,
                referer=self._upstream_referer(request, label, origin, context),
                content_type=content_type,
                accept=_ACCEPT_BY_DESTINATION.get(destination, ACCEPT_HTML),
                same_origin=context.same_origin,
            )
        except ValueError:
            return self._error("unsupported_media")
        upstream = UpstreamRequest(
            origin=origin,
            method=method,
            target=request_target,
            headers=headers,
            isolation_key=self._isolation_key(session_id),
            body=body,
        )
        if not self._take_fetch_slot(session_id):
            return self._error("busy")
        try:
            response = await self.fetcher.fetch(upstream, max_body_bytes=profile.max_asset_bytes)
        except UpstreamError as exc:
            _log.info("fetch failed: %s", exc.kind)
            await self._record("failed", who, origin, "fetch", rule=exc.kind, path=request_target)
            return self._error(exc.kind if exc.kind in pages.ERRORS else "protocol_error")
        finally:
            self._release_fetch_slot(session_id)
        self.metrics.observe_upstream(response.elapsed)
        # The outcome is recorded before anything of the reply is used. If it cannot be recorded
        # the reply is dropped, cookies included.
        recorded = await self._record(
            "response", who, origin, "fetch", path=request_target, status=response.status
        )
        if not recorded:
            return self._error("audit_unavailable")
        media = parse_content_type(response.header("content-type"))[0]
        if media in _HTML_TYPES and not await self._charge(who, profile, profile.page_cost):
            return self._error("quota_unavailable")
        await self.jar.store_from_response(
            session_id, origin, request_target, response.header_all("set-cookie")
        )
        frame_url = (
            self._gateway_url(label, raw_path.decode("ascii"), query.decode("ascii"))
            if destination in _NAVIGATION_DESTINATIONS
            else None
        )
        return await self._deliver(
            session_id, page_url, method, response, profile, frame_url, sent=body
        )

    async def _deliver(
        self,
        session_id: str,
        page_url: OnionUrl,
        method: str,
        response: UpstreamResponse,
        profile: Profile,
        frame_url: str | None = None,
        sent: bytes = b"",
    ) -> Response:
        settings = self.settings
        status = response.status if 200 <= response.status < 600 else 502
        if status in (204, 205, 304):
            # These replies have no body, and a body would break the connection.
            return Response(status_code=status, headers=document_headers(settings.header_policy))
        location = response.header("location")
        if response.status in _REDIRECT_STATUSES and location is not None:
            return await self._redirect(session_id, page_url, response.status, location)
        media, charset = parse_content_type(response.header("content-type"))
        limit = profile.max_page_bytes if media in _HTML_TYPES else profile.max_asset_bytes
        try:
            body = decode_body(response.body, response.header("content-encoding"), max_output=limit)
        except DecodeError:
            return self._error("bad_response")
        policy = settings.header_policy
        if media in _HTML_TYPES:
            if method == "HEAD":
                return Response(b"", status, document_headers(policy))
            return await self._deliver_html(
                session_id, page_url, body, charset, status, profile, frame_url, sent
            )
        if media == "text/css":
            return await self._deliver_css(session_id, page_url, body, charset, status, profile)
        if media in _FONT_TYPES and profile.allow_fonts:
            return Response(body, status, resource_headers(policy, media))
        if media in _IMAGE_TYPES:
            if profile.allow_images:
                return Response(body, status, resource_headers(policy, media))
            return self._error("images_withheld")
        if media == "text/plain":
            return Response(body, status, resource_headers(policy, "text/plain; charset=utf-8"))
        return self._error("blocked_type")

    async def _label_map(
        self, session_id: str, mapper: PlaceholderMapper
    ) -> dict[OnionOrigin, str]:
        labels: dict[OnionOrigin, str] = {}
        new_allowed = self.settings.max_labels_per_page
        for origin in mapper.origins():
            known = await self.labels.peek(session_id, origin)
            if known is not None:
                labels[origin] = known
                continue
            if new_allowed <= 0:
                continue  # that link is turned off, see PlaceholderMapper.substitute
            new_allowed -= 1
            try:
                labels[origin] = await self.labels.label_for(session_id, origin)
            except LabelError:
                continue
        return labels

    @staticmethod
    async def _in_thread(function: Callable[[], Any], profile: Profile) -> Any:
        return await asyncio.wait_for(asyncio.to_thread(function), timeout=profile.rewrite_timeout)

    async def _deliver_html(
        self,
        session_id: str,
        page_url: OnionUrl,
        body: bytes,
        charset: str | None,
        status: int,
        profile: Profile,
        frame_url: str | None = None,
        sent: bytes = b"",
    ) -> Response:
        mapper = PlaceholderMapper(self.settings)
        options = HtmlOptions(
            allow_images=profile.allow_images,
            allow_post_forms=profile.allow_post_forms,
            allow_uploads=profile.allow_uploads,
            allow_password_fields=profile.allow_password_fields,
            max_bytes=profile.max_page_bytes,
            reader=await self._reader_on(session_id),
        )
        try:
            result = await self._in_thread(
                lambda: rewrite_html(body, page_url, mapper, options=options, charset=charset),
                profile,
            )
        except (RewriteError, TimeoutError):
            self.metrics.inc("rewrite_failures_total")
            return self._error("rewrite_failed")
        if await self._name_gate_hit(session_id, page_url, result.title, result.headings, sent):
            return self._error("denied")
        labels = await self._label_map(session_id, mapper)
        text = mapper.substitute(result.body.decode("utf-8"), labels)
        if frame_url is not None and status < 400:
            refresh = mapper.substitute(result.refresh_url, labels) if result.refresh_url else ""
            entities = await self._entities_of(result.text, profile)
            await self._remember_page(
                session_id, page_url, frame_url, result.title, refresh, entities
            )
        return Response(text.encode("utf-8"), status, document_headers(self.settings.header_policy))

    async def _entities_of(self, text: str, profile: Profile) -> list[dict[str, str]] | None:
        """What the page names, for a profile that may see it, else None. Never fails the page."""
        if not profile.show_entities:
            return None
        try:
            found = await self._in_thread(lambda: extract_entities(text), profile)
        except TimeoutError:
            return []
        return [{"kind": entity.kind, "value": entity.value} for entity in found]

    async def _name_gate_hit(
        self,
        session_id: str,
        page_url: OnionUrl,
        title: str,
        headings: tuple[str, ...],
        sent: bytes = b"",
    ) -> bool:
        """True if the page's title or headings are on the name list. The page is then refused.

        The site is held only when the hit is not an echo of the request and enough different
        accounts have met it. A search page that prints back what was typed would otherwise let
        one visitor hold any site by asking it for a listed phrase.
        """
        gate = self.settings.name_gate
        if gate is None or not gate.check(title, *headings):
            return False
        who = await self._who_of(session_id)
        origin = page_url.origin
        await self._record("refused", who, origin, "fetch", rule="name-gate", path=page_url.path)
        held = self.settings.held
        if held is None or gate.check(self._request_text(page_url, sent)):
            return True  # a page that repeats the request is refused, but proves nothing
        if not await self._enough_to_hold(origin.host.address, who.subject):
            return True
        try:
            await held.hold(origin.host.address, "name-gate")
        except Exception:
            _log.warning("the held list could not be written, the site is held in memory")
        return True

    @staticmethod
    def _request_text(page_url: OnionUrl, sent: bytes) -> str:
        """What the visitor sent, decoded twice so that encoding cannot hide an echo."""
        raw = f"{page_url.path}?{page_url.query}" + " " + sent[:100_000].decode("latin-1")
        return unquote_plus(unquote_plus(raw))

    async def _enough_to_hold(self, address: str, subject: str) -> bool:
        """Record that this account met a listed page here. True once enough different ones have.

        In personal mode there is one visitor, so one hit is enough.
        """
        needed = 1 if self.settings.open_mode else self.settings.name_gate_hold_after
        if needed <= 1:
            return True
        key = f"nghit:{address}"
        mark = hashlib.sha256(f"{address}:{subject}".encode()).hexdigest()[:16]
        seen = [m for m in (await self.store.get(key) or "").split(",") if m]
        if mark not in seen:
            seen.append(mark)
            try:
                await self.store.put(key, ",".join(seen[:needed]), 7 * 86_400)
            except StoreFullError:
                return False
        return len(set(seen)) >= needed

    async def _deliver_css(
        self,
        session_id: str,
        page_url: OnionUrl,
        body: bytes,
        charset: str | None,
        status: int,
        profile: Profile,
    ) -> Response:
        mapper = PlaceholderMapper(self.settings)
        options = CssOptions(allow_images=profile.allow_images)
        source = decode_document(body, charset)
        try:
            css = await self._in_thread(
                lambda: sanitize_stylesheet(source, page_url, mapper, options), profile
            )
        except (CssError, TimeoutError):
            return self._error("rewrite_failed")
        if not verify_stylesheet(css, mapper):
            return self._error("rewrite_failed")
        labels = await self._label_map(session_id, mapper)
        text = mapper.substitute(css, labels)
        headers = resource_headers(self.settings.header_policy, "text/css; charset=utf-8")
        return Response(text.encode("utf-8"), status, headers)

    async def _redirect(
        self, session_id: str, page_url: OnionUrl, status: int, location: str
    ) -> Response:
        mapper = PlaceholderMapper(self.settings)
        resolved = resolve_reference(location, page_url, mapper)
        if resolved.kind not in ("onion", "external"):
            return self._error("bad_redirect")
        target = resolved.url
        if resolved.kind == "onion":
            target = mapper.substitute(target, await self._label_map(session_id, mapper))
            if "/_og/blocked" in target.split("?", 1)[0] and target.startswith(
                self.settings.apex_origin
            ):
                return self._error("bad_redirect")
        headers = document_headers(self.settings.header_policy)
        headers["Location"] = target
        return Response(status_code=status, headers=headers)
