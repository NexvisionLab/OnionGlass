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
import re
import secrets
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from onionglass import pages
from onionglass.audit import AuditEvent
from onionglass.cookies import CookieJar, RequestContext
from onionglass.decode import DecodeError, decode_body
from onionglass.headers import (
    ACCEPT_ANY,
    ACCEPT_HTML,
    apex_headers,
    document_headers,
    normalise_multipart,
    parse_content_type,
    resource_headers,
    upstream_request_headers,
    viewer_headers,
)
from onionglass.labels import LabelBook, LabelError, is_valid_label, is_valid_session_id
from onionglass.mapper import PlaceholderMapper
from onionglass.onion import InvalidOnionError, OnionHost, OnionOrigin, OnionUrl, parse_onion_url
from onionglass.policy import Decision, PolicyRequest
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
class _Who:
    """The visitor as the sign-in service described them. Never a network address."""

    subject: str
    group: str
    profile: str


_FILE_PART = re.compile(rb"content-disposition:[^\r\n]*;\s*filename\*?\s*=", re.IGNORECASE)


def _has_file_part(body: bytes, content_type: str | None) -> bool:
    """True if a multipart body carries a file, whatever else it holds."""
    if content_type is None or parse_content_type(content_type)[0] != "multipart/form-data":
        return False
    return _FILE_PART.search(body) is not None


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
            self.store, ttl=settings.session_ttl, max_per_session=settings.max_labels_per_session
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

    async def _refusal(self, who: _Who, origin: OnionOrigin, action: str, path: str) -> str | None:
        """The error kind that stops this request, or None if it may go ahead.

        Order matters: the kill switch is the cheapest and the surest, then the policy, and last
        the audit record, which must be written before the request goes out.
        """
        settings = self.settings
        if settings.kill is not None:
            scope = settings.kill.engaged(profile=who.profile, address=origin.host.address)
            if scope is not None:
                await self._record("refused", who, origin, action, rule=f"kill:{scope}", path=path)
                return "paused"
        rule = ""
        if settings.policy is not None:
            request = PolicyRequest(origin, who.profile, who.group, who.subject, action)
            try:
                decision = await asyncio.wait_for(
                    settings.policy.decide(request), timeout=settings.hook_timeout
                )
                if not isinstance(decision, Decision):
                    raise TypeError("a policy must return a Decision")
            except Exception:
                _log.warning("the policy could not decide, so the request was refused")
                await self._record(
                    "refused", who, origin, action, rule="policy-unavailable", path=path
                )
                return "policy_unavailable"
            if not decision.allowed:
                await self._record("refused", who, origin, action, rule=decision.rule, path=path)
                return "denied"
            rule = decision.rule
        if not await self._record("allowed", who, origin, action, rule=rule, path=path):
            return "audit_unavailable"
        return None

    async def _admit(
        self,
        who: _Who,
        origin: OnionOrigin,
        action: str,
        *,
        path: str = "",
        apex: bool = False,
    ) -> Response | None:
        """None means go ahead. Anything else is the refusal to send."""
        kind = await self._refusal(who, origin, action, path)
        return None if kind is None else self._error(kind, apex=apex)

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
        try:
            if len(request.headers.getlist("host")) > 1:
                return self._error("bad_request")  # two Host headers: some servers read the other
            host = request.headers.get("host", "")
            hosts = self.settings.hosts
            if hosts.is_apex(host):
                return await self._handle_apex(request)
            label = hosts.label_from_host(host)
            if label is not None:
                return await self._handle_label(request, label)
            return self._error("not_found")
        except StoreFullError:
            return self._error("internal")
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
            return self._apex(pages.landing_page(can_open=can_open), form=can_open)
        if path == "/open" and method == "POST":
            return await self._open(request)
        if path == "/enter" and method == "GET":
            return await self._enter(request)
        if path == "/_og/external" and method in ("GET", "HEAD"):
            return self._external(request)
        if path == "/view" and method == "GET":
            return await self._viewer(request)
        if path == "/_og/current" and method == "GET":
            return await self._current_page(request)
        if path == "/_og/viewer.js" and method == "GET":
            return self._viewer_script()
        if path == "/_og/blocked":
            return self._apex(pages.blocked_page(), 403)
        if path == "/_og/health":
            headers = apex_headers(self.settings.header_policy)
            headers["Content-Type"] = "application/json"
            return Response(b'{"status":"ok"}', 200, headers)
        if path == "/robots.txt":
            headers = apex_headers(self.settings.header_policy)
            headers["Content-Type"] = "text/plain; charset=utf-8"
            return Response(b"User-agent: *\nDisallow: /\n", 200, headers)
        return self._error("not_found", apex=True)

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

    async def _open(self, request: Request) -> Response:
        if not self._same_origin(request):
            return self._error("forbidden", apex=True)
        existing = await self._current_session(request)
        if existing is None and not self.settings.open_mode:
            return self._error("sign_in_required", apex=True)
        raw = await self._read_body(request, _FORM_LIMIT)
        if raw is None:
            return self._error("payload_too_large", apex=True)
        fields = parse_qs(
            raw.decode("ascii", errors="ignore"), keep_blank_values=True, max_num_fields=10
        )
        text = (fields.get("address") or [""])[0].strip()
        candidate = text if "://" in text else f"http://{text}"
        try:
            parsed = parse_onion_url(candidate) if text and len(text) <= 2000 else None
        except InvalidOnionError:
            parsed = None
        if parsed is None:
            body = pages.landing_page(notice="That is not a valid version 3 onion address.")
            return self._apex(body, 400, form=True)
        who = await self._who_of(existing)
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        refusal = await self._admit(who, parsed.origin, "open", path=target, apex=True)
        if refusal is not None:
            return refusal
        try:
            session_id = existing or await self._create_session(
                "local", "local", self.settings.profile.name
            )
        except _TooBusyError:
            return self._error("busy", apex=True)
        try:
            label = await self.labels.label_for(session_id, parsed.origin, reserved=True)
        except LabelError:
            return self._error("session_limit", apex=True)
        headers = apex_headers(self.settings.header_policy)
        headers["Location"] = self._viewer_url(label, parsed.path, parsed.query)
        response = Response(status_code=303, headers=headers)
        if existing is None:
            self._set_session_cookie(response, session_id)
        return response

    async def _enter(self, request: Request) -> Response:
        if self.verifier is None:
            return self._error("not_found", apex=True)
        try:
            claims = await self.verifier.redeem(request.query_params.get("t", ""), self.store)
        except TicketError as exc:
            _log.info("ticket refused: %s", exc.reason)
            return self._error("forbidden", apex=True)
        if self.settings.profile_named(claims.profile) is None:
            _log.info("ticket names a profile this gateway does not have")
            return self._error("unknown_profile", apex=True)
        ticket_origin = (
            OnionOrigin("http", OnionHost(claims.onion), 80) if claims.onion is not None else None
        )
        if ticket_origin is not None:
            who = _Who(claims.subject, claims.group, claims.profile)
            refusal = await self._admit(who, ticket_origin, "open", path="/", apex=True)
            if refusal is not None:
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
        return Response(pages.viewer_page(source), 200, viewer_headers(self.settings.header_policy))

    def _viewer_script(self) -> Response:
        headers = resource_headers(self.settings.header_policy, "text/javascript; charset=utf-8")
        return Response(pages.VIEWER_SCRIPT.encode("ascii"), 200, headers)

    async def _remember_page(
        self, session_id: str, page_url: OnionUrl, frame_url: str, title: str
    ) -> None:
        record = json.dumps({"url": page_url.url, "frame": frame_url, "title": title})
        await self.store.put(f"cur:{session_id}", record, self.settings.session_ttl)

    async def _current_page(self, request: Request) -> Response:
        headers = apex_headers(self.settings.header_policy)
        headers["Content-Type"] = "application/json"
        session_id = await self._current_session(request)
        if session_id is None:
            return Response(b"{}", 403, headers)
        record = await self.store.get(f"cur:{session_id}")
        return Response((record or "{}").encode("utf-8"), 200, headers)

    async def _gate(
        self,
        session_id: str,
        who: _Who,
        profile: Profile,
        origin: OnionOrigin,
        method: str,
        target: str,
    ) -> Response | None:
        """What the profile, the rate limit, the kill switch, the policy and the audit log say."""
        if method == "POST" and not profile.allow_post_forms:
            await self._record("refused", who, origin, "fetch", rule="profile:post", path=target)
            return self._error("not_permitted")
        if not self._take_rate_slot(session_id, profile):
            return self._error("slow_down")
        return await self._admit(who, origin, "fetch", path=target)

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
        refusal = await self._gate(session_id, who, profile, origin, method, request_target)
        if refusal is not None:
            return refusal
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
        # The outcome is recorded before anything of the reply is used. If it cannot be recorded
        # the reply is dropped, cookies included.
        recorded = await self._record(
            "response", who, origin, "fetch", path=request_target, status=response.status
        )
        if not recorded:
            return self._error("audit_unavailable")
        await self.jar.store_from_response(
            session_id, origin, request_target, response.header_all("set-cookie")
        )
        frame_url = (
            self._gateway_url(label, raw_path.decode("ascii"), query.decode("ascii"))
            if destination in _NAVIGATION_DESTINATIONS
            else None
        )
        return await self._deliver(session_id, page_url, method, response, profile, frame_url)

    async def _deliver(
        self,
        session_id: str,
        page_url: OnionUrl,
        method: str,
        response: UpstreamResponse,
        profile: Profile,
        frame_url: str | None = None,
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
                session_id, page_url, body, charset, status, profile, frame_url
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
    ) -> Response:
        mapper = PlaceholderMapper(self.settings)
        options = HtmlOptions(
            allow_images=profile.allow_images,
            allow_post_forms=profile.allow_post_forms,
            allow_uploads=profile.allow_uploads,
            allow_password_fields=profile.allow_password_fields,
            max_bytes=profile.max_page_bytes,
        )
        try:
            result = await self._in_thread(
                lambda: rewrite_html(body, page_url, mapper, options=options, charset=charset),
                profile,
            )
        except (RewriteError, TimeoutError):
            return self._error("rewrite_failed")
        labels = await self._label_map(session_id, mapper)
        text = mapper.substitute(result.body.decode("utf-8"), labels)
        if frame_url is not None and status < 400:
            await self._remember_page(session_id, page_url, frame_url, result.title)
        return Response(text.encode("utf-8"), status, document_headers(self.settings.header_policy))

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
