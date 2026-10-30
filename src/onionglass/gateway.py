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
import json
import logging
import secrets
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from onionglass import pages
from onionglass.cookies import CookieJar
from onionglass.decode import DecodeError, decode_body
from onionglass.headers import (
    ACCEPT_ANY,
    ACCEPT_HTML,
    apex_headers,
    document_headers,
    parse_content_type,
    resource_headers,
    upstream_request_headers,
)
from onionglass.labels import LabelBook, LabelError, is_valid_session_id
from onionglass.mapper import PlaceholderMapper
from onionglass.onion import InvalidOnionError, OnionHost, OnionOrigin, OnionUrl, parse_onion_url
from onionglass.rewrite.css import CssError, CssOptions, sanitize_stylesheet, verify_stylesheet
from onionglass.rewrite.html import HtmlOptions, RewriteError, decode_document, rewrite_html
from onionglass.rewrite.urls import resolve_reference
from onionglass.settings import Settings
from onionglass.store import InMemoryStore, SessionStore, StoreFullError
from onionglass.tickets import TicketError, TicketVerifier
from onionglass.upstream import Fetcher, UpstreamError, UpstreamRequest, UpstreamResponse

_log = logging.getLogger("onionglass")

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


class Gateway:
    """Builds the web application around a fetcher, a store and the settings."""

    def __init__(
        self,
        settings: Settings,
        *,
        fetcher: Fetcher,
        store: SessionStore | None = None,
    ) -> None:
        self.settings = settings
        self.fetcher = fetcher
        self.store = store or InMemoryStore()
        self.labels = LabelBook(
            self.store, ttl=settings.session_ttl, max_per_session=settings.max_labels_per_session
        )
        self.jar = CookieJar(self.store, ttl=settings.session_ttl)
        self.verifier = (
            TicketVerifier(settings.keys, settings.audience) if settings.keys is not None else None
        )
        self.app = Starlette(
            routes=[Route("/{path:path}", self._handle, methods=["GET", "HEAD", "POST"])]
        )

    # --- helpers ---------------------------------------------------------------------------

    def _apex(self, body: bytes, status: int = 200, *, form: bool = False) -> Response:
        return Response(body, status, apex_headers(self.settings.header_policy, form=form))

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
        session_id = secrets.token_urlsafe(24)
        record = json.dumps({"sub": subject, "grp": group, "prf": profile})
        await self.store.put(f"sess:{session_id}", record, self.settings.session_ttl)
        return session_id

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
        site = request.headers.get("sec-fetch-site")
        if site is not None and site not in ("same-origin", "none"):
            return False
        origin = request.headers.get("origin")
        return origin is None or origin == self.settings.apex_origin

    # --- entry point -----------------------------------------------------------------------

    async def _handle(self, request: Request) -> Response:
        try:
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
        )
        if not usable:
            return self._error("bad_request", apex=True)
        return self._apex(pages.external_page(target))

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
        session_id = existing or await self._create_session(
            "local", "local", self.settings.profile.name
        )
        try:
            label = await self.labels.label_for(session_id, parsed.origin)
        except LabelError:
            return self._error("session_limit", apex=True)
        headers = apex_headers(self.settings.header_policy)
        headers["Location"] = self._gateway_url(label, parsed.path, parsed.query)
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
        session_id = await self._create_session(claims.subject, claims.group, claims.profile)
        location = f"{self.settings.apex_origin}/"
        if claims.onion is not None:
            origin = OnionOrigin("http", OnionHost(claims.onion), 80)
            try:
                location = self._gateway_url(await self.labels.label_for(session_id, origin))
            except LabelError:
                return self._error("session_limit", apex=True)
        headers = apex_headers(self.settings.header_policy)
        headers["Location"] = location
        response = Response(status_code=303, headers=headers)
        self._set_session_cookie(response, session_id)
        return response

    # --- onion content ---------------------------------------------------------------------

    async def _handle_label(self, request: Request, label: str) -> Response:
        settings = self.settings
        target = await self.labels.resolve(label)
        if target is None:
            return self._error("not_found")
        session_id, origin = target.session_id, target.origin
        if not await self.store.get(f"sess:{session_id}"):
            return self._error("expired_session")
        if settings.require_cookie and request.cookies.get(settings.cookie_name) != session_id:
            return self._error("forbidden")
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
        body = b""
        if method == "POST":
            read = await self._read_body(request, settings.max_request_body)
            if read is None:
                return self._error("payload_too_large")
            body = read
        cookie = await self.jar.header_for(session_id, origin, request_target)
        destination = request.headers.get("sec-fetch-dest", "")
        try:
            headers = upstream_request_headers(
                origin,
                method=method,
                cookie=cookie,
                content_type=request.headers.get("content-type") if method == "POST" else None,
                accept=_ACCEPT_BY_DESTINATION.get(destination, ACCEPT_HTML),
            )
        except ValueError:
            return self._error("unsupported_media")
        upstream = UpstreamRequest(
            origin=origin,
            method=method,
            target=request_target,
            headers=headers,
            isolation_key=session_id,
            body=body,
        )
        try:
            response = await self.fetcher.fetch(
                upstream, max_body_bytes=settings.profile.max_asset_bytes
            )
        except UpstreamError as exc:
            _log.info("fetch failed: %s", exc.kind)
            return self._error(exc.kind if exc.kind in pages.ERRORS else "protocol_error")
        await self.jar.store_from_response(
            session_id, origin, request_target, response.header_all("set-cookie")
        )
        return await self._deliver(session_id, page_url, method, response)

    async def _deliver(
        self, session_id: str, page_url: OnionUrl, method: str, response: UpstreamResponse
    ) -> Response:
        settings = self.settings
        profile = settings.profile
        status = response.status if 200 <= response.status < 600 else 502
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
            return await self._deliver_html(session_id, page_url, body, charset, status)
        if media == "text/css":
            return await self._deliver_css(session_id, page_url, body, charset, status)
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
        for origin in mapper.origins():
            try:
                labels[origin] = await self.labels.label_for(session_id, origin)
            except LabelError:
                continue  # that link is turned off, see PlaceholderMapper.substitute
        return labels

    async def _in_thread(self, function: Callable[[], Any]) -> Any:
        return await asyncio.wait_for(
            asyncio.to_thread(function), timeout=self.settings.profile.rewrite_timeout
        )

    async def _deliver_html(
        self, session_id: str, page_url: OnionUrl, body: bytes, charset: str | None, status: int
    ) -> Response:
        profile = self.settings.profile
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
                lambda: rewrite_html(body, page_url, mapper, options=options, charset=charset)
            )
        except (RewriteError, TimeoutError):
            return self._error("rewrite_failed")
        labels = await self._label_map(session_id, mapper)
        text = mapper.substitute(result.body.decode("utf-8"), labels)
        return Response(text.encode("utf-8"), status, document_headers(self.settings.header_policy))

    async def _deliver_css(
        self, session_id: str, page_url: OnionUrl, body: bytes, charset: str | None, status: int
    ) -> Response:
        mapper = PlaceholderMapper(self.settings)
        options = CssOptions(allow_images=self.settings.profile.allow_images)
        source = decode_document(body, charset)
        try:
            css = await self._in_thread(
                lambda: sanitize_stylesheet(source, page_url, mapper, options)
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
