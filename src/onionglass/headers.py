# SPDX-License-Identifier: AGPL-3.0-only
"""Headers the gateway sends to visitors, and the headers it sends to onion sites.

Security properties:

* P1 backstop: every page is served with a Content-Security-Policy that sandboxes it without
  ``allow-scripts``, so even a rewriting bug cannot run script.
* P4: nothing identifying reaches the onion site, and nothing from the onion site's own headers
  reaches the visitor. Visitor-facing headers are built from scratch, never copied.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from onionglass.onion import DEFAULT_PORTS, InvalidOnionError, OnionOrigin, parse_onion_url

# A recent Tor Browser string. Onion sites see the same value from every gateway visitor, which
# is the point. Keep it in step with the current Tor Browser release.
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0"
ACCEPT_HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ACCEPT_ANY = "*/*"
ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST"})
ALLOWED_REQUEST_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")

_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~"
)
_BOUNDARY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=? "
)
_PERMISSIONS_POLICY = (
    "accelerometer=(), autoplay=(), bluetooth=(), browsing-topics=(), camera=(), "
    "clipboard-read=(), clipboard-write=(), display-capture=(), fullscreen=(), geolocation=(), "
    "gyroscope=(), hid=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), "
    "payment=(), publickey-credentials-get=(), serial=(), usb=(), xr-spatial-tracking=()"
)


@dataclass(frozen=True, slots=True)
class HeaderPolicy:
    """Where the gateway lives, which decides the sources a page may load from."""

    scheme: str
    base_domain: str
    port: int | None = None
    viewer_origin: str | None = None
    hsts: bool = True

    def __post_init__(self) -> None:
        if self.scheme not in ("http", "https"):
            raise ValueError("scheme must be http or https")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("port out of range")
        if not self.base_domain or any(ch in self.base_domain for ch in " ;,'\"\r\n"):
            raise ValueError("invalid base domain")
        if self.viewer_origin is not None and any(ch in self.viewer_origin for ch in " ;,'\"\r\n"):
            raise ValueError("invalid viewer origin")

    @property
    def source(self) -> str:
        """The CSP source covering every label host of this gateway."""
        port = f":{self.port}" if self.port is not None else ""
        return f"{self.scheme}://*.{self.base_domain}{port}"


def _common(policy: HeaderPolicy) -> dict[str, str]:
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-site",
        "Permissions-Policy": _PERMISSIONS_POLICY,
        "X-Robots-Tag": "noindex, nofollow, noarchive",
        "Cache-Control": "no-store",
    }
    if policy.scheme == "https" and policy.hsts:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


def document_headers(policy: HeaderPolicy) -> dict[str, str]:
    """Headers for a rewritten HTML page.

    The ``sandbox`` directive has no ``allow-scripts``, so scripts cannot run whatever the page
    contains. ``allow-same-origin`` is needed so the page can use its session cookie, and
    ``allow-forms`` so forms work. Nothing else is allowed: no popups, no top-level navigation.
    """
    source = policy.source
    ancestors = policy.viewer_origin or "'none'"
    csp = "; ".join(
        (
            "sandbox allow-forms allow-same-origin",
            "default-src 'none'",
            "script-src 'none'",
            "object-src 'none'",
            "base-uri 'none'",
            "connect-src 'none'",
            "frame-src 'none'",
            "media-src 'none'",
            "manifest-src 'none'",
            f"form-action {source}",
            f"img-src {source}",
            f"style-src {source} 'unsafe-inline'",
            f"font-src {source}",
            f"frame-ancestors {ancestors}",
        )
    )
    return {
        **_common(policy),
        "Content-Security-Policy": csp,
        "Content-Type": "text/html; charset=utf-8",
    }


def apex_headers(policy: HeaderPolicy, *, form: bool = False) -> dict[str, str]:
    """Headers for the gateway's own pages on its main domain: entry form, warnings, errors.

    These pages have a few lines of inline style and, for the entry form, a form that posts back
    to the gateway. Nothing else is allowed, and no other site may frame them.
    """
    csp = "; ".join(
        (
            "default-src 'none'",
            "style-src 'unsafe-inline'",
            "script-src 'none'",
            "object-src 'none'",
            "base-uri 'none'",
            "connect-src 'none'",
            "form-action 'self'" if form else "form-action 'none'",
            "frame-ancestors 'none'",
        )
    )
    return {
        **_common(policy),
        "Content-Security-Policy": csp,
        "Content-Type": "text/html; charset=utf-8",
    }


def resource_headers(policy: HeaderPolicy, content_type: str) -> dict[str, str]:
    """Headers for anything that is not a page: stylesheets, images, fonts and files.

    Images are served with a sandboxing policy too, so an image type that can carry script, such
    as SVG, cannot run it if a visitor opens it directly.
    """
    return {
        **_common(policy),
        "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
        "Content-Type": content_type,
    }


def parse_content_type(value: str | None) -> tuple[str, str | None]:
    """Reduce an upstream Content-Type to a safe media type and an optional charset."""
    if not value or len(value) > 200 or not value.isascii():
        return "application/octet-stream", None
    pieces = [piece.strip() for piece in value.split(";")]
    media = pieces[0].lower()
    kind, slash, subtype = media.partition("/")
    if not slash or not kind or not subtype or not (set(kind) | set(subtype)) <= _TOKEN_CHARS:
        return "application/octet-stream", None
    charset: str | None = None
    for piece in pieces[1:]:
        name, equals, parameter = piece.partition("=")
        if equals and name.strip().lower() == "charset":
            candidate = parameter.strip().strip('"').lower()
            if candidate and len(candidate) <= 40 and set(candidate) <= _TOKEN_CHARS:
                charset = candidate
    return media, charset


def visitor_headers_from_upstream(upstream: Mapping[str, str]) -> dict[str, str]:
    """What survives from the onion site's own response headers: nothing but the media type.

    The caller builds everything else with ``document_headers`` or ``resource_headers``.
    """
    lowered = {key.lower(): value for key, value in upstream.items()}
    media, charset = parse_content_type(lowered.get("content-type"))
    return {"Content-Type": f"{media}; charset={charset}" if charset else media}


def authority(origin: OnionOrigin) -> str:
    hostname = origin.host.hostname
    return hostname if origin.port == DEFAULT_PORTS[origin.scheme] else f"{hostname}:{origin.port}"


def _check_value(value: str) -> str:
    if not value.isascii() or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("header value has control or non-ASCII characters")
    return value


def _request_content_type(value: str) -> str:
    media, _ = parse_content_type(value)
    if media not in ALLOWED_REQUEST_TYPES:
        raise ValueError("request content type is not allowed")
    if media != "multipart/form-data":
        return media
    for piece in value.split(";")[1:]:
        name, _, parameter = piece.strip().partition("=")
        if name.strip().lower() == "boundary":
            boundary = parameter.strip().strip('"')
            if 1 <= len(boundary) <= 70 and set(boundary) <= _BOUNDARY_CHARS:
                return f'multipart/form-data; boundary="{boundary}"'
    raise ValueError("multipart request has no valid boundary")


def upstream_request_headers(
    origin: OnionOrigin,
    *,
    method: str,
    referer: str | None = None,
    content_type: str | None = None,
    cookie: str | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    accept: str = ACCEPT_HTML,
) -> dict[str, str]:
    """The only headers an onion site ever sees. Built from scratch, copying nothing.

    The visitor's own headers (address, language, user agent, cookies, anything forwarded) are
    never passed through. The Referer is only sent when it is a page on the same origin.
    """
    if method not in ALLOWED_METHODS:
        raise ValueError("method is not allowed")
    headers = {
        "Host": authority(origin),
        "User-Agent": _check_value(user_agent),
        "Accept": _check_value(accept),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    if cookie:
        headers["Cookie"] = _check_value(cookie)
    if referer:
        try:
            parsed = parse_onion_url(referer, allowed_ports=frozenset(range(1, 65536)))
        except InvalidOnionError:
            parsed = None
        if parsed is not None and parsed.origin == origin:
            headers["Referer"] = parsed.url
    if method == "POST":
        headers["Origin"] = f"{origin.scheme}://{authority(origin)}"
        if content_type is not None:
            headers["Content-Type"] = _request_content_type(content_type)
    return headers
