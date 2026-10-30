# SPDX-License-Identifier: AGPL-3.0-only
"""The gateway application end to end, with a fake fetcher standing in for Tor."""

from __future__ import annotations

import asyncio
import gzip
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from helpers import DUCKDUCKGO, TOR_PROJECT, assert_safe_output
from onionglass.gateway import Gateway
from onionglass.settings import Profile, Settings
from onionglass.store import InMemoryStore
from onionglass.tickets import KeyRing, TicketIssuer, generate_key
from onionglass.upstream import UpstreamError, UpstreamRequest, UpstreamResponse

PORT = 8080
APEX = f"localhost:{PORT}"
PAGE = f"http://{TOR_PROJECT}.onion/"


class Owns:
    """What counts as a gateway URL in personal mode, for the independent output check."""

    def owns(self, url: str) -> bool:
        if url == "" or url.startswith("#"):
            return True
        parts = urlsplit(url)
        if parts.scheme != "http" or parts.port != PORT or not parts.hostname:
            return False
        if parts.hostname == "localhost":
            return parts.path in ("/_og/external", "/_og/blocked") or parts.path.startswith(
                "/_og/blocked/"
            )
        return parts.hostname.endswith(".localhost") and len(parts.hostname) == 26 + len(
            ".localhost"
        )


def reply(
    body: bytes | str = b"",
    *,
    status: int = 200,
    content_type: str | None = "text/html; charset=utf-8",
    headers: tuple[tuple[str, str], ...] = (),
) -> UpstreamResponse:
    data = body.encode("utf-8") if isinstance(body, str) else body
    pairs = list(headers)
    if content_type is not None:
        pairs.append(("content-type", content_type))
    return UpstreamResponse(
        status=status,
        reason="OK",
        headers=tuple((name.lower(), value) for name, value in pairs),
        body=data,
        elapsed=0.0,
    )


class FakeFetcher:
    def __init__(
        self, handler: Callable[[UpstreamRequest], UpstreamResponse | Exception] | None = None
    ) -> None:
        self.handler = handler or (lambda _request: reply("<p>default</p>"))
        self.requests: list[UpstreamRequest] = []

    async def fetch(
        self, request: UpstreamRequest, *, max_body_bytes: int | None = None
    ) -> UpstreamResponse:
        self.requests.append(request)
        outcome = self.handler(request)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class Env:
    def __init__(
        self,
        handler: Callable[[UpstreamRequest], UpstreamResponse | Exception] | None = None,
        **settings: Any,
    ) -> None:
        profile = settings.pop("profile", Profile())
        self.settings = Settings(
            base_domain="localhost",
            scheme="http",
            port=PORT,
            open_mode=True,
            profile=profile,
            **settings,
        )
        self.fetcher = FakeFetcher(handler)
        self.store = InMemoryStore()
        self.gateway = Gateway(self.settings, fetcher=self.fetcher, store=self.store)
        self.client = TestClient(
            self.gateway.app, base_url=f"http://{APEX}", follow_redirects=False
        )

    def open(self, address: str = PAGE) -> str:
        """Open an address through the entry form and return the label that serves it."""
        response = self.client.post("/open", data={"address": address})
        assert response.status_code == 303, response.text
        return self.viewer_label(response.headers["location"])

    @staticmethod
    def viewer_label(location: str) -> str:
        """The label named by a redirect to the viewer page."""
        parts = urlsplit(location)
        assert parts.path == "/view", location
        return parse_qs(parts.query)["l"][0]

    def get(self, label: str, path: str = "/", **kwargs: Any) -> Any:
        headers = {"host": f"{label}.localhost:{PORT}", **kwargs.pop("headers", {})}
        return self.client.get(path, headers=headers, **kwargs)

    @staticmethod
    def label_in(location: str) -> str:
        host = urlsplit(location).hostname
        assert host is not None
        return host.split(".")[0]


# --- the entry form and sessions -----------------------------------------------------------------


def test_the_start_page_warns_that_the_operator_sees_everything() -> None:
    env = Env()
    response = env.client.get("/")
    assert response.status_code == 200
    assert "can see every address you open" in response.text
    assert 'action="/open"' in response.text
    assert "Content-Security-Policy" in response.headers
    assert "script-src 'none'" in response.headers["content-security-policy"]
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_opening_an_address_redirects_to_an_opaque_label_and_sets_a_session() -> None:
    env = Env()
    response = env.client.post("/open", data={"address": f"{TOR_PROJECT}.onion/some/page?x=1"})
    assert response.status_code == 303
    location = response.headers["location"]
    parts = urlsplit(location)
    assert parts.hostname == "localhost" and parts.port == PORT  # the viewer, on the main domain
    assert parts.path == "/view"
    fields = parse_qs(parts.query)
    assert len(fields["l"][0]) == 26
    assert fields["p"] == ["/some/page?x=1"]
    assert TOR_PROJECT not in location
    assert "onion" not in location
    assert "og_session" in response.headers["set-cookie"]
    assert "httponly" in response.headers["set-cookie"].lower()
    assert env.fetcher.requests == []  # nothing is fetched until the label is used


def test_addresses_are_accepted_with_or_without_a_scheme() -> None:
    env = Env()
    plain = env.open(f"{TOR_PROJECT}.onion")
    secure = env.open(f"https://{TOR_PROJECT}.onion/")
    again = env.open(f"http://{TOR_PROJECT}.onion/")
    assert plain == again
    assert secure != plain  # https is a different origin


@pytest.mark.parametrize(
    "address",
    [
        "",
        "   ",
        "example.org",
        "http://example.org/",
        f"{TOR_PROJECT[:-1]}x.onion",
        "abc.onion",
        "javascript:alert(1)",
        f"ftp://{TOR_PROJECT}.onion/",
        "x" * 3000,
        f"http://{TOR_PROJECT}.onion:22/",
    ],
)
def test_bad_addresses_are_refused_with_the_form_again(address: str) -> None:
    env = Env()
    response = env.client.post("/open", data={"address": address})
    assert response.status_code == 400
    assert "not a valid version 3 onion address" in response.text
    assert 'action="/open"' in response.text


def test_the_entry_form_refuses_requests_from_other_sites() -> None:
    env = Env()
    for headers in (
        {"origin": "http://evil.example"},
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-site"},
    ):
        response = env.client.post("/open", data={"address": PAGE}, headers=headers)
        assert response.status_code == 403
    assert (
        env.client.post(
            "/open", data={"address": PAGE}, headers={"origin": f"http://{APEX}"}
        ).status_code
        == 303
    )


def test_browsers_that_send_a_null_origin_for_same_origin_posts_are_accepted() -> None:
    # Found in a real browser: with a no-referrer policy, Chrome sends "Origin: null" on a
    # same-origin form post. The Sec-Fetch-Site header is the reliable signal.
    env = Env()
    same = {"origin": "null", "sec-fetch-site": "same-origin"}
    assert env.client.post("/open", data={"address": PAGE}, headers=same).status_code == 303
    assert (
        env.client.post("/open", data={"address": PAGE}, headers={"origin": "null"}).status_code
        == 403
    )
    cross = {"origin": "null", "sec-fetch-site": "cross-site"}
    assert env.client.post("/open", data={"address": PAGE}, headers=cross).status_code == 403
    # A forged Origin cannot override the browser's own statement of where the request came from.
    forged = {"origin": f"http://{APEX}", "sec-fetch-site": "cross-site"}
    assert env.client.post("/open", data={"address": PAGE}, headers=forged).status_code == 403


def test_oversized_and_wrong_methods_on_the_entry_form() -> None:
    env = Env()
    assert (
        env.client.post(
            "/open",
            content=b"address=" + b"a" * 20000,
            headers={"content-type": "application/x-www-form-urlencoded"},
        ).status_code
        == 413
    )
    assert env.client.get("/open").status_code == 404
    assert env.client.put("/").status_code == 405


def test_open_mode_cannot_be_turned_on_for_a_public_domain() -> None:
    with pytest.raises(ValueError, match="localhost"):
        Settings(base_domain="gw.example", open_mode=True)
    with pytest.raises(ValueError, match="key ring"):
        Settings(base_domain="gw.example")


def test_health_robots_and_unknown_hosts() -> None:
    env = Env()
    assert env.client.get("/_og/health").json() == {"status": "ok"}
    assert "Disallow: /" in env.client.get("/robots.txt").text
    assert env.client.get("/nothing-here").status_code == 404
    assert env.client.get("/", headers={"host": "evil.example"}).status_code == 404
    assert env.client.get("/", headers={"host": f"{'a' * 26}.localhost:{PORT}"}).status_code == 404
    assert env.client.get("/", headers={"host": f"x.localhost:{PORT}"}).status_code == 404


# --- fetching and rewriting pages ------------------------------------------------------------------


def test_a_page_is_fetched_rewritten_and_served_with_a_sandbox() -> None:
    page = (
        "<title>Hi</title><script>alert(1)</script><p onclick='x()'>text</p>"
        f"<a href='/next'>same</a><a href='http://{DUCKDUCKGO}.onion/'>other</a>"
        "<a href='https://example.org/'>web</a><img src='/a.png' alt='pic'>"
    )
    env = Env(lambda _request: reply(page))
    label = env.open()
    response = env.get(label, "/dir/index.html")
    assert response.status_code == 200
    body = response.text
    assert "<script" not in body and "onclick" not in body and "src=" not in body
    assert "[image withheld: pic]" in body
    assert f"http://{label}.localhost:{PORT}/next" in body
    assert "/_og/external?u=https%3A%2F%2Fexample.org%2F" in body
    assert ".invalid" not in body
    assert_safe_output(response.content, Owns())  # type: ignore[arg-type]
    csp = response.headers["content-security-policy"]
    assert csp.startswith("sandbox allow-forms allow-same-origin")
    assert "allow-scripts" not in csp
    assert response.headers["cache-control"] == "no-store"
    request = env.fetcher.requests[0]
    assert request.target == "/dir/index.html"
    assert request.headers["Host"] == f"{TOR_PROJECT}.onion"
    assert "Cookie" not in request.headers


def test_the_onion_sites_headers_never_reach_the_visitor() -> None:
    env = Env(
        lambda _request: reply(
            "<p>x</p>",
            headers=(
                ("Set-Cookie", "sid=abc; Path=/"),
                ("Content-Security-Policy", "default-src *"),
                ("Location", "http://evil.example/"),
                ("Access-Control-Allow-Origin", "*"),
                ("X-Powered-By", "secret"),
                ("Server", "nginx"),
                ("Refresh", "0; url=http://evil.example/"),
            ),
        )
    )
    response = env.get(env.open())
    names = {name.lower() for name in response.headers}
    for forbidden in (
        "set-cookie",
        "location",
        "access-control-allow-origin",
        "x-powered-by",
        "server",
        "refresh",
    ):
        assert forbidden not in names
    assert "evil" not in response.headers["content-security-policy"]


def test_cookies_stay_on_the_server_and_come_back_to_the_same_origin_only() -> None:
    def handler(request: UpstreamRequest) -> UpstreamResponse:
        if request.target == "/login":
            return reply("<p>in</p>", headers=(("Set-Cookie", "sid=abc123; Path=/"),))
        return reply("<p>page</p>")

    env = Env(handler)
    label = env.open()
    assert "set-cookie" not in env.get(label, "/login").headers
    env.get(label, "/account")
    assert env.fetcher.requests[1].headers["Cookie"] == "sid=abc123"
    other = env.open(f"http://{DUCKDUCKGO}.onion/")
    env.get(other, "/")
    assert "Cookie" not in env.fetcher.requests[2].headers
    assert "sid" not in str(env.client.cookies.get("og_session"))


def test_the_visitor_cannot_send_their_own_headers_to_the_onion_site() -> None:
    env = Env()
    label = env.open()
    env.get(
        label,
        "/",
        headers={
            "cookie": "evil=1",
            "x-forwarded-for": "203.0.113.5",
            "referer": "http://x/",
            "authorization": "Basic zz",
            "accept-language": "de",
        },
    )
    sent = {name.lower(): value for name, value in env.fetcher.requests[0].headers.items()}
    assert set(sent) <= {
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "cookie",
        "referer",
        "origin",
        "content-type",
    }
    assert sent["accept-language"] == "en-US,en;q=0.5"
    assert "evil" not in sent.get("cookie", "")


def test_a_link_to_another_onion_gets_its_own_label_that_works() -> None:
    def handler(request: UpstreamRequest) -> UpstreamResponse:
        if request.origin.host.address == TOR_PROJECT:
            return reply(f"<a href='http://{DUCKDUCKGO}.onion/page'>other</a>")
        return reply("<p>second site</p>")

    env = Env(handler)
    label = env.open()
    body = env.get(label).text
    link = next(part for part in body.split('"') if part.startswith("http://") and "/page" in part)
    other_label = env.label_in(link)
    assert other_label != label
    assert "second site" in env.get(other_label, "/page").text
    assert env.fetcher.requests[-1].origin.host.address == DUCKDUCKGO


def test_only_get_head_and_post_reach_the_onion_and_head_returns_no_body() -> None:
    env = Env()
    label = env.open()
    head = env.client.head("/", headers={"host": f"{label}.localhost:{PORT}"})
    assert head.status_code == 200 and head.content == b""
    assert env.fetcher.requests[0].method == "HEAD"
    assert env.client.delete("/", headers={"host": f"{label}.localhost:{PORT}"}).status_code == 405


def test_post_forms_are_forwarded_with_a_checked_content_type() -> None:
    env = Env()
    label = env.open()
    host = {"host": f"{label}.localhost:{PORT}"}
    response = env.client.post("/search", data={"q": "x y"}, headers=host)
    assert response.status_code == 200
    request = env.fetcher.requests[0]
    assert request.method == "POST" and request.body == b"q=x+y"
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert request.headers["Origin"] == f"http://{TOR_PROJECT}.onion"
    assert env.client.post("/search", json={"q": 1}, headers=host).status_code == 415
    assert (
        env.client.post(
            "/search", content=b"a" * 2_000_000, headers={**host, "content-type": "text/plain"}
        ).status_code
        == 413
    )


async def _raw_get(app: Any, host: str, raw_path: bytes, query: bytes) -> int:
    """Call the application directly, so bytes a client library would encode arrive untouched."""
    status = 0

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": raw_path.decode("latin-1"),
        "raw_path": raw_path,
        "query_string": query,
        "headers": [(b"host", host.encode())],
        "server": ("localhost", PORT),
        "client": ("127.0.0.1", 1),
        "http_version": "1.1",
    }
    await app(scope, receive, send)
    return status


def test_requests_with_unusable_targets_are_refused_before_the_onion_is_contacted() -> None:
    env = Env()
    label = env.open()
    host = f"{label}.localhost:{PORT}"
    assert env.get(label, "/caf%C3%A9").status_code == 200  # percent-encoded text is fine
    contacted = len(env.fetcher.requests)
    assert asyncio.run(_raw_get(env.gateway.app, host, b"/caf\xe9", b"")) == 400
    assert asyncio.run(_raw_get(env.gateway.app, host, b"/ok", b"q=\xe9")) == 400
    assert asyncio.run(_raw_get(env.gateway.app, host, b"/has space", b"")) == 400
    assert asyncio.run(_raw_get(env.gateway.app, host, b"/ok", b"q=a b")) == 400
    assert len(env.fetcher.requests) == contacted


# --- redirects -------------------------------------------------------------------------------------


def test_redirects_are_rewritten_and_never_followed() -> None:
    def handler(request: UpstreamRequest) -> UpstreamResponse:
        locations = {
            "/same": "/next",
            "/other": f"http://{DUCKDUCKGO}.onion/x",
            "/web": "https://example.org/page",
            "/script": "javascript:alert(1)",
            "/ftp": "ftp://example.org/",
            "/bad": "http://x.onion/",
        }
        return reply(
            b"", status=302, content_type=None, headers=(("Location", locations[request.target]),)
        )

    env = Env(handler)
    label = env.open()
    same = env.get(label, "/same")
    assert (
        same.status_code == 302
        and same.headers["location"] == f"http://{label}.localhost:{PORT}/next"
    )
    other = env.get(label, "/other")
    assert other.status_code == 302 and env.label_in(other.headers["location"]) != label
    web = env.get(label, "/web")
    assert (
        web.status_code == 302
        and "/_og/external?u=https%3A%2F%2Fexample.org%2Fpage" in web.headers["location"]
    )
    for path in ("/script", "/ftp", "/bad"):
        assert env.get(label, path).status_code == 502
    assert len(env.fetcher.requests) == 6  # exactly one fetch per request, none followed


def test_a_redirect_with_a_status_code_that_is_not_a_redirect_is_just_a_page() -> None:
    env = Env(
        lambda _r: reply(
            "<p>moved?</p>", status=200, headers=(("Location", "http://evil.example/"),)
        )
    )
    response = env.get(env.open())
    assert response.status_code == 200 and "location" not in response.headers


# --- stylesheets, images, fonts and other files --------------------------------------------------------


def test_stylesheets_are_rebuilt_and_sandboxed() -> None:
    css = (
        '@import "/more.css"; body{color:red;background:url(/bg.png)} @font-face{src:url(/f.woff2)}'
    )
    env = Env(lambda _r: reply(css, content_type="text/css"))
    label = env.open()
    response = env.get(label, "/style.css")
    assert response.headers["content-type"].startswith("text/css")
    assert response.headers["content-security-policy"].startswith("sandbox;")
    text = response.text
    assert "bg.png" not in text and "color:red" in text.replace(" ", "")
    assert f"http://{label}.localhost:{PORT}/more.css" in text and "f.woff2" in text
    assert ".invalid" not in text


def test_a_hostile_stylesheet_is_refused_or_cleaned_never_passed_on() -> None:
    env = Env(
        lambda _r: reply(
            "a{background:image-set(url(http://evil.example/x) 1x)}", content_type="text/css"
        )
    )
    response = env.get(env.open(), "/s.css")
    assert "evil" not in response.text


def test_images_are_withheld_unless_the_profile_allows_them() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 20
    env = Env(lambda _r: reply(png, content_type="image/png"))
    label = env.open()
    assert env.get(label, "/a.png").status_code == 403
    allowed = Env(
        lambda _r: reply(png, content_type="image/png"), profile=Profile(allow_images=True)
    )
    served = allowed.get(allowed.open(), "/a.png")
    assert served.status_code == 200 and served.content == png
    assert served.headers["content-type"] == "image/png"
    assert served.headers["content-security-policy"].startswith("sandbox;")


@pytest.mark.parametrize(
    "media",
    [
        "image/svg+xml",
        "application/pdf",
        "application/zip",
        "application/octet-stream",
        "video/mp4",
        "application/javascript",
        "text/xml",
        "application/json",
    ],
)
def test_other_kinds_of_file_are_not_passed_on(media: str) -> None:
    env = Env(lambda _r: reply(b"data", content_type=media), profile=Profile(allow_images=True))
    assert env.get(env.open(), "/x").status_code == 403


def test_missing_or_garbled_content_types_are_not_passed_on() -> None:
    def answer(content_type: str | None) -> Callable[[UpstreamRequest], UpstreamResponse]:
        return lambda _request: reply(b"data", content_type=content_type)

    for content_type in (None, "garbage", "text/", ""):
        env = Env(answer(content_type))
        assert env.get(env.open(), "/x").status_code == 403


def test_fonts_are_passed_on_unless_the_profile_forbids_them() -> None:
    env = Env(lambda _r: reply(b"font", content_type="font/woff2"))
    assert env.get(env.open(), "/f.woff2").content == b"font"
    strict = Env(
        lambda _r: reply(b"font", content_type="font/woff2"), profile=Profile(allow_fonts=False)
    )
    assert strict.get(strict.open(), "/f.woff2").status_code == 403


def test_plain_text_is_served_as_plain_text() -> None:
    env = Env(
        lambda _r: reply("<script>alert(1)</script>", content_type="text/plain; charset=utf-8")
    )
    response = env.get(env.open(), "/notes.txt")
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["x-content-type-options"] == "nosniff"


# --- compression and size ---------------------------------------------------------------------------------


def test_compressed_pages_are_decoded_and_bombs_and_damage_are_refused() -> None:
    page = "<p>compressed</p>" * 10
    ok = Env(
        lambda _r: reply(gzip.compress(page.encode()), headers=(("Content-Encoding", "gzip"),))
    )
    assert "compressed" in ok.get(ok.open()).text
    bomb = gzip.compress(b"a" * 20_000_000)
    refused = Env(lambda _r: reply(bomb, headers=(("Content-Encoding", "gzip"),)))
    assert refused.get(refused.open()).status_code == 502
    damaged = Env(
        lambda _r: reply(gzip.compress(page.encode())[:-8], headers=(("Content-Encoding", "gzip"),))
    )
    assert damaged.get(damaged.open()).status_code == 502
    unknown = Env(lambda _r: reply(b"x", headers=(("Content-Encoding", "br"),)))
    assert unknown.get(unknown.open()).status_code == 502


def test_a_page_that_cannot_be_made_safe_is_not_shown() -> None:
    env = Env(lambda _r: reply("<div>" * 100_000))
    response = env.get(env.open())
    assert response.status_code == 502
    assert "could not be shown safely" in response.text


# --- upstream failures -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        ("descriptor_not_found", 502),
        ("introduction_failed", 502),
        ("rendezvous_failed", 502),
        ("introduction_timeout", 504),
        ("auth_required", 403),
        ("auth_wrong", 403),
        ("timeout", 504),
        ("connect_timeout", 504),
        ("proxy_unreachable", 503),
        ("connection_refused", 502),
        ("connection_closed", 502),
        ("too_large", 502),
        ("tls_failed", 502),
        ("protocol_error", 502),
        ("some_future_kind", 502),
    ],
)
def test_every_failure_has_a_plain_error_page(kind: str, status: int) -> None:
    env = Env(lambda _r: UpstreamError(kind))
    response = env.get(env.open())
    assert response.status_code == status
    assert "<h1>" in response.text
    assert "content-security-policy" in response.headers


def test_unexpected_exceptions_become_a_generic_page_and_are_not_logged_in_detail(
    caplog: pytest.LogCaptureFixture,
) -> None:
    env = Env(lambda _r: RuntimeError(f"secret detail {TOR_PROJECT}"))
    label = env.open()
    with caplog.at_level(logging.DEBUG, logger="onionglass"):
        response = env.get(label, "/private/path?token=abc")
    assert response.status_code == 500
    assert "secret detail" not in response.text
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "RuntimeError" in logged
    for private in (TOR_PROJECT, "private", "token=abc", label):
        assert private not in logged


def test_nothing_visitor_identifying_is_logged_on_ordinary_failures(
    caplog: pytest.LogCaptureFixture,
) -> None:
    env = Env(lambda _r: UpstreamError("descriptor_not_found"))
    label = env.open()
    with caplog.at_level(logging.DEBUG, logger="onionglass"):
        env.get(label, "/some/secret/path")
        env.client.post("/open", data={"address": f"{TOR_PROJECT}.onion"})
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert TOR_PROJECT not in logged and "secret" not in logged and label not in logged


# --- warning page, labels and limits ----------------------------------------------------------------------------


def test_the_warning_page_shows_where_the_link_goes() -> None:
    env = Env()
    url = "https://example.org/a?b=<script>alert(1)</script>"
    response = env.client.get("/_og/external", params={"u": url})
    assert response.status_code == 200
    assert "example.org" in response.text and "leaves Tor" in response.text
    assert "<script>alert(1)" not in response.text
    assert 'target="_blank"' in response.text and "noopener" in response.text
    # Only the viewer's own frame may show the warning page, and only from its own origin.
    assert "frame-ancestors 'self'" in response.headers["content-security-policy"]


@pytest.mark.parametrize(
    "target",
    [
        "",
        "javascript:alert(1)",
        "ftp://example.org/",
        "http://user:pw@example.org/",
        "http://a b/",
        "/relative",
        "http://example.org/" + "a" * 3000,
        "data:text/html,x",
    ],
)
def test_the_warning_page_only_accepts_plain_web_addresses(target: str) -> None:
    env = Env()
    assert env.client.get("/_og/external", params={"u": target}).status_code == 400


def test_a_session_can_only_name_so_many_different_sites() -> None:
    addresses = [f"http://{TOR_PROJECT}.onion/", f"http://{DUCKDUCKGO}.onion/"]
    links = "".join(f"<a href='{a}x'>l</a>" for a in addresses)
    env = Env(lambda _r: reply(links), max_labels_per_session=1)
    label = env.open()  # uses the one label this session is allowed
    body = env.get(label).text
    assert ".invalid" not in body
    assert f"http://localhost:{PORT}/_og/blocked/x" in body or "/_og/blocked" in body
    assert env.client.get("/_og/blocked").status_code == 403
    assert_safe_output(env.get(label).content, Owns())  # type: ignore[arg-type]


def test_a_label_stops_working_when_its_session_ends() -> None:
    env = Env()
    label = env.open()
    assert env.get(label).status_code == 200
    session = env.client.cookies.get("og_session")
    asyncio.run(env.store.delete(f"sess:{session}"))
    assert env.get(label).status_code == 410


# --- sign-in tickets and the session cookie on a real domain ------------------------------------------------------


class Deployed:
    """A team-mode gateway on a real domain, where tickets sign visitors in."""

    def __init__(self) -> None:
        self.key = generate_key()
        keys = KeyRing()
        keys.add("k1", self.key.public_key())
        self.issuer = TicketIssuer(self.key, "k1", "onionglass")
        self.settings = Settings(base_domain="gw.example", keys=keys)
        self.fetcher = FakeFetcher()
        self.gateway = Gateway(self.settings, fetcher=self.fetcher)
        self.client = TestClient(
            self.gateway.app, base_url="https://gw.example", follow_redirects=False
        )

    def ticket(self, **kwargs: Any) -> str:
        return self.issuer.issue(subject="analyst-1", group="team", profile="personal", **kwargs)


def test_without_a_ticket_nothing_can_be_opened_on_a_real_domain() -> None:
    env = Deployed()
    assert "sign in" in env.client.get("/").text.lower()
    assert env.client.post("/open", data={"address": PAGE}).status_code == 403
    assert env.client.get("/enter", params={"t": "garbage"}).status_code == 403
    assert env.client.get("/enter").status_code == 403


def test_a_ticket_signs_the_visitor_in_once_and_only_once() -> None:
    env = Deployed()
    ticket = env.ticket()
    first = env.client.get("/enter", params={"t": ticket})
    assert first.status_code == 303 and first.headers["location"] == "https://gw.example/"
    cookie = first.headers["set-cookie"].lower()
    assert (
        "domain=gw.example" in cookie
        and "secure" in cookie
        and "httponly" in cookie
        and "samesite=lax" in cookie
    )
    assert env.client.get("/enter", params={"t": ticket}).status_code == 403  # replay


def test_a_ticket_can_open_one_onion_directly() -> None:
    env = Deployed()
    response = env.client.get("/enter", params={"t": env.ticket(onion=TOR_PROJECT)})
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("https://gw.example/view?l=")
    assert TOR_PROJECT not in location


def test_labels_need_the_matching_session_cookie_on_a_real_domain() -> None:
    env = Deployed()
    env.client.get("/enter", params={"t": env.ticket()})
    opened = env.client.post(
        "/open", data={"address": PAGE}, headers={"origin": "https://gw.example"}
    )
    assert opened.status_code == 303
    label_host = f"{Env.viewer_label(opened.headers['location'])}.gw.example"
    assert env.client.get("/", headers={"host": label_host}).status_code == 200
    stranger = TestClient(env.gateway.app, base_url="https://gw.example", follow_redirects=False)
    assert stranger.get("/", headers={"host": label_host}).status_code == 403
    other = TestClient(env.gateway.app, base_url="https://gw.example", follow_redirects=False)
    other.get("/enter", params={"t": env.ticket()})
    assert other.get("/", headers={"host": label_host}).status_code == 403
    other.cookies.set("og_session", "x" * 32, domain="gw.example")
    assert other.get("/", headers={"host": label_host}).status_code == 403
