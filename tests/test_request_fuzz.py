# SPDX-License-Identifier: AGPL-3.0-only
"""Generated requests and replies through the whole gateway.

The rewriter tests cover what a page can say. These cover the other side: everything a visitor's
browser sends, and everything an onion site's reply can carry. Two things must hold whatever the
input is.

* Nothing that identifies the visitor or their session reaches the onion site. Every request the
  fake onion site receives is checked against an allowlist of header names, and each visitor
  header carries a marker that must never be seen upstream.
* Nothing from the onion site's reply reaches the visitor except through the gateway's own
  headers, and no request ends in an internal error.
"""

from __future__ import annotations

import os
import re
import string
from typing import Any
from urllib.parse import urlsplit

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from onionglass.cookies import MAX_HEADER_BYTES, parse_set_cookie
from onionglass.onion import parse_onion_url
from onionglass.settings import Profile
from test_gateway import PAGE, PORT, Env, reply
from test_grammar_fuzz import documents

pytestmark = pytest.mark.timeout(600)
SCALE = max(1, int(os.environ.get("ONIONGLASS_FUZZ_SCALE", "1")))
HUNT = settings(
    max_examples=150 * SCALE,
    deadline=None,
    suppress_health_check=list(HealthCheck),
)

MARK = "VISITORSECRET"
UPSTREAM_NAMES = frozenset(
    {
        "host", "user-agent", "accept", "accept-language", "accept-encoding", "cookie", "referer",
        "origin", "content-type",
    }
)  # fmt: skip

# --- what a visitor's browser can send ---------------------------------------------------------

SEC_FETCH = {
    "sec-fetch-site": ["same-origin", "same-site", "cross-site", "none", "bogus", ""],
    "sec-fetch-mode": ["navigate", "cors", "no-cors", "same-origin", "websocket", "bogus"],
    "sec-fetch-dest": ["document", "iframe", "frame", "style", "image", "font", "script", "empty"],
    "sec-fetch-user": ["?1", "?0", "x"],
}
OTHER_HEADERS = [
    "cookie", "authorization", "proxy-authorization", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-real-ip", "forwarded", "via", "user-agent", "accept-language", "accept",
    "accept-encoding", "origin", "dnt", "sec-gpc", "sec-ch-ua", "sec-ch-ua-platform", "te",
    "upgrade", "x-requested-with", "cache-control", "pragma", "if-none-match",
    "if-modified-since", "range", "expect", "x-custom", "x-og-session", "client-ip", "true-client-ip",
    "cf-connecting-ip", "x-client-ip", "x-originating-ip", "fastly-client-ip", "x-wap-profile",
]  # fmt: skip
BOUNDARIES = [
    "WKBabc123def456ghi789", "WKB----xyz", "WKBquoted", "xYz", "a", "-", "WKB" + "x" * 67,
    "WKB" + "x" * 80, "bad;semi", "has space", "'q'", "WKB(a)+b_c,d-e.f/g:h=i?j",
]  # fmt: skip
CONTENT_TYPES = [
    "multipart/form-data; boundary={b}", 'multipart/form-data; boundary="{b}"',
    "MULTIPART/FORM-DATA; BOUNDARY={b}", "multipart/form-data;boundary={b}",
    "multipart/form-data; boundary=OTHER; boundary={b}", "multipart/form-data; charset=x; boundary={b}",
    "multipart/form-data", "multipart/form-data; boundary=", "multipart/mixed; boundary={b}",
    "application/x-www-form-urlencoded", "application/x-www-form-urlencoded; charset=utf-8",
    "text/plain", "application/json", "text/html", "application/octet-stream", "", "x",
]  # fmt: skip
METHODS = [
    "GET",
    "GET",
    "POST",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "TRACE",
    "FOO",
]
SEGMENTS = [
    "a", "b.html", "..", ".", "%2e%2e", "%2E", "%2F", "%5c", "%00", "%0d%0a", "%C3%A9", "%FF", "%",
    "x" * 300, "", ";x=1", "~", "a%20b", "index.php", "%2e%2e%2f", "..%5c", "@", ":", "[", "%u0041",
]  # fmt: skip
QUERIES = [
    "", "a=1", "a=%00", "%0d%0a", "x=http://evil.example", "x[]=1", "=", "&&", "a=b&a=c",
    "q=" + "z" * 2000, "%FF%FE", "a=%", "javascript:alert(1)", "u=http%3A%2F%2Fevil.example%2F",
]  # fmt: skip


@st.composite
def visitor_requests(draw: st.DrawFn) -> dict[str, Any]:
    method = draw(st.sampled_from(METHODS))
    path = "/" + "/".join(draw(st.lists(st.sampled_from(SEGMENTS), max_size=5)))
    query = draw(st.sampled_from(QUERIES))
    headers: dict[str, str] = {}
    for name in draw(st.lists(st.sampled_from(sorted(SEC_FETCH)), max_size=4, unique=True)):
        headers[name] = draw(st.sampled_from(SEC_FETCH[name]))
    for name in draw(st.lists(st.sampled_from(OTHER_HEADERS), max_size=10, unique=True)):
        junk = draw(
            st.text(alphabet=string.ascii_letters + string.digits + " ;,=/-_.:", max_size=24)
        )
        headers[name] = MARK + junk
    referer = draw(st.sampled_from([None, "SELF", "SELF-DEEP", "OTHER", "TRICK"]))
    boundary = draw(st.sampled_from(BOUNDARIES))
    content_type = draw(st.sampled_from(CONTENT_TYPES)).format(b=boundary)
    embedded = draw(st.booleans())
    value = f"v{boundary}v" if embedded else "v"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="a"\r\n\r\n{value}\r\n'
        f"--{boundary}--\r\n"
    ).encode()
    if draw(st.integers(0, 4)) == 0:
        body = draw(st.binary(max_size=300))
    return {
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "referer": referer,
        "content_type": content_type,
        "body": body,
        "boundary": boundary,
    }


def send(env: Env, label: str, case: dict[str, Any]) -> Any:
    host = f"{label}.localhost:{PORT}"
    headers = {"host": host, **case["headers"]}
    referer = case["referer"]
    if referer == "SELF":
        headers["referer"] = f"http://{host}/start"
    elif referer == "SELF-DEEP":
        headers["referer"] = f"http://{host}/a/b/c?d=e#f"
    elif referer == "OTHER":
        headers["referer"] = f"http://evil.example/{MARK}"
    elif referer == "TRICK":
        headers["referer"] = f"http://{host}.evil.example/{MARK}"
    if case["method"] in ("POST", "PUT", "PATCH"):
        headers["content-type"] = case["content_type"]
    url = case["path"] + (f"?{case['query']}" if case["query"] else "")
    try:
        return env.client.request(
            case["method"],
            url,
            headers=headers,
            content=case["body"] if case["method"] != "GET" else None,
        )
    except Exception as exc:  # the client refusing to build an odd request is not a finding
        if type(exc).__module__.startswith("httpx") or isinstance(exc, ValueError):
            pytest.skip("the test client would not send that request")
        raise


@HUNT
@given(visitor_requests())
def test_nothing_identifying_reaches_the_onion_site(case: dict[str, Any]) -> None:
    env = Env()
    label = env.open()
    session = env.client.cookies.get(env.settings.cookie_name) or ""
    before = len(env.fetcher.requests)
    response = send(env, label, case)
    assert response.status_code != 500, f"internal error for {case}"
    sent = env.fetcher.requests[before:]
    if case["method"] not in ("GET", "HEAD", "POST"):
        assert sent == [], "a method the gateway does not allow reached the onion site"
    origin_text = f"http://{PAGE.split('/')[2]}"
    for upstream in sent:
        names = {name.lower() for name in upstream.headers}
        assert names <= UPSTREAM_NAMES, f"unexpected headers upstream: {names - UPSTREAM_NAMES}"
        everything = " ".join([*upstream.headers.values(), upstream.target])
        assert MARK not in everything
        header_text = " ".join(upstream.headers.values())
        assert "localhost" not in header_text and "evil.example" not in header_text
        assert label not in everything
        if session:
            assert session not in everything
            assert session not in upstream.isolation_key
        assert upstream.method in ("GET", "HEAD", "POST")
        assert "Cookie" not in upstream.headers  # nothing was ever stored for this origin
        referer = upstream.headers.get("Referer")
        if referer is not None:
            assert referer.startswith(origin_text), referer
            assert parse_onion_url(referer, allowed_ports=frozenset(range(1, 65536)))
        if upstream.method == "POST":
            origin = upstream.headers["Origin"]
            assert origin in ("null", origin_text)
        else:
            assert "Origin" not in upstream.headers
        content_type = upstream.headers.get("Content-Type", "")
        if content_type.startswith("multipart/form-data"):
            assert re.fullmatch(
                r"multipart/form-data; boundary=[-A-Za-z0-9'()+_,./:=? ]{1,70}", content_type
            )
            boundary = case["boundary"]
            if boundary.startswith("WKB") and set(boundary) <= set(
                string.ascii_letters + string.digits
            ):
                assert boundary not in content_type
                assert f"--{boundary}".encode() not in upstream.body


# --- what an onion site's reply can carry --------------------------------------------------------

STATUSES = [
    100,
    101,
    199,
    200,
    201,
    204,
    205,
    206,
    301,
    302,
    303,
    304,
    307,
    308,
    400,
    404,
    500,
    502,
    600,
    999,
]
CONTENT_TYPES_BACK = [
    "text/html", "text/html; charset=shift_jis", "text/html; charset=utf-7", "TEXT/HTML", "text/css",
    "text/plain", "text/javascript", "application/javascript", "application/xhtml+xml", "image/svg+xml",
    "text/xml", "application/xml", "application/pdf", "application/octet-stream", "image/png",
    "image/jpeg", "font/woff2", "multipart/x-mixed-replace", "text/html, text/css", "", "x",
    "text/html; charset=\"utf-8\"; foo=bar", "message/rfc822", "application/x-shockwave-flash",
]  # fmt: skip
ENCODINGS = [
    None,
    "gzip",
    "deflate",
    "br",
    "zstd",
    "identity",
    "gzip, gzip",
    "gzip, gzip, gzip",
    "x",
]
LOCATIONS = [
    "/a", "http://evil.example/x", "//evil.example/x", "javascript:alert(1)", "data:text/html,x",
    f"{PAGE}x", "http://abc.onion/", "https://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/z",
    "", " ", "\\\\evil.example", "http://[::1]/", "ftp://evil.example/",
]  # fmt: skip
BACK_HEADERS = [
    "set-cookie", "refresh", "link", "content-disposition", "x-frame-options",
    "content-security-policy", "content-security-policy-report-only", "report-to", "nel",
    "access-control-allow-origin", "access-control-allow-credentials", "strict-transport-security",
    "alt-svc", "clear-site-data", "permissions-policy", "referrer-policy", "cache-control", "etag",
    "vary", "server", "x-powered-by", "x-custom", "www-authenticate", "content-language",
    "content-location", "p3p", "x-content-type-options", "cross-origin-opener-policy",
    "cross-origin-resource-policy", "timing-allow-origin", "accept-ch", "critical-ch",
    "origin-agent-cluster", "service-worker-allowed", "sourcemap", "x-sourcemap", "content-range",
    "accept-ranges", "last-modified", "expires", "age", "content-length", "transfer-encoding",
    "connection", "keep-alive", "upgrade", "trailer",
]  # fmt: skip
FORBIDDEN_BACK = frozenset(
    {
        "set-cookie", "refresh", "link", "content-disposition", "x-frame-options", "report-to", "nel",
        "alt-svc", "clear-site-data", "www-authenticate", "server", "x-powered-by", "content-location",
        "sourcemap", "x-sourcemap", "accept-ch", "critical-ch", "service-worker-allowed",
        "access-control-allow-origin", "access-control-allow-credentials", "timing-allow-origin",
        "content-security-policy-report-only", "etag", "last-modified", "expires", "age", "vary",
        "keep-alive", "upgrade", "trailer", "content-range", "accept-ranges", "origin-agent-cluster",
        "p3p", "content-language",
    }
)  # fmt: skip
SAFE_BACK_TYPES = re.compile(
    r"^(text/html; charset=utf-8|text/css; charset=utf-8|text/plain; charset=utf-8"
    r"|image/(png|jpeg|gif|webp|avif|bmp|x-icon|vnd\.microsoft\.icon)|font/(woff2?|ttf|otf)"
    r"|application/font-woff2?)$"
)


@st.composite
def onion_replies(draw: st.DrawFn) -> dict[str, Any]:
    headers = []
    for name in draw(st.lists(st.sampled_from(BACK_HEADERS), max_size=14, unique=True)):
        if name == "content-length":
            headers.append((name, draw(st.sampled_from(["0", "5", "99999999", "-1", "abc", ""]))))
        else:
            headers.append(
                (
                    name,
                    MARK + draw(st.text(alphabet=string.ascii_letters + " ;,=/*-'", max_size=20)),
                )
            )
    location = draw(st.sampled_from([None, None, *LOCATIONS]))
    if location is not None:
        headers.append(("location", location))
    encoding = draw(st.sampled_from(ENCODINGS))
    if encoding is not None:
        headers.append(("content-encoding", encoding))
    kind = draw(st.integers(0, 3))
    if kind == 0:
        body = draw(documents()).encode("utf-8")
    elif kind == 1:
        body = draw(st.binary(max_size=600))
    elif kind == 2:
        body = b"a{background:url(http://evil.example/x)}" + draw(st.binary(max_size=40))
    else:
        body = b""
    return {
        "status": draw(st.sampled_from(STATUSES)),
        "content_type": draw(st.sampled_from(CONTENT_TYPES_BACK)),
        "headers": tuple(headers),
        "body": body,
    }


LOCATION_OK = re.compile(
    rf"^http://(localhost:{PORT}/_og/(external\?u=|blocked)|[a-z2-7]{{26}}\.localhost:{PORT}/)"
)


@HUNT
@given(onion_replies(), st.sampled_from([False, True]), st.sampled_from(["GET", "HEAD", "POST"]))
def test_nothing_from_the_onion_reply_reaches_the_visitor_except_through_the_gateway(
    case: dict[str, Any], images: bool, method: str
) -> None:
    state: dict[str, Any] = {"armed": False}

    def handler(_request: Any) -> Any:
        if not state["armed"]:
            return reply("<p>start</p>")
        return reply(
            case["body"],
            status=case["status"],
            content_type=case["content_type"] or None,
            headers=case["headers"],
        )

    env = Env(handler, profile=Profile(allow_images=images))
    label = env.open()
    state["armed"] = True
    host = f"{label}.localhost:{PORT}"
    response = env.client.request(
        method,
        "/p",
        headers={"host": host, "sec-fetch-site": "same-origin"},
        content=b"a=1" if method == "POST" else None,
    )
    if response.status_code == 500:
        assert case["status"] == 500, f"internal error for {case}"  # the site said 500 itself
    names = {name.lower() for name in response.headers}
    assert not names & FORBIDDEN_BACK, f"reply headers passed through: {names & FORBIDDEN_BACK}"
    for name, value in response.headers.items():
        assert MARK not in value, f"{name} carries the onion site's text"
    assert "content-security-policy" in names, "a response without a policy"
    policy = response.headers["content-security-policy"]
    assert "default-src 'none'" in policy and "sandbox" in policy
    assert response.headers.get("x-content-type-options") == "nosniff"
    if response.status_code < 300 or response.status_code >= 400:
        media = response.headers.get("content-type", "")
        if response.content:
            assert SAFE_BACK_TYPES.match(media) or media.startswith("text/html"), media
    location = response.headers.get("location")
    if 300 <= response.status_code < 400 and location is not None:
        assert LOCATION_OK.match(location), location
    assert urlsplit(location or "http://localhost/").scheme in ("http", "https")


# --- cookies -------------------------------------------------------------------------------------

COOKIE_NAMES = [
    "sid",
    "a",
    "__Host-x",
    "__Secure-y",
    "x y",
    "x;y",
    "x=y",
    "",
    "n" * 300,
    "NAME",
    "ok-name",
]
COOKIE_VALUES = [
    "v",
    "",
    "a b",
    'a"b',
    "a;b",
    "a,b",
    "a\\b",
    "a\r\nSet-Cookie: z=1",
    "a\x00b",
    "v" * 5000,
    "dmFsdWU=",
    "'q'",
]
COOKIE_ATTRIBUTES = [
    "", "Path=/", "Path=/a", "Path=a", "Path=", "Path=/../x", "Domain=x.onion", "Domain=.onion",
    "Domain=evil.example", "Domain=", "SameSite=None", "SameSite=Strict", "SameSite=Lax", "SameSite=bogus",
    "Max-Age=0", "Max-Age=-1", "Max-Age=99999999999999999999", "Max-Age=abc", "Max-Age=60",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT", "Expires=Wed, 21 Oct 2099 07:28:00 GMT", "Expires=bogus",
    "Expires=Thu, 01 Jan 1970 00:00:00 -0000", "Secure", "HttpOnly", "Partitioned", "Priority=High",
    "x" * 5000,
]  # fmt: skip
COOKIE_GRAMMAR = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+=[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*"
    r"(; [!#$%&'*+\-.^_`|~0-9A-Za-z]+=[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*)*$"
)


@st.composite
def set_cookie_lines(draw: st.DrawFn) -> str:
    parts = [f"{draw(st.sampled_from(COOKIE_NAMES))}={draw(st.sampled_from(COOKIE_VALUES))}"]
    parts += draw(st.lists(st.sampled_from(COOKIE_ATTRIBUTES), max_size=4))
    return "; ".join(p for p in parts if p)


@HUNT
@given(
    st.lists(set_cookie_lines(), max_size=40),
    st.sampled_from(["same-origin", "cross-site", "none"]),
)
def test_stored_cookies_come_back_well_formed_and_never_reach_the_visitor(
    lines: list[str], site: str
) -> None:
    state = {"armed": False}

    def handler(_request: Any) -> Any:
        if state["armed"]:
            return reply("<p>x</p>", headers=tuple(("set-cookie", line) for line in lines))
        return reply("<p>start</p>")

    env = Env(handler)
    label = env.open()
    state["armed"] = True
    host = f"{label}.localhost:{PORT}"
    first = env.client.get("/a/b", headers={"host": host, "sec-fetch-site": "same-origin"})
    assert first.status_code != 500
    assert "set-cookie" not in {name.lower() for name in first.headers}
    state["armed"] = False
    env.client.get(
        "/a/b/c",
        headers={
            "host": host,
            "sec-fetch-site": site,
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
        },
    )
    cookie = env.fetcher.requests[-1].headers.get("Cookie")
    if cookie is not None:
        assert COOKIE_GRAMMAR.match(cookie), cookie
        assert len(cookie) <= MAX_HEADER_BYTES
        assert "\r" not in cookie and "\n" not in cookie


@HUNT
@given(st.text(max_size=300), st.integers(0, 10**10))
def test_no_set_cookie_text_can_crash_the_parser(header: str, now: int) -> None:
    origin = parse_onion_url(PAGE).origin
    parse_set_cookie(header, origin, "/a/b", float(now))
