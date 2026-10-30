# SPDX-License-Identifier: AGPL-3.0-only
"""Visitor-facing headers (P1 backstop) and clean upstream request headers (P4)."""

from __future__ import annotations

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.headers import (
    DEFAULT_USER_AGENT,
    HeaderPolicy,
    document_headers,
    parse_content_type,
    resource_headers,
    upstream_request_headers,
    visitor_headers_from_upstream,
)
from onionglass.onion import OnionHost, OnionOrigin

POLICY = HeaderPolicy("https", "gw.example", viewer_origin="https://gw.example")
LOCAL = HeaderPolicy(
    "http", "localhost", port=8080, viewer_origin="http://localhost:8080", hsts=True
)
ORIGIN = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)


def directives(csp: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in csp.split(";"):
        name, _, value = part.strip().partition(" ")
        result[name] = value
    return result


def test_documents_are_sandboxed_without_script() -> None:
    csp = directives(document_headers(POLICY)["Content-Security-Policy"])
    assert csp["sandbox"] == "allow-forms allow-same-origin"
    assert csp["script-src"] == "'none'"
    assert csp["default-src"] == "'none'"
    assert csp["object-src"] == "'none'"
    assert csp["base-uri"] == "'none'"
    assert csp["connect-src"] == "'none'"
    assert csp["frame-src"] == "'none'"


def test_no_policy_ever_allows_scripts_popups_or_top_navigation() -> None:
    for policy in (POLICY, LOCAL, HeaderPolicy("https", "gw.example")):
        for headers in (document_headers(policy), resource_headers(policy, "image/png")):
            csp = headers["Content-Security-Policy"]
            for forbidden in (
                "allow-scripts",
                "allow-popups",
                "allow-top-navigation",
                "allow-modals",
            ):
                assert forbidden not in csp
            assert "unsafe-eval" not in csp
            assert "'unsafe-inline'" not in directives(csp).get("script-src", "")


def test_sources_are_limited_to_the_gateways_own_hosts() -> None:
    csp = directives(document_headers(POLICY)["Content-Security-Policy"])
    assert csp["img-src"] == "https://*.gw.example"
    assert csp["font-src"] == "https://*.gw.example"
    assert csp["form-action"] == "https://*.gw.example"
    assert csp["style-src"] == "https://*.gw.example 'unsafe-inline'"
    local = directives(document_headers(LOCAL)["Content-Security-Policy"])
    assert local["img-src"] == "http://*.localhost:8080"


def test_only_the_viewer_may_frame_a_page() -> None:
    assert (
        directives(document_headers(POLICY)["Content-Security-Policy"])["frame-ancestors"]
        == "https://gw.example"
    )
    alone = HeaderPolicy("https", "gw.example")
    assert (
        directives(document_headers(alone)["Content-Security-Policy"])["frame-ancestors"]
        == "'none'"
    )


def test_common_privacy_and_hardening_headers() -> None:
    headers = document_headers(POLICY)
    # Pages on the gateway's label hosts send a Referer only to their own origin, which lets a
    # same-origin form post carry a real Origin and a cross-origin one carry none.
    assert headers["Referrer-Policy"] == "same-origin"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Cache-Control"] == "no-store"
    assert "noindex" in headers["X-Robots-Tag"]
    for feature in ("camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"):
        assert feature in headers["Permissions-Policy"]
    assert headers["Content-Type"] == "text/html; charset=utf-8"


def test_hsts_only_over_https_and_only_when_enabled() -> None:
    assert "Strict-Transport-Security" in document_headers(POLICY)
    assert "Strict-Transport-Security" not in document_headers(LOCAL)
    off = HeaderPolicy("https", "gw.example", hsts=False)
    assert "Strict-Transport-Security" not in document_headers(off)


def test_resources_are_sandboxed_too() -> None:
    headers = resource_headers(POLICY, "image/svg+xml")
    assert headers["Content-Security-Policy"].startswith("sandbox;")
    assert headers["Content-Type"] == "image/svg+xml"
    assert headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(
    "bad",
    [
        {"scheme": "ftp", "base_domain": "gw.example"},
        {"scheme": "https", "base_domain": ""},
        {"scheme": "https", "base_domain": "gw.example; script-src *"},
        {"scheme": "https", "base_domain": "gw.example", "port": 0},
        {
            "scheme": "https",
            "base_domain": "gw.example",
            "viewer_origin": "https://x.example; sandbox",
        },
        {
            "scheme": "https",
            "base_domain": "gw.example",
            "viewer_origin": "https://x.example\r\nSet-Cookie: a=b",
        },
    ],
)
def test_a_policy_cannot_inject_extra_directives(bad: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r"scheme|port|domain|origin"):
        HeaderPolicy(**bad)  # type: ignore[arg-type]


def test_content_type_parsing() -> None:
    assert parse_content_type("text/html; charset=UTF-8") == ("text/html", "utf-8")
    assert parse_content_type('Text/CSS ; Charset="iso-8859-1"') == ("text/css", "iso-8859-1")
    assert parse_content_type("image/png") == ("image/png", None)
    for bad in (
        None,
        "",
        "garbage",
        "text/",
        "/html",
        "text/ht ml",
        "text/html\r\nX: y",
        "a" * 300,
    ):
        assert parse_content_type(bad) == ("application/octet-stream", None)
    # A charset parameter that is not a clean token is ignored rather than trusted.
    assert parse_content_type("text/html; charset=utf-8\x00") == ("text/html", None)


def test_nothing_from_the_onion_sites_own_headers_reaches_the_visitor_but_the_media_type() -> None:
    upstream = {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": "session=abc; Domain=gw.example",
        "Content-Security-Policy": "default-src *",
        "Location": "http://evil.example/",
        "Strict-Transport-Security": "max-age=0",
        "Access-Control-Allow-Origin": "*",
        "X-Powered-By": "something",
        "Server": "nginx",
        "Link": "<http://evil.example/>; rel=preload",
        "Refresh": "0; url=http://evil.example/",
        "Clear-Site-Data": '"cookies"',
    }
    assert visitor_headers_from_upstream(upstream) == {"Content-Type": "text/html; charset=utf-8"}
    assert visitor_headers_from_upstream({}) == {"Content-Type": "application/octet-stream"}


# --- upstream request headers ------------------------------------------------------------------


def test_upstream_headers_are_built_from_scratch() -> None:
    headers = upstream_request_headers(ORIGIN, method="GET")
    assert headers == {
        "Host": f"{TOR_PROJECT}.onion",
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }


def test_nothing_identifying_can_be_added() -> None:
    headers = upstream_request_headers(ORIGIN, method="GET", cookie="a=b")
    lowered = {name.lower() for name in headers}
    for name in (
        "x-forwarded-for",
        "x-real-ip",
        "via",
        "forwarded",
        "authorization",
        "dnt",
        "x-requested-with",
    ):
        assert name not in lowered
    assert headers["Cookie"] == "a=b"


def test_host_header_includes_virtual_host_labels_and_non_default_ports() -> None:
    origin = OnionOrigin("https", OnionHost(TOR_PROJECT, ("www",)), 8443)
    assert upstream_request_headers(origin, method="GET")["Host"] == f"www.{TOR_PROJECT}.onion:8443"
    secure = OnionOrigin("https", OnionHost(TOR_PROJECT), 443)
    assert upstream_request_headers(secure, method="GET")["Host"] == f"{TOR_PROJECT}.onion"


def test_referer_is_sent_only_for_the_same_origin() -> None:
    same = f"http://{TOR_PROJECT}.onion/a/b?c=d#frag"
    assert (
        upstream_request_headers(ORIGIN, method="GET", referer=same)["Referer"]
        == f"http://{TOR_PROJECT}.onion/a/b?c=d"
    )
    for other in (
        f"http://{DUCKDUCKGO}.onion/",
        f"https://{TOR_PROJECT}.onion/",
        "https://example.org/",
        "https://gw.example/viewer?t=ticket",
        "not a url",
        f"http://www.{TOR_PROJECT}.onion/",
    ):
        assert "Referer" not in upstream_request_headers(ORIGIN, method="GET", referer=other)


def test_post_adds_origin_and_a_checked_content_type() -> None:
    headers = upstream_request_headers(
        ORIGIN, method="POST", content_type="application/x-www-form-urlencoded; charset=UTF-8"
    )
    assert headers["Origin"] == f"http://{TOR_PROJECT}.onion"
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    multipart = upstream_request_headers(
        ORIGIN, method="POST", content_type="multipart/form-data; boundary=----abc123"
    )
    assert multipart["Content-Type"] == "multipart/form-data; boundary=----abc123"
    assert "Origin" not in upstream_request_headers(ORIGIN, method="GET")


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "text/html",
        "multipart/form-data",
        'multipart/form-data; boundary="a\r\nX: y"',
        "multipart/form-data; boundary=" + "a" * 100,
        "x" * 300,
    ],
)
def test_unexpected_request_content_types_are_refused(content_type: str) -> None:
    with pytest.raises(ValueError, match=r"content type|boundary"):
        upstream_request_headers(ORIGIN, method="POST", content_type=content_type)


def test_only_get_head_and_post_are_allowed() -> None:
    for method in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "get", ""):
        with pytest.raises(ValueError, match="method"):
            upstream_request_headers(ORIGIN, method=method)
    for method in ("GET", "HEAD", "POST"):
        assert upstream_request_headers(ORIGIN, method=method)


def test_header_injection_is_refused() -> None:
    for bad in (
        "a=b\r\nX-Evil: 1",
        "a=b\nX-Evil: 1",
        "a=b\x00",
        "caf" + chr(0xE9) + "=1",
    ):
        with pytest.raises(ValueError, match="control or non-ASCII"):
            upstream_request_headers(ORIGIN, method="GET", cookie=bad)
    with pytest.raises(ValueError, match="control or non-ASCII"):
        upstream_request_headers(ORIGIN, method="GET", user_agent="ua\r\nX: y")
