# SPDX-License-Identifier: AGPL-3.0-only
"""Property P2: every reference in a page ends up on the gateway, or is dropped."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from helpers import DUCKDUCKGO, TOR_PROJECT, FakeMapper, base_url
from onionglass.rewrite.urls import resolve_reference

MAPPER = FakeMapper()
BASE = base_url()
ORIGIN_PREFIX = MAPPER.onion(BASE.origin)


def resolve(reference: str):  # type: ignore[no-untyped-def]
    return resolve_reference(reference, BASE, MAPPER)


@pytest.mark.parametrize(
    ("reference", "expected_path"),
    [
        ("other.html", "/dir/other.html"),
        ("/root.html", "/root.html"),
        ("../up.html", "/up.html"),
        ("./same.html?x=1", "/dir/same.html?x=1"),
        ("sub/dir/", "/dir/sub/dir/"),
        ("?q=1", "/dir/page.html?q=1"),
        (f"http://{TOR_PROJECT}.onion/abs", "/abs"),
        (f"//{TOR_PROJECT}.onion/scheme-relative", "/scheme-relative"),
        ("HTTP:other.html", "/dir/other.html"),
    ],
)
def test_references_to_the_same_onion_become_gateway_urls(
    reference: str, expected_path: str
) -> None:
    result = resolve(reference)
    assert result.kind == "onion"
    assert result.url == ORIGIN_PREFIX + expected_path


def test_fragments_are_kept() -> None:
    assert resolve("/p#section-2").url == ORIGIN_PREFIX + "/p#section-2"
    assert resolve("#top").kind == "local"
    assert resolve("#top").url == "#top"
    assert resolve("").kind == "local"
    assert resolve("").url == ""


def test_a_different_onion_gets_its_own_gateway_origin() -> None:
    result = resolve(f"http://{DUCKDUCKGO}.onion/x")
    assert result.kind == "onion"
    assert result.url.startswith("https://")
    assert result.url != ORIGIN_PREFIX + "/x"
    assert result.url.endswith(".gw.example/x")


def test_https_and_http_of_the_same_onion_are_different_origins() -> None:
    plain = resolve(f"http://{TOR_PROJECT}.onion/x").url
    secure = resolve(f"https://{TOR_PROJECT}.onion/x").url
    assert plain != secure


def test_virtual_host_labels_are_part_of_the_origin() -> None:
    assert resolve(f"http://www.{TOR_PROJECT}.onion/x").url != resolve("/x").url


@pytest.mark.parametrize(
    "reference",
    [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "java\tscript:alert(1)",
        "java\nscript:alert(1)",
        "java\rscript:alert(1)",
        "  javascript:alert(1)",
        "\x01javascript:alert(1)",
        "vbscript:msgbox(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "data:image/png;base64,AAAA",
        "blob:http://x/1",
        "file:///etc/passwd",
        "ftp://example.org/x",
        "about:blank",
        "view-source:http://x",
        "localhost:8080/x",
    ],
)
def test_unsafe_schemes_are_dropped(reference: str) -> None:
    assert resolve(reference).kind == "dropped"


def test_non_web_links_are_dropped_with_their_own_reason() -> None:
    for reference in (
        "mailto:a@b.example",
        "tel:+10000000",
        "magnet:?xt=urn:btih:x",
        "bitcoin:addr",
    ):
        result = resolve(reference)
        assert result.kind == "dropped"
        assert result.reason == "non_web_link"


@pytest.mark.parametrize(
    "reference",
    [
        "http://example.org/page",
        "https://example.org:8443/page?x=1",
        "//example.org/page",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://localhost/",
        "HTTP://EXAMPLE.ORG/",
    ],
)
def test_links_to_the_normal_internet_go_to_the_warning_page(reference: str) -> None:
    result = resolve(reference)
    assert result.kind == "external"
    assert result.url.startswith("https://gw.example/_og/external?u=")


def test_the_warning_page_url_does_not_carry_user_information() -> None:
    result = resolve(f"http://{TOR_PROJECT}.onion@evil.example/login")
    assert result.kind == "external"
    assert "%40" not in result.url
    assert "evil.example" in result.url
    assert TOR_PROJECT not in result.url


def test_leading_backslashes_mean_a_host_just_as_they_do_in_browsers() -> None:
    for reference in ("\\\\evil.example/x", "/\\evil.example/x", "\\/evil.example/x"):
        result = resolve(reference)
        assert result.kind == "external", reference
        assert "evil.example" in result.url


@pytest.mark.parametrize(
    "reference",
    [
        f"http://{TOR_PROJECT}.onion:22/",
        f"http://{TOR_PROJECT}.onion:0/",
        f"http://user@{TOR_PROJECT}.onion/",
        f"//evil.example@{TOR_PROJECT}.onion/",
        "http://abcdefghijklmnop.onion/",
        f"http://{TOR_PROJECT[:-1]}x.onion/",
        "http://x.onion/",
        "http://onion/",
    ],
)
def test_malformed_or_unsupported_onion_urls_are_dropped_not_sent_anywhere(reference: str) -> None:
    result = resolve(reference)
    assert result.kind == "dropped"
    assert result.url == ""


def test_references_that_browsers_and_python_read_differently_still_stay_on_the_gateway() -> None:
    # A browser reads "http:///evil.example/x" as a link to evil.example. Python reads it as a
    # path on the current site. The gateway never leaves a relative URL for the browser to
    # interpret, so either way the written URL is on the gateway or the reference is dropped.
    for reference in (
        "http:///evil.example/x",
        "https:evil.example",
        "http:",
        "http://",
        "http:\\evil.example",
    ):
        result = resolve(reference)
        assert result.kind in ("dropped", "onion", "external")
        if result.kind != "dropped":
            assert MAPPER.owns(result.url)


def test_spaces_and_non_ascii_text_are_percent_encoded() -> None:
    result = resolve("/a b/" + chr(0xE9) + "?q=" + chr(0xE9) + " x")
    assert result.kind == "onion"
    assert " " not in result.url
    assert result.url.isascii()
    assert "%C3%A9" in result.url


def test_control_characters_inside_a_reference_are_rejected() -> None:
    assert resolve("/a\x00b").kind == "dropped"
    assert resolve("/a\x7fb").kind == "dropped"
    assert resolve("/a\tb").url == ORIGIN_PREFIX + "/ab"


def test_very_long_external_links_are_dropped() -> None:
    assert resolve("http://example.org/" + "a" * 3000).kind == "dropped"


def test_every_onion_result_parses_back_to_a_gateway_url() -> None:
    result = resolve("/x?y=z#frag")
    assert result.url == ORIGIN_PREFIX + "/x?y=z#frag"
    assert MAPPER.owns(result.url.split("#")[0])


@given(st.text(max_size=200))
def test_no_reference_ever_produces_an_unowned_url(reference: str) -> None:
    result = resolve(reference)
    if result.kind in ("onion", "external"):
        assert MAPPER.owns(result.url)
    elif result.kind == "local":
        assert result.url == "" or result.url.startswith("#")
    else:
        assert result.url == ""


@given(st.text(alphabet="abc:/.@\\?#%&=- \t\n" + chr(0xE9), max_size=60))
def test_urlish_garbage_never_escapes_and_onion_results_are_valid(reference: str) -> None:
    result = resolve(reference)
    if result.kind in ("onion", "external"):
        assert MAPPER.owns(result.url)
