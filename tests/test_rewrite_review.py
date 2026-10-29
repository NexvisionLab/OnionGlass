# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for problems found by an independent security review of the rewriter.

Each test is the review's own reproduction. The first group is a break of P2 and P6 that was
confirmed in a real browser: an unquoted url() inside image-set() was not rewritten.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from helpers import FakeMapper, assert_safe_output, base_url
from onionglass.rewrite import html as html_module
from onionglass.rewrite.css import (
    CssOptions,
    sanitize_declarations,
    sanitize_stylesheet,
    verify_declarations,
    verify_stylesheet,
)
from onionglass.rewrite.html import (
    HtmlOptions,
    RewriteError,
    decode_document,
    rewrite_html,
)
from onionglass.rewrite.urls import resolve_reference

MAPPER = FakeMapper()
BASE = base_url()
NO_IMAGES = CssOptions(allow_images=False)
IMAGES = CssOptions(allow_images=True)


def css(text: str, options: CssOptions = NO_IMAGES) -> str:
    return sanitize_stylesheet(text, BASE, MAPPER, options)


def page(markup: str, **options: Any) -> bytes:
    opts = HtmlOptions(**options) if options else None
    return rewrite_html(markup.encode("utf-8"), BASE, MAPPER, options=opts).body


# --- the image-set() break -----------------------------------------------------------------------

IMAGE_SET_VARIANTS = [
    "image-set(url(http://evil.example/a.png) 1x)",
    "-webkit-image-set(url(http://evil.example/a.png) 1x)",
    "image-set(image-set(url(http://evil.example/a.png) 1x) 1x)",
    "image-set(url( http://evil.example/a.png ) 1x, url(http://evil.example/b.png) 2x)",
    'image-set("http://evil.example/a.png" 1x)',
    "image-set('http://evil.example/a.png' 1x, url(http://evil.example/b.png) 2x)",
    "image-set((url(http://evil.example/a.png)) 1x)",
    "image-set([url(http://evil.example/a.png)] 1x)",
    'image-set("http://evil.example/a.png" type("image/png"))',
    "image-set(foo(url(http://evil.example/a.png)) 1x)",
]


@pytest.mark.parametrize("value", IMAGE_SET_VARIANTS)
@pytest.mark.parametrize("options", [NO_IMAGES, IMAGES])
def test_no_form_of_image_set_can_reach_another_host(value: str, options: CssOptions) -> None:
    out = css("a{background:" + value + "}", options)
    assert "evil" not in out
    attribute = sanitize_declarations("background:" + value, BASE, MAPPER, options)
    assert "evil" not in attribute


@pytest.mark.parametrize("value", IMAGE_SET_VARIANTS)
def test_image_set_in_a_page_comes_out_safe_in_every_position(value: str) -> None:
    markup = (
        f'<div style="background-image:{value}">x</div>'
        f"<style>.d{{background:{value}}} @media print{{p{{background:{value}}}}}</style>"
    )
    for allow in (False, True):
        out = page(markup, allow_images=allow)
        assert b"evil" not in out
        assert_safe_output(out, MAPPER, allow_images=allow)


def test_a_variable_cannot_stand_in_for_an_image_address() -> None:
    out = css(':root{--u:"http://evil.example/x"} a{background:image-set(var(--u) 1x)}', IMAGES)
    assert "image-set" not in out  # the use is dropped
    assert "var(" not in out
    # The string in the custom property is inert text once nothing can use it as an address.
    assert verify_stylesheet(out, MAPPER)


def test_attr_cannot_turn_page_text_into_an_address() -> None:
    for value in ("attr(title url)", "attr(title type(<url>))", "attr(data-x url, none)"):
        out = css("a{background-image:" + value + "}", IMAGES)
        assert "attr(" not in out
    assert "attr(title)" in css("a::before{content:attr(title)}")


def test_preludes_are_checked_as_well_as_bodies() -> None:
    out = css(
        "@counter-style url(http://evil.example/x) { symbols: a } a, b[href=x] { color: red }"
    )
    assert "evil" not in out
    assert "color:red" in out.replace(" ", "")


# --- verification is independent of rewriting --------------------------------------------------------


@pytest.mark.parametrize("value", IMAGE_SET_VARIANTS)
def test_verification_rejects_what_the_rewriter_must_never_emit(value: str) -> None:
    assert not verify_stylesheet("a{background:" + value + "}", MAPPER)
    assert not verify_declarations("background:" + value, MAPPER)


@pytest.mark.parametrize(
    "bad",
    [
        "a{background:url(http://evil.example/x)}",
        "a{background:url(/relative.png)}",
        '@import "http://evil.example/x.css";',
        '@import url("http://evil.example/x.css");',
        "@import url(x.css);",
        "a{width:expression(alert(1))}",
        "a{behavior:url(x)}",
        "a{background:image(url(x))}",
        "@namespace url(http://evil.example/);",
        "@unknown thing{a{color:red}}",
        "a{background:attr(title url)}",
        "@media screen{a{background:url(http://evil.example/x)}}",
        "a{--x:url(http://evil.example/x)}",
    ],
)
def test_verification_rejects_stylesheets_that_could_contact_other_hosts(bad: str) -> None:
    assert not verify_stylesheet(bad, MAPPER)


def test_verification_accepts_gateway_urls_fragments_and_plain_css() -> None:
    owned = MAPPER.onion(BASE.origin)
    assert verify_stylesheet(f'a{{background:url("{owned}/x.png")}} b{{color:red}}', MAPPER)
    assert verify_stylesheet(f'@import url("{owned}/more.css");', MAPPER)
    assert verify_stylesheet("a{filter:url(#blur)}", MAPPER)
    assert verify_declarations("color: red; margin: 0", MAPPER)
    assert verify_declarations(f'background: image-set("{owned}/a.png" 1x)', MAPPER)


def test_verification_gives_up_safely_on_extreme_input() -> None:
    assert not verify_stylesheet("@media screen{" * 100 + "a{color:red}" + "}" * 100, MAPPER)
    assert isinstance(verify_stylesheet("a{" + "(" * 5000, MAPPER), bool)


@given(
    st.text(alphabet="abcxyz:;{}()[]@#.,-_ '\"/<>!url\n0123456789%=*+", max_size=300),
    st.sampled_from([NO_IMAGES, IMAGES]),
)
def test_everything_the_rewriter_emits_passes_verification(text: str, options: CssOptions) -> None:
    assert verify_stylesheet(css(text, options), MAPPER)
    assert verify_declarations(sanitize_declarations(text, BASE, MAPPER, options), MAPPER)


# --- images in style attributes are kept when the profile allows them --------------------------------


def test_allowed_images_in_style_attributes_survive_the_final_pass() -> None:
    owned = MAPPER.onion(BASE.origin)
    out = page('<div style="background:url(/a.png);color:red">x</div>', allow_images=True).decode()
    assert f"{owned}/a.png" in out
    assert "color:red" in out
    withheld = page('<div style="background:url(/a.png);color:red">x</div>').decode()
    assert "a.png" not in withheld
    assert "color:red" in withheld


# --- no exception type other than RewriteError escapes ------------------------------------------------


@pytest.mark.parametrize("reference", ["//[", "http://[::1/", "//[x", "http://[", "https://[::1"])
def test_broken_ipv6_references_are_dropped_not_crashes(reference: str) -> None:
    assert resolve_reference(reference, BASE, MAPPER).kind == "dropped"


@pytest.mark.parametrize(
    "markup",
    [
        '<a href="//[">x</a>',
        '<a href="http://[::1/">x</a>',
        '<base href="//["><a href="x">y</a>',
        '<form action="//["><input name=a></form>',
        '<img src="//[" alt=x>',
        '<link rel=stylesheet href="//[">',
        '<meta http-equiv=refresh content="0;url=//[">',
    ],
)
def test_pages_with_broken_references_still_rewrite(markup: str) -> None:
    for allow in (False, True):
        assert_safe_output(page(markup, allow_images=allow), MAPPER, allow_images=allow)


@pytest.mark.parametrize(
    "name",
    [
        "undefined",
        "idna",
        "punycode",
        "unicode_escape",
        "utf-7",
        "a\x00b",
        "rot13",
        "hex",
        "x" * 500,
    ],
)
def test_hostile_charsets_fall_back_to_utf8(name: str) -> None:
    body = ("<p>caf" + chr(0xE9) + "</p>").encode("utf-8")
    assert decode_document(body, name) == body.decode("utf-8")
    meta = f"<meta charset={name}><p>x</p>".encode("latin-1", errors="ignore")
    assert "x" in decode_document(meta)
    result = rewrite_html(meta, BASE, MAPPER)
    assert b"<p>x</p>" in result.body


def test_real_browser_charsets_are_still_honoured() -> None:
    assert decode_document("caf".encode("latin-1") + b"\xe9", "iso-8859-1").endswith(chr(0xE9))
    assert decode_document("x".encode("shift_jis"), "shift_jis") == "x"
    assert decode_document(b"\xe9", "windows-1252") == chr(0xE9)


def test_a_failure_inside_the_parser_becomes_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("parser failure")

    monkeypatch.setattr(html_module, "LexborHTMLParser", explode)
    with pytest.raises(RewriteError):
        rewrite_html(b"<p>x</p>", BASE, MAPPER)


def test_an_oversized_stylesheet_is_left_out_but_the_page_survives() -> None:
    big = "a{color:red}" * 100_000
    out = page(f"<style>{big}</style><p>kept</p>").decode()
    assert "kept" in out
    assert "<style" not in out


# --- hostile markup that makes parsing slow ------------------------------------------------------------

SLOW_SHAPES = [
    "<select>" + "<option>x" * 100_000,
    "<div>" * 100_000,
    "<table>" + "<b>x<div>" * 50_000,
    "<a href=x><div>" * 50_000,
]


@pytest.mark.parametrize("markup", SLOW_SHAPES, ids=["select", "div", "table", "anchor"])
def test_markup_that_would_parse_slowly_is_refused_up_front(markup: str) -> None:
    started = time.monotonic()
    with pytest.raises(RewriteError):
        rewrite_html(markup.encode(), BASE, MAPPER)
    assert time.monotonic() - started < 2.0


def test_a_large_but_ordinary_page_is_still_accepted() -> None:
    rows = "".join(f"<tr><td>{i}</td><td><a href='/p/{i}'>row</a></td></tr>" for i in range(3000))
    result = rewrite_html(f"<table>{rows}</table>".encode(), BASE, MAPPER)
    assert result.body.count(b"<tr>") == 3000
