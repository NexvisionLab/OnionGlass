# SPDX-License-Identifier: AGPL-3.0-only
"""CSS rewriting: no scripting hooks, no third-party contact, no image requests unless allowed."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from helpers import FORBIDDEN_CSS, FakeMapper, _css_urls, base_url
from onionglass.rewrite.css import (
    CssOptions,
    CssTooLargeError,
    sanitize_declarations,
    sanitize_stylesheet,
)

MAPPER = FakeMapper()
BASE = base_url()
PREFIX = MAPPER.onion(BASE.origin)
NO_IMAGES = CssOptions(allow_images=False)
IMAGES = CssOptions(allow_images=True)


def clean(css: str, options: CssOptions = NO_IMAGES) -> str:
    return sanitize_stylesheet(css, BASE, MAPPER, options)


def test_plain_css_passes_through() -> None:
    out = clean("body { color: red; margin: 0 auto } a:hover { text-decoration: underline }")
    assert "color:red" in out.replace(" ", "")
    assert "a:hover" in out


def test_images_are_dropped_unless_allowed() -> None:
    css = "a { color: red; background: url(/bg.png) } b { list-style-image: url('/dot.png') }"
    withheld = clean(css)
    assert "url(" not in withheld
    assert "color:red" in withheld.replace(" ", "")
    allowed = clean(css, IMAGES)
    assert f'url("{PREFIX}/bg.png")' in allowed
    assert f'url("{PREFIX}/dot.png")' in allowed


def test_images_on_other_hosts_are_dropped_even_when_images_are_allowed() -> None:
    out = clean("a { background: url(http://evil.example/x.png); color: red }", IMAGES)
    assert "evil" not in out
    assert "color:red" in out.replace(" ", "")


def test_local_fragment_references_are_kept() -> None:
    out = clean("a { filter: url(#blur) }")
    assert 'url("#blur")' in out


def test_fonts_are_allowed_because_a_font_is_not_an_image() -> None:
    out = clean("@font-face { font-family: F; src: url(/f.woff2) format('woff2'), local(F) }")
    assert f'url("{PREFIX}/f.woff2")' in out
    assert "local(F)" in out


def test_a_background_image_in_font_face_is_not_treated_as_a_font() -> None:
    out = clean("@font-face { font-family: F; background: url(/x.png) }")
    assert "url(" not in out


def test_imports_are_mapped_and_external_imports_are_dropped() -> None:
    out = clean(
        '@import "/a.css"; @import url(/b.css) screen; @import "http://evil.example/c.css";'
    )
    assert f'@import url("{PREFIX}/a.css");' in out
    assert f'@import url("{PREFIX}/b.css") screen;' in out
    assert "evil" not in out


def test_import_conditions_cannot_smuggle_urls() -> None:
    out = clean('@import "/a.css" supports(background: url(http://evil.example/x));')
    assert "evil" not in out


@pytest.mark.parametrize(
    "declaration",
    [
        "width: expression(alert(1))",
        "behavior: url(x.htc)",
        "-moz-binding: url(x.xml#y)",
        "background: image(url(/x.png))",
        "background: cross-fade(url(/x.png), url(/y.png), 50%)",
        "background: element(#id)",
        "background: paint(houdini)",
        "color: red; background: -moz-image-rect(url(/x.png), 0, 0, 1, 1)",
    ],
)
def test_scripting_hooks_and_exotic_image_functions_are_dropped(declaration: str) -> None:
    out = clean("a { " + declaration + " }", IMAGES).lower()
    for forbidden in (
        "expression",
        "behavior",
        "binding",
        "cross-fade",
        "element(",
        "paint(",
        "image(",
    ):
        assert forbidden not in out


def test_escaped_function_names_are_still_recognised() -> None:
    # \75 is "u", so this is url(). Parsers decode the escape, and so does the sanitiser.
    out = clean("a { background: \\75rl(http://evil.example/x) }", IMAGES)
    assert "evil" not in out
    out = clean("a { width: \\65xpression(alert(1)) }", IMAGES)
    assert "xpression" not in out.lower()


def test_urls_with_unusual_quoting_are_handled() -> None:
    for text in (
        'url( "http://evil.example/x" )',
        "url( 'http://evil.example/x' )",
        "url(http://evil.example/x)",
        'URL("http://evil.example/x")',
        "url(data:image/png;base64,AAAA)",
        'url("javascript:alert(1)")',
        "url()",
        "url(/a.png /b.png)",
    ):
        out = clean("a { background: " + text + " }", IMAGES)
        assert "evil" not in out
        assert "javascript" not in out.lower()
        assert "data:" not in out
        assert "/b.png" not in out


def test_custom_properties_cannot_carry_urls_to_use_later() -> None:
    out = clean(":root { --bg: url(http://evil.example/x) } a { background: var(--bg) }", IMAGES)
    assert "evil" not in out


def test_nested_at_rules_are_processed_recursively() -> None:
    out = clean(
        "@media screen { @supports (display: grid) { a { background: url(/x.png); color: red } } }"
    )
    assert "url(" not in out
    assert "color:red" in out.replace(" ", "")
    out = clean("@media screen { a { background: url(/x.png) } }", IMAGES)
    assert f'url("{PREFIX}/x.png")' in out


def test_unknown_and_dangerous_at_rules_are_dropped() -> None:
    out = clean(
        '@charset "utf-7"; @namespace url(http://evil.example/ns); @-moz-document url-prefix() { a { color: red } }'
        " @viewport { width: 1px } a { color: blue }"
    )
    assert "charset" not in out
    assert "evil" not in out
    assert "document" not in out
    assert "color:blue" in out.replace(" ", "")


def test_keyframes_and_page_rules_survive_but_are_cleaned() -> None:
    out = clean("@keyframes spin { from { transform: rotate(0) } to { background: url(/x.png) } }")
    assert "@keyframes spin" in out
    assert "url(" not in out
    assert "@page" in clean("@page { margin: 1cm }")


def test_nothing_in_the_output_can_end_a_style_element() -> None:
    out = clean('p::after { content: "</style><script>alert(1)</script>"; color: red }')
    assert "<" not in out
    assert "color:red" in out.replace(" ", "")
    attribute = sanitize_declarations('content: "</style>"', BASE, MAPPER, NO_IMAGES)
    assert "<" not in attribute


def test_parse_errors_do_not_stop_later_rules() -> None:
    out = clean("a { color: red } } } b { color: blue } {{{ c { color: green }")
    assert "color:red" in out.replace(" ", "")


def test_deep_nesting_does_not_crash() -> None:
    css = "@media screen{" * 200 + "a{color:red}" + "}" * 200
    assert isinstance(clean(css), str)
    assert isinstance(clean("a{" * 500 + "color:red" + "}" * 500), str)


def test_the_size_limit_is_enforced() -> None:
    with pytest.raises(CssTooLargeError):
        clean("a{color:red}" * 10, CssOptions(max_bytes=20))


def test_style_attributes_are_cleaned() -> None:
    cleaned = sanitize_declarations("color: red; background: url(/x.png)", BASE, MAPPER, NO_IMAGES)
    assert cleaned == "color: red"
    out = sanitize_declarations("background: url(/x.png)", BASE, MAPPER, IMAGES)
    assert f'url("{PREFIX}/x.png")' in out
    assert sanitize_declarations("x" * 30000, BASE, MAPPER, NO_IMAGES) == ""
    assert sanitize_declarations("behavior: url(x)", BASE, MAPPER, IMAGES) == ""


@given(
    st.text(
        alphabet="abcxyz:;{}()[]@#.,-_ '\"/\\<>!url\n0123456789%=*+",
        max_size=300,
    )
)
def test_arbitrary_css_never_yields_forbidden_content(css: str) -> None:
    for options in (NO_IMAGES, IMAGES):
        out = clean(css, options)
        lowered = out.lower()
        for forbidden in FORBIDDEN_CSS:
            assert forbidden not in lowered
        assert "<" not in out
        for url in _css_urls(out):
            assert url.startswith("#") or MAPPER.owns(url)
        if options is NO_IMAGES:
            # With images withheld the only URLs left are local references, fonts and imports.
            for url in _css_urls(out):
                assert url.startswith("#") or "font-face" in out or "@import" in out
