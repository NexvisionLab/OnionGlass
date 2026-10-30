# SPDX-License-Identifier: AGPL-3.0-only
"""HTML rewriting: properties P1 (no script), P2 (no third-party contact), P6 (images withheld)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from helpers import DUCKDUCKGO, TOR_PROJECT, FakeMapper, assert_safe_output, base_url
from onionglass.rewrite.html import (
    HtmlOptions,
    RewriteError,
    RewriteResult,
    decode_document,
    rewrite_html,
)

MAPPER = FakeMapper()
BASE = base_url()
PREFIX = MAPPER.onion(BASE.origin)


def rewrite(page: str | bytes, charset: str | None = None, **options: Any) -> RewriteResult:
    data = page.encode("utf-8") if isinstance(page, str) else page
    return rewrite_html(
        data, BASE, MAPPER, options=HtmlOptions(**options) if options else None, charset=charset
    )


def text(result: RewriteResult) -> str:
    return result.body.decode("utf-8")


HOSTILE_PAGES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<body onload=alert(1)>text",
    '<a href="javascript:alert(1)">x</a>',
    '<a href="&#106;avascript:alert(1)">x</a>',
    '<a href="jav&#x09;ascript:alert(1)">x</a>',
    '<a href="  javascript:alert(1)">x</a>',
    '<a href="JaVaScRiPt:alert(1)">x</a>',
    "<a href=javascript:alert(1)>x</a>",
    '<a/href="javascript:alert(1)">x</a>',
    '<a href = "javascript:alert(1)">x</a>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<object data="javascript:alert(1)"></object>',
    '<embed src="javascript:alert(1)">',
    '<form action="javascript:alert(1)"><input type=submit></form>',
    "<input type=image src=x onerror=alert(1)>",
    '<button formaction="javascript:alert(1)">x</button>',
    '<math><mtext><style><a id="</style><img src=x onerror=alert(1)>"></style></mtext></math>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>"></p></noscript>',
    '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
    "<style>@import 'http://evil.example/x.css';</style>",
    "<style>a{background:url(http://evil.example/x)}</style>",
    "<link rel=stylesheet href=http://evil.example/x.css>",
    '<link rel="stylesheet" href="javascript:alert(1)">',
    '<base href="http://evil.example/"><a href="x">x</a>',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<meta http-equiv=refresh content="0;url=http://evil.example/">',
    '<table background="http://evil.example/x"><tr><td background="http://evil.example/y">x</td></tr></table>',
    '<body background="http://evil.example/x">x',
    '<video poster="http://evil.example/x"><source src="http://evil.example/v.mp4"></video>',
    '<audio src="http://evil.example/a.mp3"></audio>',
    '<img src="http://evil.example/x" srcset="http://evil.example/y 2x">',
    '<picture><source srcset="http://evil.example/x"><img src="http://evil.example/y"></picture>',
    '<a href="http://evil.example/" ping="http://evil.example/ping">x</a>',
    "<xmp><script>alert(1)</script></xmp>",
    "<plaintext><script>alert(1)</script>",
    "<template><script>alert(1)</script></template>",
    "<!--[if IE]><script>alert(1)</script><![endif]-->",
    "<![CDATA[<script>alert(1)</script>]]>",
    '<div style="background:url(http://evil.example/x)">x</div>',
    '<div style="width:expression(alert(1))">x</div>',
    "<p style=\"background-image:image-set('http://evil.example/x' 1x)\">x</p>",
    "<img src=x onerror=alert(1)//",
    '<a href="http://evil.example/" target="_blank" download>x</a>',
    '<input type="file" name="f">',
    '<link rel="preload" href="http://evil.example/x" as="image">',
    '<link rel="icon" href="http://evil.example/favicon.ico">',
    '<isindex action="javascript:alert(1)">',
    "<marquee onstart=alert(1)>x</marquee>",
    "<details open ontoggle=alert(1)>x</details>",
    "<div id=x tabindex=1 onfocus=alert(1) autofocus>x</div>",
    '<svg><use href="http://evil.example/x.svg#a"/></svg>',
    '<a href="//evil.example/x">x</a>',
    '<a href="\\\\evil.example\\x">x</a>',
    '<img src="x" alt=\'" onerror="alert(1)\'>',
    '<form action="http://evil.example/"><form action="/ok"><input name=a></form></form>',
    "<textarea></textarea><script>alert(1)</script>",
    "<title><script>alert(1)</script></title>",
    "<select><option><script>alert(1)</script></option></select>",
    "<img/src=x/onerror=alert(1)>",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    '<a href="java\x00script:alert(1)">x</a>',
    "<iframe><script>alert(1)</script></iframe>",
    "<noframes><script>alert(1)</script></noframes>",
    '<div style="background:url(&quot;http://evil.example/x&quot;)">x</div>',
    '<a href="data:text/html,<script>alert(1)</script>">x</a>',
    '<img src="data:image/svg+xml,<svg onload=alert(1)>">',
    "<style>@media screen{a{background:url(http://evil.example/x)}}</style>",
    '<style>a{content:"</style><script>alert(1)</script>"}</style>',
    '<form action="/x"><input type=password name=p><input type=submit formaction="http://evil.example/"></form>',
    '<svg><a xlink:href="javascript:alert(1)"><text>x</text></a></svg>',
    "<?php echo 1; ?><script>alert(1)</script>",
    "<!DOCTYPE html [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><p>&x;</p>",
]


@pytest.mark.parametrize("page", HOSTILE_PAGES)
@pytest.mark.parametrize("allow_images", [False, True])
def test_hostile_pages_come_out_safe(page: str, allow_images: bool) -> None:
    result = rewrite(page, allow_images=allow_images)
    assert_safe_output(result.body, MAPPER, allow_images=allow_images)
    lowered = text(result).lower()
    assert "<script" not in lowered
    assert "javascript:" not in lowered
    assert "evil.example" not in lowered.replace("%2f", "/") or "gw.example/_og/external" in lowered


# --- P1: no script ----------------------------------------------------------------------------


def test_scripts_and_event_handlers_are_removed_and_counted() -> None:
    result = rewrite(
        '<p onclick="x()" onmouseover="y()">hi</p><script>a()</script><script src="/s.js"></script>'
    )
    out = text(result)
    assert "<p>hi</p>" in out
    assert "onclick" not in out and "script" not in out
    assert result.removed_scripts == 2


def test_frames_plugins_and_vector_graphics_are_removed_with_their_content() -> None:
    out = text(
        rewrite(
            "<p>keep</p><iframe>one</iframe><object>two</object><embed><svg>three</svg><canvas>four</canvas>"
            "<video>five</video><audio>six</audio><math>seven</math><template>eight</template>"
        )
    )
    assert "keep" in out
    for word in ("one", "two", "three", "four", "five", "six", "seven", "eight"):
        assert word not in out


def test_noscript_content_is_shown_because_script_never_runs() -> None:
    out = text(rewrite("<noscript><p>fallback text</p></noscript>"))
    assert "<p>fallback text</p>" in out


def test_unknown_elements_are_unwrapped_and_keep_their_text() -> None:
    out = text(
        rewrite("<marquee>moving</marquee><blink>x</blink><custom-thing>kept</custom-thing>")
    )
    assert "moving" in out and "kept" in out
    assert "marquee" not in out and "custom-thing" not in out


def test_comments_are_removed() -> None:
    out = text(rewrite("<p>a</p><!-- secret --><!--[if IE]>x<![endif]-->"))
    assert "secret" not in out and "[if" not in out


def test_attributes_outside_the_allowlist_are_dropped() -> None:
    out = text(
        rewrite(
            '<div data-x="1" contenteditable accesskey=a tabindex=1 draggable=true class=k id=i>x</div>'
        )
    )
    assert 'class="k"' in out and 'id="i"' in out
    for dropped in ("data-x", "contenteditable", "accesskey", "tabindex", "draggable"):
        assert dropped not in out


def test_aria_attributes_are_kept() -> None:
    assert 'aria-label="Menu"' in text(rewrite('<div aria-label="Menu">x</div>'))


def test_anchor_rel_is_fixed_and_the_page_cannot_change_it() -> None:
    out = text(rewrite('<a href="/x" rel="opener" target="_top">x</a>'))
    assert out.count("rel=") == 1
    assert 'rel="noopener noreferrer nofollow"' in out
    assert "target" not in out and "opener" not in out.replace("noopener", "")


# --- P2: nothing outside the gateway ------------------------------------------------------------


def test_links_are_rewritten_by_kind() -> None:
    result = rewrite(
        f'<a href="/p?q=1#f">a</a><a href="http://{DUCKDUCKGO}.onion/">b</a>'
        '<a href="https://example.org/">c</a><a href="mailto:a@b.example">d</a>'
        '<a href="#top">e</a><a href="javascript:x()">f</a>'
    )
    out = text(result)
    assert f'href="{PREFIX}/p?q=1#f"' in out
    assert 'href="#top"' in out
    assert "gw.example/_og/external?u=https%3A%2F%2Fexample.org%2F" in out
    assert "mailto" not in out and "javascript" not in out
    assert result.external_links == 1


def test_base_href_on_the_same_onion_changes_how_links_resolve() -> None:
    out = text(rewrite('<base href="/other/"><a href="x.html">x</a>'))
    assert f'href="{PREFIX}/other/x.html"' in out
    assert "<base" not in out


def test_base_href_cannot_redirect_relative_links_off_the_onion() -> None:
    for base in (
        "http://evil.example/",
        "//evil.example/",
        "javascript:alert(1)",
        "http://x.onion/",
    ):
        out = text(rewrite(f'<base href="{base}"><a href="x.html">x</a>'))
        assert f'href="{PREFIX}/dir/x.html"' in out, base
        assert "evil" not in out


def test_meta_refresh_becomes_a_visible_notice_and_never_redirects() -> None:
    result = rewrite('<meta http-equiv="refresh" content="3; url=/next"><p>body</p>')
    out = text(result)
    assert "<meta http-equiv" not in out
    assert "Automatic redirects are off" in out
    assert f'href="{PREFIX}/next"' in out
    assert result.refresh_url == f"{PREFIX}/next"


def test_meta_refresh_to_another_site_goes_through_the_warning_page() -> None:
    result = rewrite("<meta http-equiv=refresh content='0; URL=\"http://evil.example/x\"'>")
    assert result.refresh_url is not None
    assert result.refresh_url.startswith("https://gw.example/_og/external?u=")


def test_stylesheet_links_are_kept_when_they_point_at_an_onion_and_other_links_are_dropped() -> (
    None
):
    out = text(
        rewrite(
            '<link rel="stylesheet" href="/s.css" media="screen"><link rel="stylesheet" href="http://evil.example/x.css">'
            '<link rel="icon" href="/i.ico"><link rel="alternate stylesheet" href="/alt.css">'
            '<link rel="preload" href="/p" as="image"><link rel="canonical" href="/c">'
        )
    )
    assert f'<link rel="stylesheet" href="{PREFIX}/s.css" media="screen">' in out
    assert out.count("<link") == 1
    assert "evil" not in out


def test_style_elements_are_rebuilt() -> None:
    out = text(
        rewrite(
            "<style>a{color:red;background:url(/x.png)}</style><p style='color:blue;behavior:url(x)'>t</p>"
        )
    )
    assert "color:red" in out.replace(" ", "")
    assert "url(" not in out
    assert 'style="color:blue"' in out


# --- P6: withheld images are never requested ------------------------------------------------------


def test_images_become_placeholders_without_any_image_attribute() -> None:
    result = rewrite(
        '<img src="/a.png" alt="A cat" srcset="/b.png 2x"><picture><source srcset="/c.webp"><img src="/d.png"></picture>'
    )
    out = text(result)
    assert result.withheld_images == 2
    assert "<img" not in out and "<source" not in out and "<picture" not in out
    assert "src=" not in out and "srcset" not in out
    assert "[image withheld: A cat]" in out
    assert "[image withheld]" in out


def test_image_alt_text_is_escaped_and_cannot_break_out() -> None:
    out = text(
        rewrite('<img src=x alt="&lt;script&gt;alert(1)&lt;/script&gt;&quot; onerror=&quot;x">')
    )
    assert "<script" not in out
    assert "&lt;script&gt;" in out  # shown as text, not parsed as markup
    assert_safe_output(out.encode(), MAPPER)


def test_image_alt_text_is_shortened() -> None:
    out = text(rewrite('<img src=x alt="' + "a" * 500 + '">'))
    assert "a" * 101 not in out


def test_images_are_kept_and_mapped_when_the_profile_allows_them() -> None:
    result = rewrite(
        '<img src="/a.png" alt="A" width=10 height=20 srcset="/b.png 2x, /c.png 1.5x, http://evil.example/d.png 3x, /e.png javascript">'
        '<img src="http://evil.example/x.png"><img src="data:image/png;base64,AAAA">',
        allow_images=True,
    )
    out = text(result)
    assert f'src="{PREFIX}/a.png"' in out
    assert f'srcset="{PREFIX}/b.png 2x, {PREFIX}/c.png 1.5x, {PREFIX}/e.png"' in out
    assert 'width="10"' in out and 'height="20"' in out
    assert "evil" not in out and "data:" not in out
    assert result.withheld_images == 0


def test_input_type_image_becomes_a_plain_submit_button() -> None:
    out = text(rewrite('<form><input type=image src="/x.png" name=go></form>'))
    assert 'type="submit"' in out
    assert "src=" not in out


def test_css_images_are_withheld_too() -> None:
    out = text(
        rewrite(
            '<style>a{background:url(/x.png)}</style><div style="background:url(/y.png)">t</div>'
        )
    )
    assert "url(" not in out


def test_the_picture_element_is_unwrapped_when_images_are_allowed() -> None:
    out = text(
        rewrite(
            '<picture><source srcset="/c.webp 1x"><img src="/d.png"></picture>', allow_images=True
        )
    )
    assert f'src="{PREFIX}/d.png"' in out
    assert "<picture" not in out
    assert "<source" not in out


# --- forms -------------------------------------------------------------------------------------


def test_forms_to_the_same_onion_are_kept() -> None:
    out = text(
        rewrite('<form action="/search" method="GET"><input name=q><button>Go</button></form>')
    )
    assert f'action="{PREFIX}/search"' in out
    assert 'method="get"' in out
    assert '<button type="submit">Go</button>' in out


def test_a_form_without_an_action_is_kept_and_submits_to_the_current_page() -> None:
    out = text(rewrite("<form method=post><input name=q></form>"))
    assert "<form " in out and "action=" not in out


def test_forms_to_other_sites_are_dropped_but_their_text_stays() -> None:
    result = rewrite(
        '<form action="http://evil.example/x"><label>Name</label><input name=n></form>'
    )
    out = text(result)
    assert "<form" not in out
    assert "Name" in out
    assert result.blocked_forms == 1


def test_post_forms_can_be_switched_off_for_a_profile() -> None:
    result = rewrite(
        '<form method="post" action="/x"><input name=a></form><form action="/y"><input name=b></form>',
        allow_post_forms=False,
    )
    out = text(result)
    assert out.count("<form") == 1
    assert result.blocked_forms == 1


def test_the_method_is_always_get_or_post() -> None:
    for method in ("PUT", "dialog", "delete", "", "post "):
        out = text(rewrite(f'<form method="{method}" action="/x"></form>'))
        assert 'method="get"' in out or 'method="post"' in out


def test_password_fields_are_flagged_and_can_be_blocked() -> None:
    page = '<form action="/login" method=post><input name=u><input type=PASSWORD name=p></form>'
    allowed = rewrite(page)
    assert allowed.has_password_field
    assert 'type="password"' in text(allowed)
    blocked = rewrite(page, allow_password_fields=False)
    assert blocked.has_password_field
    assert "password" not in text(blocked)


def test_file_inputs_are_removed_unless_uploads_are_allowed() -> None:
    page = '<form action="/up" method=post enctype="multipart/form-data"><input type=file name=f></form>'
    assert 'type="file"' not in text(rewrite(page))
    assert 'type="file"' in text(rewrite(page, allow_uploads=True))


def test_form_controls_ask_the_browser_not_to_remember_anything() -> None:
    out = text(
        rewrite(
            '<form action="/x"><input name=a><input type=password name=b autocomplete=on></form>'
        )
    )
    assert out.count('autocomplete="off"') == 3
    assert 'autocomplete="on"' not in out


def test_unknown_input_types_become_text() -> None:
    out = text(rewrite('<form><input type="weird"><input type="IMAGE"><input></form>'))
    assert 'type="weird"' not in out
    assert out.count('type="text"') >= 2


def test_formaction_is_mapped_or_removed() -> None:
    out = text(
        rewrite(
            '<form action="/x"><button formaction="/other">a</button><button formaction="http://evil.example/">b</button></form>'
        )
    )
    assert f'formaction="{PREFIX}/other"' in out
    assert "evil" not in out
    assert "_og/external" not in out  # form data must never go to the warning page


# --- document level ------------------------------------------------------------------------------


def test_title_language_and_skeleton() -> None:
    result = rewrite(
        '<html lang="fr-CA"><head><title> Bonjour &amp; salut </title></head><body><p>x</p></body></html>'
    )
    out = text(result)
    assert result.title == "Bonjour & salut"
    assert out.startswith('<!DOCTYPE html><html lang="fr-CA">')
    assert "<title>Bonjour &amp; salut</title>" in out
    assert '<meta name="referrer" content="same-origin">' in out
    assert '<meta charset="utf-8">' in out


def test_a_bad_language_attribute_is_ignored() -> None:
    assert "lang=" not in text(rewrite('<html lang="x&quot;><script>"><p>x</p></html>'))


def test_text_survives_with_entities_intact() -> None:
    out = text(rewrite("<p>5 &lt; 6 &amp; 7 &gt; 3 &copy; caf&eacute;</p>"))
    assert "5 &lt; 6 &amp; 7 &gt; 3" in out
    assert "caf" in out


def test_pre_keeps_its_first_line_break() -> None:
    out = text(rewrite("<pre>\n\nfirst</pre>"))
    assert "<pre>\n" in out


def test_long_attribute_values_are_shortened() -> None:
    out = text(rewrite('<div title="' + "t" * 5000 + '" class="' + "c" * 5000 + '">x</div>'))
    assert "t" * 1001 not in out and "c" * 201 not in out


def test_image_tag_alias_is_treated_as_an_image() -> None:
    result = rewrite('<image src="/x.png">')
    assert result.withheld_images == 1


# --- decoding --------------------------------------------------------------------------------------


def test_declared_charset_is_used() -> None:
    page = (
        "<p>" + chr(0x43F) + chr(0x440) + chr(0x438) + chr(0x432) + chr(0x435) + chr(0x442) + "</p>"
    )
    out = text(rewrite(page.encode("cp1251"), charset="windows-1251"))
    assert chr(0x43F) in out


def test_meta_charset_is_used_when_nothing_is_declared() -> None:
    page = b'<meta charset="iso-8859-1"><p>caf\xe9</p>'
    assert "caf" + chr(0xE9) in text(rewrite(page))


def test_byte_order_marks_win() -> None:
    assert "x" in text(rewrite(b"\xef\xbb\xbf<p>x</p>"))
    assert "x" in text(rewrite("<p>x</p>".encode("utf-16")))


def test_unknown_and_non_text_charsets_fall_back_to_utf8() -> None:
    assert decode_document(b"abc", "no-such-charset") == "abc"
    assert decode_document(b"abc", "rot13") == "abc"
    assert decode_document(b"a\xffb", None) == "a" + chr(0xFFFD) + "b"


# --- limits and robustness ------------------------------------------------------------------------


def test_oversized_pages_are_refused() -> None:
    with pytest.raises(RewriteError):
        rewrite("<p>x</p>" * 100, max_bytes=50)


def test_too_many_elements_are_refused() -> None:
    with pytest.raises(RewriteError):
        rewrite("<p>x</p>" * 100, max_nodes=50)


def test_a_page_cannot_grow_a_lot_when_rewritten() -> None:
    # Each image tag becomes a longer placeholder, so output size has its own limit.
    with pytest.raises(RewriteError):
        rewrite("<img src=x>" * 2000, max_output_bytes=20_000)
    assert rewrite("<img src=x>" * 10, max_output_bytes=20_000).withheld_images == 10


def test_extremely_deep_nesting_does_not_crash() -> None:
    result = rewrite("<div>" * 10000 + "deep" + "</div>" * 10000)
    assert_safe_output(result.body, MAPPER)
    assert rewrite("<b>" * 5000).body


def test_awkward_input_does_not_crash() -> None:
    for page in (
        b"",
        b"\x00" * 100,
        b"<" * 1000,
        b"<a " * 1000,
        b"&" * 1000,
        b"\xff\xfe" * 100,
        b"<p" + b"x" * 100000,
    ):
        result = rewrite(page)
        assert_safe_output(result.body, MAPPER)


# --- fuzzing -----------------------------------------------------------------------------------------

FRAGMENTS = [
    "<script>",
    "</script>",
    "<img src=",
    "<a href=",
    '"',
    "'",
    "javascript:",
    "http://evil.example/",
    "/relative",
    "onerror=",
    "onclick=alert(1)",
    "<style>",
    "</style>",
    "url(",
    ")",
    "<svg>",
    "</svg>",
    "<iframe>",
    "<form action=",
    "<input type=password>",
    "<base href=",
    "<meta http-equiv=refresh content=",
    "<link rel=stylesheet href=",
    ">",
    "<",
    "/",
    "=",
    "&lt;",
    "&#106;",
    "<!--",
    "-->",
    "<noscript>",
    "</noscript>",
    "<math>",
    "<mtext>",
    "<template>",
    "<textarea>",
    "</textarea>",
    "<select>",
    "<table>",
    "<td background=",
    " srcset=",
    " style=",
    "expression(",
    "@import ",
    "<p>",
    "text ",
    "\n",
    "\t",
    "\x00",
]


@given(st.lists(st.sampled_from(FRAGMENTS), max_size=40).map("".join))
def test_random_markup_never_produces_unsafe_output(page: str) -> None:
    for allow_images in (False, True):
        result = rewrite(page, allow_images=allow_images)
        assert_safe_output(result.body, MAPPER, allow_images=allow_images)


@given(st.text(max_size=300))
def test_arbitrary_text_never_produces_unsafe_output(page: str) -> None:
    result = rewrite(page)
    assert_safe_output(result.body, MAPPER)


def test_same_onion_helper_constants_are_valid() -> None:
    assert TOR_PROJECT in BASE.url
