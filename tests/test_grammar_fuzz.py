# SPDX-License-Identifier: AGPL-3.0-only
"""Attacks on the rewriter from two directions that the earlier reviews did not cover.

* Character sets. A page can declare any character set, and some multi-byte sets let a lead byte
  swallow the quote or bracket after it. The rewriter decodes the page itself and emits UTF-8, so
  what the browser would have made of the original bytes does not matter. These tests prove that
  rather than assume it.
* Generated pages. Pages are built from a grammar of tags, attributes, URLs, style rules and known
  mutation-XSS shapes, then serialised in awkward ways. Every page must either be refused or come
  out safe according to two parsers that are not the one that wrote it.
"""

from __future__ import annotations

import codecs
import encodings.aliases
import os

import pytest
import tinycss2
from hypothesis import given, settings
from hypothesis import strategies as st
from selectolax.lexbor import LexborHTMLParser
from tinycss2 import ast

from helpers import ALLOWED_TAGS, FakeMapper, _css_urls, assert_safe_output, base_url
from onionglass.mapper import PlaceholderMapper
from onionglass.rewrite.css import (
    CssError,
    CssOptions,
    sanitize_declarations,
    sanitize_stylesheet,
    verify_declarations,
    verify_stylesheet,
)
from onionglass.rewrite.html import HtmlOptions, RewriteError, decode_document, rewrite_html
from onionglass.settings import Settings

pytestmark = pytest.mark.timeout(600)  # the long hunts take far more than the usual 30 seconds
MAPPER = FakeMapper()
# Set ONIONGLASS_FUZZ_SCALE=10 for a long hunt. The default keeps the normal test run short.
SCALE = max(1, int(os.environ.get("ONIONGLASS_FUZZ_SCALE", "1")))
BASE = base_url()
EVIL = "http://evil.example/x"

# --- character sets ------------------------------------------------------------------------------

MULTIBYTE = [
    "shift_jis", "cp932", "euc-jp", "euc-kr", "cp949", "gbk", "gb2312", "gb18030", "big5",
    "big5hkscs", "iso2022-jp", "iso2022-kr", "utf-16", "utf-16-le", "utf-16-be", "utf-8",
]  # fmt: skip
NOT_TEXT_OR_NOT_BROWSER = [
    "utf-7", "utf-32", "cp037", "cp500", "hz", "rot13", "base64", "hex", "zlib", "bz2",
    "punycode", "idna", "unicode_escape", "raw_unicode_escape", "undefined", "uu", "quopri",
    "mbcs", "oem", "utf_7", "utf7", "cp1026", "ebcdic-cp-be", "tis-620x",
]  # fmt: skip

PAYLOAD = (
    b'<a href="http://evil.example/a">x</a>'
    b"<img src='http://evil.example/b' onerror=alert(1)>"
    b"<script>alert(1)</script>"
    b'<div style="background:url(http://evil.example/c)">y</div>'
)

# Bytes that are the first half of a two-byte character in one set or another, placed so they
# touch a quote, a bracket, a backslash or a slash.
LEADS = [
    b"\x81",
    b"\x8e",
    b"\x8f",
    b"\xa1",
    b"\xb0",
    b"\xc0",
    b"\xe0",
    b"\xfc",
    b"\x1b$B",
    b"\x1b(J",
]
TRAILS = [b'"', b"'", b">", b"<", b"\\", b"/", b"=", b"(", b")", b"\x00"]


def lead_byte_pages() -> list[bytes]:
    pages = []
    for lead in LEADS:
        for trail in TRAILS:
            pages.append(
                b'<p title="' + lead + trail + b' onmouseover=alert(1) x="">' + PAYLOAD + b"</p>"
            )
            pages.append(b"<a href=" + lead + trail + b"http://evil.example/z>go</a>" + PAYLOAD)
            pages.append(
                b'<div style="background:url(' + lead + trail + b"http://evil.example/q);"
                b'color:red">' + PAYLOAD + b"</div>"
            )
            pages.append(
                b"<style>a{content:'"
                + lead
                + trail
                + b"}b{background:url(http://evil.example/s)}</style>"
                + PAYLOAD
            )
    return pages


def assert_page_safe(data: bytes, charset: str | None) -> None:
    try:
        result = rewrite_html(data, BASE, MAPPER, charset=charset)
    except RewriteError:
        return  # refusing is always acceptable
    assert_safe_output(result.body, MAPPER)
    assert_reparse_safe(result.body.decode("utf-8"))


def assert_reparse_safe(document: str) -> None:
    """A second look with the rewriter's own parser: no tag or attribute that should be gone."""
    tree = LexborHTMLParser(document)
    for node in tree.css("*"):
        tag = node.tag
        assert tag in ALLOWED_TAGS or tag in ("-undef",), f"tag {tag} came back after reparse"
        for name in node.attributes:
            assert not name.startswith("on"), f"{name} on {tag} after reparse"


@pytest.mark.parametrize("charset", MULTIBYTE)
def test_lead_bytes_cannot_swallow_markup_in_any_declared_set(charset: str) -> None:
    for page in lead_byte_pages():
        assert_page_safe(page, charset)


@pytest.mark.parametrize("charset", MULTIBYTE)
def test_lead_bytes_cannot_swallow_markup_when_the_page_declares_the_set_itself(
    charset: str,
) -> None:
    for page in lead_byte_pages()[::3]:
        declared = b'<meta charset="' + charset.encode("ascii") + b'">' + page
        assert_page_safe(declared, None)
        declared = (
            b'<meta http-equiv="content-type" content="text/html; charset='
            + charset.encode("ascii")
            + b'">'
            + page
        )
        assert_page_safe(declared, None)


@pytest.mark.parametrize("name", NOT_TEXT_OR_NOT_BROWSER)
def test_a_page_cannot_pick_a_codec_that_is_not_a_browser_text_encoding(name: str) -> None:
    data = b"+ADw-script+AD4-alert(1)+ADw-/script+AD4- <b>plain</b>"
    plain = data.decode("utf-8", errors="replace")
    assert decode_document(data, name) == plain
    assert decode_document(b'<meta charset="' + name.encode() + b'">' + data, None) == (
        b'<meta charset="' + name.encode() + b'">' + data
    ).decode("utf-8", errors="replace")


def test_every_codec_python_knows_ends_safe() -> None:
    names = sorted(set(encodings.aliases.aliases.values()) | set(encodings.aliases.aliases))
    page = b"".join(lead_byte_pages()[:12]) + PAYLOAD
    for name in names:
        try:
            codecs.lookup(name)
        except LookupError:
            continue
        assert_page_safe(page, name)
        assert_page_safe(b'<meta charset="' + name.encode("ascii") + b'">' + page, None)


@pytest.mark.parametrize("bom", [codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE])
def test_byte_order_marks_do_not_help_a_hostile_page(bom: bytes) -> None:
    for charset in (None, "shift_jis", "utf-7"):
        assert_page_safe(bom + PAYLOAD, charset)
        assert_page_safe(bom + PAYLOAD.decode("ascii").encode("utf-16-le"), charset)


def test_text_that_decodes_to_unpaired_surrogates_does_not_crash_the_encoder() -> None:
    for page in (
        b"&#xD800;&#xDFFF;<p title='&#xD800;'>x</p>",
        b"<p>\xed\xa0\x80</p>",
        "<p>\ud800</p>".encode("utf-16-le", errors="surrogatepass"),
    ):
        for charset in (None, "utf-16"):
            assert_page_safe(page, charset)


@settings(max_examples=200 * SCALE)
@given(
    st.binary(max_size=400),
    st.sampled_from(MULTIBYTE + NOT_TEXT_OR_NOT_BROWSER + [None, "latin-1", "cp1252", "koi8-r"]),
)
def test_random_bytes_in_any_declared_set_end_safely(data: bytes, charset: str | None) -> None:
    assert_page_safe(PAYLOAD + data + PAYLOAD, charset)


def assert_no_tokenizer_errors(css: str) -> None:
    """Finished CSS must tokenise cleanly: no unterminated string or address, no stray bracket.

    Browsers recover from those in ways that differ from one parser to the next, so the rewriter
    drops such declarations instead of passing them on.
    """
    pending = list(tinycss2.parse_component_value_list(css))
    while pending:
        token = pending.pop()
        assert not isinstance(token, ast.ParseError), f"{token.kind} in {css!r}"
        pending.extend(getattr(token, "arguments", []) or getattr(token, "content", []) or [])


@pytest.mark.parametrize(
    "text",
    [
        "a{content:'x\"}b{background:url(http://evil.example/s)}",
        'a{content:"x\\"}',
        "a{background:url(http://evil.example/a}",
        "a{background:url(http://evil.example/a b)}",
        "a{color:red)}",
        "a{margin:(1px}",
    ],
)
def test_declarations_with_tokenizer_errors_are_dropped(text: str) -> None:
    assert_no_tokenizer_errors(sanitize_stylesheet(text, BASE, MAPPER))
    assert_no_tokenizer_errors(sanitize_declarations(text.removeprefix("a{"), BASE, MAPPER))
    assert "evil.example" not in sanitize_stylesheet(text, BASE, MAPPER)


# --- a grammar of pages --------------------------------------------------------------------------

URL_SAMPLES = [
    EVIL, "//evil.example/x", "javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<b>x",
    "vbscript:x", "blob:http://evil.example/x", "about:blank", "ftp://evil.example/x",
    "\\\\evil.example\\x", "http:\\\\evil.example\\x", "/\\evil.example", "http://evil.example\\@x",
    "http://x@evil.example/", "http://[::1]/", "http://127.0.0.1/", "http://localhost/",
    "https://evil.example:8443/a?b=c#d", "mailto:a@b.c", "tel:123", "file:///etc/passwd",
    "x", "../x", "/rel/path", "?q=1", "#frag", "", " ", "http://",
    "http://" + "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid" + ".onion/ok",
    "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/y",
    "http://evil.example.onion/", "http://abc.onion/", "http://" + "a" * 56 + ".onion/",
    "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion.evil.example/",
]  # fmt: skip
INSERTS = [
    "\t", "\n", "\r", "\x00", "\x01", "\x0b", "\x1f", " ", "&Tab;", "&NewLine;", "&#9;",
    "&#x0A;", "&colon;", "&#58;", "&#x3a;", "&sol;", "%09", "%0a",
    chr(0x200B), chr(0xFEFF), chr(0x2028), chr(0x3002), chr(0xFF0E),
]  # fmt: skip


@st.composite
def urls(draw: st.DrawFn) -> str:
    base = draw(st.sampled_from(URL_SAMPLES))
    if draw(st.booleans()):
        return base
    position = draw(st.integers(0, max(len(base), 1)))
    return base[:position] + draw(st.sampled_from(INSERTS)) + base[position:]


CSS_PROPERTIES = [
    "background", "background-image", "list-style", "list-style-image", "content", "cursor",
    "border-image", "border-image-source", "mask", "mask-image", "-webkit-mask-image", "filter",
    "behavior", "-moz-binding", "width", "color", "font-family", "src", "shape-outside",
    "offset-path", "clip-path", "--x", "--url", "animation-name", "display", "position",
    "marker", "marker-start", "fill", "stroke", "background-position", "transition",
    "-webkit-box-reflect", "zoom", "grid-template-areas", "quotes", "counter-reset",
]  # fmt: skip
CSS_FUNCTIONS = [
    "image-set", "-webkit-image-set", "cross-fade", "-webkit-cross-fade", "element", "paint",
    "calc", "var", "env", "attr", "src", "image", "url", "linear-gradient", "expression", "min",
    "format", "local", "type", "light-dark", "if", "fn",
]  # fmt: skip


@st.composite
def css_values(draw: st.DrawFn, depth: int = 0) -> str:  # noqa: PLR0911
    link = draw(urls())
    choice = draw(st.integers(0, 15 if depth < 3 else 9))
    if choice == 0:
        return f"url({link})"
    if choice == 1:
        return f'url("{link}")'
    if choice == 2:
        return f"url('{link}')"
    if choice == 3:
        return f"u\\rl({link})"
    if choice == 4:
        return f"\\75rl({link})"
    if choice == 5:
        return f"u/**/rl({link})"
    if choice == 6:
        return f'"{link}"'
    if choice == 7:
        return "var(--x)"
    if choice == 8:
        return draw(st.sampled_from(["red", "10px", "none", "inherit", "1x", "2x", "#fff", "0"]))
    if choice == 9:
        return "attr(data-x url)"
    function = draw(st.sampled_from(CSS_FUNCTIONS))
    inner = ", ".join(draw(st.lists(css_values(depth + 1), min_size=1, max_size=3)))
    return f"{function}({inner})"


@st.composite
def declarations(draw: st.DrawFn) -> str:
    prop = draw(st.sampled_from(CSS_PROPERTIES))
    value = " ".join(draw(st.lists(css_values(), min_size=1, max_size=3)))
    important = draw(st.sampled_from(["", " !important", "!important"]))
    return f"{prop}:{value}{important}"


@st.composite
def rules(draw: st.DrawFn, depth: int = 0) -> str:  # noqa: PLR0911
    link = draw(urls())
    body = ";".join(draw(st.lists(declarations(), max_size=4)))
    choice = draw(st.integers(0, 12 if depth < 2 else 5))
    selector = draw(st.sampled_from(["a", "*", "a:hover", "#x .y", "a[href^='http']", "::before"]))
    if choice <= 2:
        return f"{selector}{{{body}}}"
    if choice == 3:
        return f"@import url({link});"
    if choice == 4:
        return f'@import "{link}" screen;'
    if choice == 5:
        return f"@font-face{{font-family:f;src:url({link}) format('woff2')}}"
    inner = "".join(draw(st.lists(rules(depth + 1), max_size=3)))
    at = draw(
        st.sampled_from(
            ["@media screen", "@supports (display:grid)", "@layer a", "@container (min-width:1px)",
             "@keyframes k", "@page", "@namespace", "@charset", "@property --x", "@scope (a)",
             "@starting-style", "@document url-prefix()"]
        )
    )  # fmt: skip
    if choice == 6:
        return f"@namespace url({link});"
    if choice == 7:
        return f'@charset "{link}";'
    return f"{at}{{{inner}}}"


@st.composite
def stylesheets(draw: st.DrawFn) -> str:
    text = "\n".join(draw(st.lists(rules(), max_size=5)))
    cut = draw(st.sampled_from([None, None, None, 0.3, 0.6, 0.9]))
    return text if cut is None else text[: int(len(text) * cut)]


MUTATION_SHAPES = [
    "</style><script>alert(1)</script>", "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>", "</script><script>alert(1)</script>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<svg><style><img src=x onerror=alert(1)></style></svg>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=1 onerror=alert(1)&gt;\">",
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
    "<svg></p><style><a id=\"</style><img src=1 onerror=alert(1)>\">",
    "<math><annotation-xml encoding=\"text/html\"><style><img src=x onerror=alert(1)></style>",
    "<select><template><style></select><img src=x onerror=alert(1)></style></template></select>",
    "<table><td><style></table><img src=x onerror=alert(1)>", "<!--[if IE]><script>alert(1)</script><![endif]-->",
    "<![CDATA[<script>alert(1)</script>]]>", "<!--><script>alert(1)</script>-->", "--!><img src=x onerror=1>",
    "<a href=\"x\" <script>alert(1)</script>>", "<plaintext><img src=x onerror=1>", "<xmp><img src=x onerror=1></xmp>",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>", "<object data=\"http://evil.example/x\"></object>",
    "<embed src=\"http://evil.example/x\">", "<base href=\"http://evil.example/\"><a href=x>x</a>",
    "<meta http-equiv=\"refresh\" content=\"0;url=http://evil.example/\">",
    "<link rel=stylesheet href=\"http://evil.example/s.css\">", "<link rel=preload href=\"http://evil.example/\" as=image>",
    "<img src=\"http://evil.example/\" srcset=\"http://evil.example/a 1x, //evil.example/b 2x\">",
    "<picture><source srcset=\"http://evil.example/a\"><img src=x></picture>",
    "<video poster=\"http://evil.example/p\"><source src=\"http://evil.example/v\"></video>",
    "<input type=image src=\"http://evil.example/i\">", "<button formaction=\"http://evil.example/\">x</button>",
    "<form action=\"http://evil.example/\" method=post><input name=a></form>",
    "<table background=\"http://evil.example/t\"><tr><td background=\"http://evil.example/u\">x</td></tr></table>",
    "<body background=\"http://evil.example/b\" onload=alert(1)>", "<div is=\"x\" slot=y popover>z</div>",
    "<a ping=\"http://evil.example/\" href=x>x</a>", "<a href=x download=\"y\" target=_blank rel=opener>x</a>",
    "<details open ontoggle=alert(1)>d</details>", "<svg onload=alert(1)>", "<math href=\"javascript:alert(1)\">x</math>",
]  # fmt: skip

TAGS = [
    "a", "div", "p", "span", "img", "form", "input", "button", "table", "tr", "td", "style", "title",
    "textarea", "select", "option", "details", "summary", "ul", "li", "b", "i", "pre", "code", "h1",
    "svg", "math", "template", "noscript", "iframe", "object", "embed", "video", "audio", "source",
    "picture", "link", "meta", "base", "script", "body", "html", "head", "frameset", "marquee",
    "plaintext", "xmp", "dialog", "label", "fieldset", "optgroup", "area", "map", "font", "center",
]  # fmt: skip
ATTRIBUTES = [
    "href", "src", "srcset", "action", "formaction", "style", "background", "poster", "data", "cite",
    "ping", "xlink:href", "onclick", "onerror", "onload", "content", "http-equiv", "rel", "type",
    "id", "class", "name", "value", "srcdoc", "is", "slot", "target", "download", "lang", "dir",
    "title", "alt", "usemap", "longdesc", "manifest", "codebase", "profile", "icon", "lowsrc",
    "dynsrc", "on", "ONCLICK", "oNeRrOr", "formmethod", "enctype", "accept", "autofocus", "popover",
]  # fmt: skip
URL_ATTRIBUTES_FOR_GRAMMAR = {"href", "src", "action", "formaction", "background", "poster", "data",
                              "cite", "ping", "xlink:href", "usemap", "longdesc", "manifest",
                              "codebase", "profile", "icon", "lowsrc", "dynsrc"}  # fmt: skip


@st.composite
def attribute_values(draw: st.DrawFn, name: str) -> str:
    if name in URL_ATTRIBUTES_FOR_GRAMMAR:
        return draw(urls())
    if name == "srcset":
        return ", ".join(f"{draw(urls())} {draw(st.sampled_from(['1x', '2x', '100w', '']))}"
                         for _ in range(draw(st.integers(1, 3))))  # fmt: skip
    if name == "style":
        return ";".join(draw(st.lists(declarations(), max_size=3)))
    if name == "content":
        return f"{draw(st.integers(0, 5))};url={draw(urls())}"
    return draw(st.text(alphabet="abc <>\"'&;=/\\:.-_()%1", max_size=20))


@st.composite
def attribute_text(draw: st.DrawFn) -> str:
    name = draw(st.sampled_from(ATTRIBUTES))
    value = draw(attribute_values(name))
    quote = draw(st.sampled_from(['"', "'", "", '"', '"']))
    if quote == '"':
        value = value.replace('"', "&quot;") if draw(st.booleans()) else value
    elif quote == "'":
        value = value.replace("'", "&#39;") if draw(st.booleans()) else value
    space = draw(st.sampled_from([" ", "  ", "\n", "\t", "/", "\x0c", "\x00"]))
    if draw(st.integers(0, 9)) == 0:
        return f"{space}{name}"
    return f"{space}{name}={quote}{value}{quote}"


@st.composite
def nodes(draw: st.DrawFn, depth: int = 0) -> str:  # noqa: PLR0911
    kind = draw(st.integers(0, 9 if depth < 4 else 4))
    if kind <= 1:
        return draw(st.text(alphabet="abc <>&;\"'/\\", max_size=12))
    if kind == 2:
        return draw(st.sampled_from(MUTATION_SHAPES))
    if kind == 3:
        return draw(
            st.sampled_from(["<!--", "-->", "<!---->", "<!DOCTYPE html>", "<?xml?>", "&amp;"])
        )
    if kind == 4:
        return draw(st.sampled_from(["<br>", "<hr>", "<wbr>", "<p>", "</p>", "</div>", "</a>"]))
    tag = draw(st.sampled_from(TAGS))
    attributes = "".join(draw(st.lists(attribute_text(), max_size=4)))
    children = "".join(draw(st.lists(nodes(depth + 1), max_size=3)))
    close = draw(st.sampled_from([f"</{tag}>", f"</{tag.upper()}>", "", "</x>", f"</{tag} >"]))
    case = draw(st.sampled_from([tag, tag, tag.upper(), tag.capitalize()]))
    if draw(st.integers(0, 6)) == 0:
        return f"<{case}{attributes}/>"
    if draw(st.integers(0, 9)) == 0:
        return f"<{case}{attributes}"  # a tag that never ends
    return f"<{case}{attributes}>{children}{close}"


@st.composite
def documents(draw: st.DrawFn) -> str:
    return "".join(draw(st.lists(nodes(), min_size=1, max_size=5)))


OPTION_SETS = [
    HtmlOptions(),
    HtmlOptions(allow_images=True),
    HtmlOptions(allow_post_forms=False, allow_password_fields=False),
    HtmlOptions(allow_uploads=True, allow_images=True),
]


@settings(max_examples=300 * SCALE)
@given(documents(), st.sampled_from(OPTION_SETS))
def test_generated_pages_are_refused_or_safe(document: str, options: HtmlOptions) -> None:
    try:
        result = rewrite_html(document.encode("utf-8"), BASE, MAPPER, options=options)
    except RewriteError:
        return
    assert_safe_output(result.body, MAPPER, allow_images=options.allow_images)
    assert_reparse_safe(result.body.decode("utf-8"))


@settings(max_examples=120 * SCALE)
@given(documents())
def test_generated_pages_stay_safe_after_the_real_mapper_substitutes_labels(document: str) -> None:
    config = Settings(base_domain="localhost", open_mode=True, port=8765, scheme="http")
    mapper = PlaceholderMapper(config)
    try:
        result = rewrite_html(document.encode("utf-8"), BASE, mapper)
    except RewriteError:
        return
    text = result.body.decode("utf-8")
    # Before substitution everything the page can load is on the placeholder or warning host.
    assert_safe_output(result.body, mapper)  # type: ignore[arg-type]
    labels = dict.fromkeys(mapper.origins()[::2], "a" * 26)
    final = mapper.substitute(text, labels)
    assert ".invalid" not in final
    assert_reparse_safe(final)
    parsed = LexborHTMLParser(final)
    for node in parsed.css("*"):
        for name, raw in node.attributes.items():
            if name in ("href", "src", "action", "formaction", "poster", "background", "cite"):
                value = raw or ""
                assert (
                    value == ""
                    or value.startswith("#")
                    or value.startswith("http://localhost:8765/")
                    or value.startswith("http://" + "a" * 26 + ".localhost:8765")
                ), f"{name}={value!r}"


@settings(max_examples=300 * SCALE)
@given(
    stylesheets(), st.sampled_from([CssOptions(allow_images=False), CssOptions(allow_images=True)])
)
def test_generated_stylesheets_are_refused_or_verified(text: str, options: CssOptions) -> None:
    try:
        out = sanitize_stylesheet(text, BASE, MAPPER, options)
    except CssError:
        return
    assert verify_stylesheet(out, MAPPER), out
    assert_no_tokenizer_errors(out)
    for link in _css_urls(out):
        assert link.startswith("#") or MAPPER.owns(link), f"{link!r} in {out!r}"
    assert "<" not in out or "\\3c" in out.lower() or "\\3C" in out


@settings(max_examples=300 * SCALE)
@given(
    st.lists(declarations(), max_size=5).map(";".join),
    st.sampled_from([CssOptions(allow_images=False), CssOptions(allow_images=True)]),
)
def test_generated_style_attributes_are_empty_or_verified(text: str, options: CssOptions) -> None:
    out = sanitize_declarations(text, BASE, MAPPER, options)
    assert verify_declarations(out, MAPPER), out
    assert_no_tokenizer_errors(out)
    for link in _css_urls(out):
        assert link.startswith("#") or MAPPER.owns(link), f"{link!r} in {out!r}"
