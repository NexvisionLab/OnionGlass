# SPDX-License-Identifier: AGPL-3.0-only
"""Test helpers: a fake URL mapper and an independent safety oracle for rewritten output."""

from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser
from urllib.parse import quote, urlsplit

from onionglass.onion import OnionOrigin, OnionUrl, parse_onion_url

GATEWAY_DOMAIN = "gw.example"
TOR_PROJECT = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"
DUCKDUCKGO = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
BASE_TEXT = f"http://{TOR_PROJECT}.onion/dir/page.html"


def base_url(text: str = BASE_TEXT) -> OnionUrl:
    return parse_onion_url(text)


class FakeMapper:
    """Maps onion origins to deterministic labels under a fake gateway domain."""

    def label(self, origin: OnionOrigin) -> str:
        digest = hashlib.sha256(origin.key.encode()).digest()
        return base64.b32encode(digest).decode("ascii").lower()[:26]

    def onion(self, origin: OnionOrigin) -> str:
        return f"https://{self.label(origin)}.{GATEWAY_DOMAIN}"

    def external(self, url: str) -> str:
        return f"https://{GATEWAY_DOMAIN}/_og/external?u={quote(url, safe='')}"

    def owns(self, url: str) -> bool:
        if url == "" or url.startswith("#"):
            return True
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            return False
        if parts.hostname == GATEWAY_DOMAIN:
            return parts.path == "/_og/external"
        return parts.hostname.endswith(f".{GATEWAY_DOMAIN}") and len(
            parts.hostname
        ) == 26 + 1 + len(GATEWAY_DOMAIN)


ALLOWED_TAGS = frozenset(
    {
        "html", "head", "meta", "title", "body", "a", "abbr", "address", "article", "aside", "b",
        "bdi", "bdo", "blockquote", "br", "button", "caption", "cite", "code", "col", "colgroup",
        "data", "dd", "del", "details", "dfn", "div", "dl", "dt", "em", "fieldset", "figcaption",
        "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr",
        "i", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "main", "mark", "menu",
        "nav", "ol", "optgroup", "option", "p", "pre", "q", "rp", "rt", "ruby", "s", "samp",
        "section", "select", "small", "span", "strong", "style", "sub", "summary", "sup", "table",
        "tbody", "td", "textarea", "tfoot", "th", "thead", "time", "tr", "u", "ul", "var", "wbr",
    }
)  # fmt: skip
URL_ATTRIBUTES = frozenset({"href", "src", "srcset", "action", "formaction"})
FORBIDDEN_CSS = ("expression(", "javascript:", "behavior", "-moz-binding", "@charset")


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str, str | None]] = []
        self.styles: list[str] = []
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            self.attributes.append((tag, name, value))
        if tag == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_style:
            self.styles.append(data)


def _css_urls(css: str) -> list[str]:
    """Every URL mentioned in some CSS text, found without using the code under test."""
    found: list[str] = []
    lowered = css.lower()
    position = 0
    while True:
        position = lowered.find("url(", position)
        if position == -1:
            break
        end = css.find(")", position)
        if end == -1:
            found.append("<unterminated>")
            break
        found.append(css[position + 4 : end].strip().strip("\"'"))
        position = end
    position = 0
    while True:
        position = lowered.find("@import", position)
        if position == -1:
            break
        statement = css[position : css.find(";", position) if ";" in css[position:] else len(css)]
        if "url(" not in statement.lower():
            found.append("<import without url()>")
        position += 7
    return found


def assert_safe_output(document: bytes, mapper: FakeMapper, *, allow_images: bool = False) -> None:
    """Check rewritten output with a different HTML parser from the one that produced it."""
    collector = _Collector()
    collector.feed(document.decode("utf-8"))
    collector.close()
    for tag in collector.tags:
        assert tag in ALLOWED_TAGS, f"tag {tag} should not survive"
    for tag, name, value in collector.attributes:
        assert not name.startswith("on"), f"event handler {name} on {tag}"
        text = value or ""
        if name in URL_ATTRIBUTES:
            candidates = (
                [c.split()[0] for c in text.split(",") if c.split()] if name == "srcset" else [text]
            )
            for candidate in candidates:
                assert mapper.owns(candidate), (
                    f"{tag} {name} points outside the gateway: {candidate}"
                )
                if name in ("action", "formaction"):
                    assert "/_og/external" not in candidate, (
                        "form data must never reach the warning page"
                    )
            if not allow_images:
                assert name not in ("src", "srcset"), f"image reference on {tag} although withheld"
        if name == "style":
            collector.styles.append(text)
    for css in collector.styles:
        lowered = css.lower()
        for forbidden in FORBIDDEN_CSS:
            assert forbidden not in lowered, f"{forbidden} survived in CSS"
        for url in _css_urls(css):
            assert url.startswith("#") or mapper.owns(url), (
                f"CSS reference outside the gateway: {url}"
            )
