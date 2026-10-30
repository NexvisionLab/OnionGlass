# SPDX-License-Identifier: AGPL-3.0-only
"""Generated hostile pages and stylesheets, opened in a real browser.

The rewriter and its checks all parse text with Python libraries. If one of those disagrees with
the browser about where a string, comment or address ends, every check could pass and the page
could still reach out. A browser is the only judge of that. Each generated page has its evil
addresses pointed at a local leak detector, goes through the real gateway, and is opened in
Chrome. A single request that reaches the detector fails the test.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings
from playwright.sync_api import Browser, Dialog, Page

from helpers import TOR_PROJECT
from onionglass.headers import document_headers, resource_headers
from onionglass.upstream import UpstreamRequest, UpstreamResponse
from test_browser import PNG, Running, browser, frame_of, open_in_viewer, running_gateway  # noqa: F401
from test_grammar_fuzz import SCALE, declarations, documents, stylesheets

pytestmark = [pytest.mark.browser, pytest.mark.timeout(900)]

EVIL = "http://evil.example"


class CaseSite:
    """A fake onion site that serves whatever the current example says."""

    def __init__(self, leak: str) -> None:
        self.leak = leak
        self.page = ""
        self.sheet = ""

    def point_at_detector(self, text: str) -> str:
        host = self.leak.removeprefix("http://")
        return text.replace(EVIL, self.leak).replace("//evil.example", "//" + host)

    async def fetch(
        self, request: UpstreamRequest, *, max_body_bytes: int | None = None
    ) -> UpstreamResponse:
        if request.target.startswith("/s.css"):
            body, media = self.point_at_detector(self.sheet).encode("utf-8"), "text/css"
        elif ".png" in request.target:
            body, media = PNG, "image/png"
        else:
            body = self.point_at_detector(self.page).encode("utf-8")
            media = "text/html; charset=utf-8"
        return UpstreamResponse(
            status=200,
            reason="OK",
            headers=(("content-type", media),),
            body=body,
            elapsed=0.0,
        )


@dataclass
class Rig:
    running: Running
    site: CaseSite
    page: Page
    url: str
    dialogs: list[str]
    count: int = 0

    def show(self, document: str, sheet: str = "") -> None:
        self.count += 1
        self.site.page = document
        self.site.sheet = sheet
        self.page.goto(f"{self.url}?case={self.count}", wait_until="load")
        self.page.wait_for_timeout(15)
        assert self.dialogs == [], f"a script ran: {self.dialogs}\npage: {document!r}"
        assert self.running.detector.hits == [], (
            f"a request reached the leak detector: {self.running.detector.hits}\n"
            f"page: {document!r}\nstylesheet: {sheet!r}"
        )


def without_csp(original: Callable[..., dict[str, str]]) -> Callable[..., dict[str, str]]:
    def stripped(*args: object, **kwargs: object) -> dict[str, str]:
        headers = original(*args, **kwargs)
        return {k: v for k, v in headers.items() if k.lower() != "content-security-policy"}

    return stripped


@contextmanager
def policy_off() -> Iterator[None]:
    """Serve pages without the Content-Security-Policy, so only the rewriter stands in the way."""
    with (
        mock.patch("onionglass.gateway.document_headers", without_csp(document_headers)),
        mock.patch("onionglass.gateway.resource_headers", without_csp(resource_headers)),
    ):
        yield


@pytest.fixture(
    scope="module",
    params=["images-off-no-csp", "images-on-no-csp", "images-on-full-headers"],
)
def rig(browser: Browser, request: pytest.FixtureRequest) -> Iterator[Rig]:  # noqa: F811
    holder: dict[str, CaseSite] = {}

    def make(leak: str) -> CaseSite:
        holder["site"] = CaseSite(leak)
        return holder["site"]

    name = str(request.param)
    with contextlib.ExitStack() as stack:
        if name.endswith("no-csp"):
            stack.enter_context(policy_off())
        running = stack.enter_context(running_gateway(allow_images="images-on" in name, site=make))
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        dialogs: list[str] = []

        def on_dialog(dialog: Dialog) -> None:
            dialogs.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", on_dialog)
        site = holder["site"]
        site.page = "<title>start</title><p>start</p>"
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        # Pages are then opened directly on the label host the viewer received.
        url = frame_of(page).url.split("?")[0]
        assert re.match(r"http://[a-z2-7]{26}\.localhost:\d+/", url), url
        try:
            yield Rig(running, site, page, url, dialogs)
        finally:
            page.wait_for_timeout(300)
            late = list(running.detector.hits)
            context.close()
            assert late == [], f"late requests reached the leak detector: {late}"


FUZZ = settings(
    max_examples=25 * SCALE,
    deadline=None,
    suppress_health_check=list(HealthCheck),
)


@FUZZ
@given(documents())
def test_generated_pages_reach_nothing_in_chrome(rig: Rig, document: str) -> None:
    rig.show(document)


@FUZZ
@given(stylesheets(), declarations())
def test_generated_stylesheets_reach_nothing_in_chrome(
    rig: Rig, sheet: str, declaration: str
) -> None:
    page = (
        '<link rel="stylesheet" href="/s.css">'
        f"<style>{sheet}</style>"
        f'<div id="a" style="{declaration.replace(chr(34), "&quot;")}">a</div>'
        "<p class=a>b</p><a href=/x>c</a><input><button>d</button>"
    )
    rig.show(page, sheet)


MALFORMED_STYLE = [
    "a{background:url(EVIL/a}",
    "a{background:url(EVIL/a",
    "a{background:url('EVIL/a)}",
    'a{background:url("EVIL/a)}',
    "a{background:url(EVIL/a b)}",
    "a{background:url(EVIL/a'b)}",
    "a{content:'x\n}b{background:url(EVIL/s)}",
    "a{content:'x\\\n}b{background:url(EVIL/s)}",
    "a{content:'\\'}b{background:url(EVIL/s)}",
    "a{content:\"\\\"}b{background:url(EVIL/s)}",
    "a{background:u\\72l(EVIL/a)}",
    "a{background:\\75rl(EVIL/a)}",
    "a{background:\\000075rl(EVIL/a)}",
    "a{background:u/**/rl(EVIL/a)}",
    "a{background:url(/**/EVIL/a)}",
    "a{background:url(EVIL/a/**/)}",
    "a{background:url(\\45VIL/a)}",
    "a{background:url(EVIL\\2f a)}",
    "a{background:image-set(EVIL/a 1x)}",
    'a{background:image-set("EVIL/a" 1x)}',
    "a{background:image-set(url(EVIL/a) 1x,url(EVIL/b 2x)}",
    "a{background:-webkit-image-set(url(EVIL/a) 1x)}",
    "a{background:cross-fade(url(EVIL/a),url(EVIL/b),50%)}",
    "a{background:element(#x)}",
    "a{background:paint(x)}",
    "a{--u:url(EVIL/a);background:var(--u)}",
    "a{--u:EVIL/a;background:url(var(--u))}",
    "a{background:attr(x url)}",
    "a{background:src(EVIL/a)}",
    "a{background:image(EVIL/a)}",
    "a{background:image('EVIL/a')}",
    "@import 'EVIL/a.css';",
    '@import "EVIL/a.css" screen;',
    "@import url(EVIL/a.css);",
    "@import url(EVIL/a.css;",
    "@import/**/'EVIL/a.css';",
    "@\\69mport 'EVIL/a.css';",
    "@IMPORT 'EVIL/a.css';",
    "@font-face{font-family:f;src:url(EVIL/a.woff2)}",
    "@font-face{font-family:f;src:url(EVIL/a.woff2",
    "@font-face{font-family:f;src:local(x),url(EVIL/a.woff2) format('woff2')}",
    "@namespace url(EVIL/ns);",
    "@namespace svg url(EVIL/ns);",
    "@media screen{a{background:url(EVIL/a)}}",
    "@media screen{@import 'EVIL/a.css';}",
    "@supports (display:grid){a{background:url(EVIL/a)}}",
    "@layer x{a{background:url(EVIL/a)}}",
    "@container (min-width:1px){a{background:url(EVIL/a)}}",
    "@scope (a){b{background:url(EVIL/a)}}",
    "@starting-style{a{background:url(EVIL/a)}}",
    "@document url-prefix(){a{background:url(EVIL/a)}}",
    "@-moz-document url-prefix(){a{background:url(EVIL/a)}}",
    "@property --x{syntax:'<url>';inherits:false;initial-value:url(EVIL/a)}",
    "@keyframes k{from{background:url(EVIL/a)}}",
    "@page{background:url(EVIL/a)}",
    "@charset 'EVIL/a';a{background:url(EVIL/b)}",
    "a{background:url(EVIL/a)}}}}b{background:url(EVIL/b)}",
    "a{{{{background:url(EVIL/a)}",
    "a{b{background:url(EVIL/a)}}",
    "a{&{background:url(EVIL/a)}}",
    "a;{background:url(EVIL/a)}",
    "a{background:url(EVIL/a)\\}b{background:url(EVIL/b)}",
    "a{background:url(EVIL/a);;;;}b{background:url(EVIL/b)}",
    "a{background:url(EVIL/a) !important}",
    "a{background:url(EVIL/a)!IMPORTANT}",
    "a{background:url(EVIL/a) !ie}",
    "a{*background:url(EVIL/a)}",
    "a{_background:url(EVIL/a)}",
    "a{background:expression(new Image().src='EVIL/e')}",
    "a{behavior:url(EVIL/a.htc)}",
    "a{-moz-binding:url(EVIL/a.xml#x)}",
    "a{cursor:url(EVIL/a),auto}",
    "a{list-style:url(EVIL/a)}",
    "a{border-image:url(EVIL/a) 1}",
    "a{mask:url(EVIL/a)}",
    "a{-webkit-mask-image:url(EVIL/a)}",
    "a{filter:url(EVIL/a#f)}",
    "a{shape-outside:url(EVIL/a)}",
    "a{offset-path:url(EVIL/a)}",
    "a{clip-path:url(EVIL/a#c)}",
    "a{marker-start:url(EVIL/a#m)}",
    "a{fill:url(EVIL/a#p)}",
    "a:not([x=\"EVIL/a\"]){background:url(EVIL/a)}",
    "a[href^='EVIL']{background:url(EVIL/a)}",
    "a::after{content:url(EVIL/a)}",
    "a::before{content:image-set('EVIL/a' 1x)}",
    "a{background:URL(EVIL/a)}",
    "a{background:uRl( EVIL/a )}",
    "a{background:url(\tEVIL/a)}",
    "a{background:url(\nEVIL/a)}",
    "a{background:url(EVIL/a\n)}",
    "a{background:\\0075 rl(EVIL/a)}",
    "<!--a{background:url(EVIL/a)}-->",
    "-->a{background:url(EVIL/a)}<!--",
    "a{background:url(EVIL/a)}</style><img src=EVIL/i>",
]  # fmt: skip


def test_malformed_styles_reach_nothing_in_chrome(rig: Rig) -> None:
    for sheet in MALFORMED_STYLE:
        for wrapper in (
            "<style>{}</style><p>x</p>",
            '<p style="{}">x</p>',
            '<link rel="stylesheet" href="/s.css"><p>x</p>',
        ):
            if wrapper.startswith("<p style"):
                declaration = sheet.removeprefix("a{").removesuffix("}")
                document = wrapper.format(declaration.replace('"', "&quot;"))
            elif wrapper.startswith("<link"):
                document = wrapper
            else:
                document = wrapper.format(sheet)
            rig.show(document.replace("EVIL", EVIL), sheet.replace("EVIL", EVIL))
