# SPDX-License-Identifier: AGPL-3.0-only
"""Properties P1, P2, P3 and P6 checked in a real browser.

The gateway runs with a fake onion site that serves a deliberately hostile page. A second local
web server acts as a leak detector: anything the browser requests from it is a leak. These tests
are skipped when no browser can be started.
"""

from __future__ import annotations

import asyncio
import re
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import uvicorn
from playwright.sync_api import Browser, Frame, Page, expect, sync_playwright

from helpers import TOR_PROJECT
from onionglass.gateway import Gateway
from onionglass.reports import ReportQueue
from onionglass.settings import Profile, Settings
from onionglass.upstream import Fetcher, UpstreamRequest, UpstreamResponse

pytestmark = pytest.mark.browser

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360f8"
    "ffff3f0005fe02fea7d5d5260000000049454e44ae426082"
)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass
class Detector:
    """A web server that records every request it receives."""

    hits: list[str] = field(default_factory=list)
    port: int = 0


@contextmanager
def leak_detector() -> Iterator[Detector]:
    detector = Detector()

    class Handler(BaseHTTPRequestHandler):
        def _answer(self) -> None:
            detector.hits.append(f"{self.command} {self.path}")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "6")
            self.end_headers()
            self.wfile.write(b"leaked")

        do_GET = _answer
        do_POST = _answer

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    detector.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield detector
    finally:
        server.shutdown()
        server.server_close()


def hostile_page(leak: str) -> str:
    return f"""<!doctype html><html lang="en"><head><title>HOSTILE PAGE</title>
<base href="{leak}/base/">
<meta http-equiv="refresh" content="0;url={leak}/refresh">
<link rel="stylesheet" href="{leak}/linked.css">
<link rel="stylesheet" href="/site.css">
<style>
@import url({leak}/import.css);
.styled {{ color: rgb(200, 0, 0); background: url({leak}/style-bg) }}
.set {{ background: image-set(url({leak}/style-imageset) 1x) }}
.webkit {{ background: -webkit-image-set(url({leak}/style-webkit) 1x) }}
.viavar {{ --u: "{leak}/via-var"; background: image-set(var(--u) 1x) }}
.cursor {{ cursor: url({leak}/cursor), auto; list-style-image: url({leak}/list) }}
@font-face {{ font-family: X; src: url({leak}/font.woff2) }}
</style>
<script>document.title = 'SCRIPT-RAN'; new Image().src = '{leak}/script-beacon';</script>
</head><body onload="document.title='ONLOAD-RAN'">
<h1>Hostile page</h1>
<p class="styled set webkit viavar cursor" id="marker" style="color:blue;background:url({leak}/inline-bg)">
Visible paragraph text.</p>
<div style="background-image:image-set(url({leak}/attr-imageset) 1x)">attribute image-set</div>
<img src="{leak}/img" onerror="document.title='ONERROR-RAN'" alt="remote image">
<img src="rel.png" alt="relative image under a hostile base">
<img src="/own.png" alt="own image">
<img srcset="{leak}/srcset 1x, /own.png 2x" alt="srcset image">
<picture><source srcset="{leak}/picture"><img src="{leak}/picture-fallback" alt="picture"></picture>
<video src="{leak}/video" poster="{leak}/poster"></video><audio src="{leak}/audio"></audio>
<iframe src="{leak}/iframe"></iframe><object data="{leak}/object"></object><embed src="{leak}/embed">
<svg onload="document.title='SVG-RAN'"><image href="{leak}/svg-image"/></svg>
<table background="{leak}/table-bg"><tr><td background="{leak}/td-bg">cell</td></tr></table>
<form action="{leak}/form" method="post"><input name="secret" value="x"><input type="submit"></form>
<a id="external" href="{leak}/link">external link</a> <a id="same" href="/page2">same-site link</a>
<a id="script-link" href="javascript:document.title='JS-URL-RAN'">javascript link</a>
</body></html>"""


class HostileOnion:
    """A fake onion site, standing in for Tor."""

    def __init__(self, leak: str) -> None:
        self._page = hostile_page(leak)

    async def fetch(
        self, request: UpstreamRequest, *, max_body_bytes: int | None = None
    ) -> UpstreamResponse:
        target = request.target
        body: bytes
        if target.startswith("/site.css"):
            body, media = b"h1{color:green} .styled{font-weight:bold}", "text/css"
        elif target.endswith(".png"):
            body, media = PNG, "image/png"
        elif target.startswith("/page2"):
            body, media = b"<title>Second</title><h1>second page</h1>", "text/html"
        else:
            body, media = self._page.encode(), "text/html; charset=utf-8"
        return UpstreamResponse(
            status=200,
            reason="OK",
            headers=(("content-type", media),),
            body=body,
            elapsed=0.0,
        )


@dataclass
class Running:
    apex: str
    port: int
    detector: Detector


@contextmanager
def running_gateway(
    *,
    allow_images: bool,
    site: Callable[[str], Fetcher] | None = None,
    reports: ReportQueue | None = None,
    show_entities: bool = False,
) -> Iterator[Running]:
    with leak_detector() as detector:
        port = free_port()
        settings = Settings(
            base_domain="localhost",
            scheme="http",
            port=port,
            open_mode=True,
            profile=Profile(allow_images=allow_images, show_entities=show_entities),
            reports=reports,
        )
        leak = f"http://127.0.0.1:{detector.port}"
        gateway = Gateway(settings, fetcher=(site or HostileOnion)(leak))
        config = uvicorn.Config(
            gateway.app, host="127.0.0.1", port=port, log_level="warning", access_log=False
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started, "the gateway did not start"
        try:
            yield Running(apex=f"http://localhost:{port}", port=port, detector=detector)
        finally:
            server.should_exit = True
            thread.join(10)


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as driver:
        launched = None
        # An installed Chrome or Edge first, then the browser Playwright downloads itself.
        for channel in ("chrome", "msedge", None):
            try:
                launched = driver.chromium.launch(headless=True, channel=channel)
                break
            except Exception:  # noqa: S112 - try the next kind of browser
                continue
        if launched is None:
            pytest.skip("no browser could be started")
        try:
            yield launched
        finally:
            launched.close()


def open_in_viewer(page: Page, running: Running, address: str) -> None:
    page.goto(f"{running.apex}/")
    page.get_by_label("Onion address").fill(address)
    page.get_by_role("button", name="Open").click()
    page.wait_for_url(re.compile(r"/view\?"))


def frame_of(page: Page) -> Frame:
    for frame in page.frames:
        if frame is not page.main_frame:
            return frame
    raise AssertionError("the viewer has no frame")


@pytest.mark.parametrize("allow_images", [False, True], ids=["images-off", "images-on"])
def test_a_hostile_page_runs_nothing_and_reaches_nothing(
    browser: Browser, allow_images: bool
) -> None:
    with running_gateway(allow_images=allow_images) as running:
        context = browser.new_context()
        requested: list[str] = []
        context.on("request", lambda request: requested.append(request.url))
        page = context.new_page()
        page.set_default_timeout(15_000)
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        page.frame_locator("#frame").get_by_role("heading", name="Hostile page").wait_for()
        child = frame_of(page)

        # Nothing the page tried has run.
        assert child.title() == "HOSTILE PAGE"
        assert child.evaluate("document.scripts.length") == 0
        assert (
            child.evaluate(
                "document.querySelectorAll('iframe,object,embed,video,audio,svg').length"
            )
            == 0
        )
        # The page's own styling still works, and its stylesheet came through the gateway.
        assert (
            child.evaluate("getComputedStyle(document.querySelector('h1')).color")
            == "rgb(0, 128, 0)"
        )
        assert (
            child.evaluate("getComputedStyle(document.getElementById('marker')).color")
            == "rgb(0, 0, 255)"
        )
        loaded_images = child.evaluate(
            "Array.from(document.images).filter(i => i.complete && i.naturalWidth > 0).length"
        )
        withheld = child.evaluate("document.querySelectorAll('.og-withheld').length")
        if allow_images:
            assert loaded_images == 2 and withheld == 0  # the page's own images only
        else:
            assert loaded_images == 0 and withheld == 5

        # Every request the browser made went to the gateway, none to the leak detector.
        for url in requested:
            host = urlsplit(url).hostname or ""
            assert host == "localhost" or host.endswith(".localhost"), url
        assert not any(f":{running.detector.port}" in url for url in requested)
        assert running.detector.hits == []

        # The toolbar shows the real address, and the frame is sandboxed without scripts.
        expect(page.locator("#address")).to_have_text(f"http://{TOR_PROJECT}.onion/")
        sandbox = page.locator("#frame").get_attribute("sandbox") or ""
        assert "allow-scripts" not in sandbox and "allow-top-navigation" not in sandbox
        assert TOR_PROJECT not in frame_of(page).url
        context.close()


def test_links_work_inside_the_frame_and_the_toolbar_follows(browser: Browser) -> None:
    with running_gateway(allow_images=False) as running:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        inside = page.frame_locator("#frame")
        inside.get_by_role("link", name="same-site link").click()
        inside.get_by_role("heading", name="second page").wait_for()
        expect(page.locator("#address")).to_have_text(f"http://{TOR_PROJECT}.onion/page2")
        expect(page).to_have_title(re.compile("Second"))
        assert running.detector.hits == []
        context.close()


def test_a_link_that_leaves_tor_shows_a_warning_in_the_frame_and_contacts_nothing(
    browser: Browser,
) -> None:
    with running_gateway(allow_images=False) as running:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        inside = page.frame_locator("#frame")
        inside.get_by_role("link", name="external link").click()
        inside.get_by_role("heading", name="This link leaves Tor").wait_for()
        link = inside.get_by_role("link", name="Continue to the site")
        assert link.get_attribute("target") == "_blank"
        assert "noopener" in (link.get_attribute("rel") or "")
        assert running.detector.hits == []  # nothing is contacted until the visitor continues
        context.close()


def test_a_javascript_link_does_nothing(browser: Browser) -> None:
    with running_gateway(allow_images=False) as running:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        page.frame_locator("#frame").get_by_role("heading", name="Hostile page").wait_for()
        child = frame_of(page)
        assert child.evaluate("document.getElementById('script-link').getAttribute('href')") is None
        assert child.title() == "HOSTILE PAGE"
        context.close()


def test_the_entry_form_refuses_a_bad_address_in_the_browser(browser: Browser) -> None:
    with running_gateway(allow_images=False) as running:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        page.goto(f"{running.apex}/")
        page.get_by_label("Onion address").fill("example.org")
        page.get_by_role("button", name="Open").click()
        expect(page.get_by_text("not a valid version 3 onion address")).to_be_visible()
        assert running.detector.hits == []
        context.close()


def test_the_report_button_works_under_the_viewers_policy(browser: Browser, tmp_path: Path) -> None:
    queue = ReportQueue(tmp_path / "reports.log")
    with running_gateway(allow_images=False, reports=queue) as running:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        page.frame_locator("#frame").get_by_role("heading", name="Hostile page").wait_for()
        expect(page.locator("#address")).to_have_text(f"http://{TOR_PROJECT}.onion/")
        page.locator("#report-category").select_option("harmful")
        page.get_by_role("button", name="Report this site").click()
        expect(page.locator("#report-status")).to_have_text(re.compile("Thank you"))
        page.get_by_role("button", name="Report this site").click()
        expect(page.locator("#report-status")).to_have_text(re.compile("already reported"))
        lines = (tmp_path / "reports.log").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1 and TOR_PROJECT in lines[0] and "harmful" in lines[0]
        assert running.detector.hits == []
        context.close()


class WalletOnion:
    """A page that names a wallet and an email address, and tries to put markup in the panel."""

    PAGE = (
        "<!doctype html><title>Shop</title><h1>Wallets</h1>"
        "<p>1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and sales@example.org</p>"
        '<p>"><img src=x onerror=alert(1)>@example.org</p>'
    )

    async def fetch(
        self, request: UpstreamRequest, *, max_body_bytes: int | None = None
    ) -> UpstreamResponse:
        return UpstreamResponse(
            status=200,
            reason="OK",
            headers=(("content-type", "text/html; charset=utf-8"),),
            body=self.PAGE.encode(),
            elapsed=0.0,
        )


def test_the_entity_panel_lists_what_the_page_names_as_plain_text(browser: Browser) -> None:
    with running_gateway(
        allow_images=False, show_entities=True, site=lambda _leak: WalletOnion()
    ) as running:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        dialogs: list[str] = []

        def refuse(dialog: Any) -> None:
            dialogs.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", refuse)
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        page.frame_locator("#frame").get_by_role("heading", name="Wallets").wait_for()
        expect(page.locator("#entities-toggle")).to_have_text(re.compile(r"Entities \(\d+\)"))
        expect(page.locator("#entities")).to_be_hidden()
        page.locator("#entities-toggle").click()
        expect(page.locator("#entities")).to_be_visible()
        listing = page.locator("#entities-list").inner_text()
        assert "bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in listing
        assert "email: sales@example.org" in listing
        assert page.locator("#entities-list img").count() == 0
        assert dialogs == [] and running.detector.hits == []
        context.close()


class HidingOnion:
    """A page built the way some real sites are: it hides itself and, for a browser without
    scripts, asks to be sent to a lighter page."""

    PAGE = (
        '<!doctype html><title>App</title><noscript><meta http-equiv="refresh" content="0; url=/lite">'
        "<style>body{display:none}</style></noscript><h1>Hidden app</h1>"
    )

    async def fetch(
        self, request: UpstreamRequest, *, max_body_bytes: int | None = None
    ) -> UpstreamResponse:
        if request.target == "/lite":
            await asyncio.sleep(3)  # slow enough for the viewer to ask again before it arrives
            body = b"<title>Lite</title><h1>Lite page</h1>"
        else:
            body = self.PAGE.encode()
        return UpstreamResponse(
            status=200,
            reason="OK",
            headers=(("content-type", "text/html; charset=utf-8"),),
            body=body,
            elapsed=0.0,
        )


def test_a_page_that_hides_itself_still_shows_the_visitor_where_it_wanted_to_go(
    browser: Browser,
) -> None:
    with running_gateway(allow_images=False, site=lambda _leak: HidingOnion()) as running:
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(15_000)
        open_in_viewer(page, running, f"{TOR_PROJECT}.onion")
        # The page has hidden its own body, so nothing inside the frame can be seen.
        expect(page.locator("#address")).to_have_text(f"http://{TOR_PROJECT}.onion/")
        assert frame_of(page).evaluate("getComputedStyle(document.body).display") == "none"
        # The toolbar belongs to the gateway, and it says what the page asked for.
        notice = page.locator("#redirect")
        expect(notice).to_be_visible()
        expect(notice).to_contain_text("Automatic redirects are off")
        page.get_by_role("button", name="Follow it").click()
        # The viewer asks again while the lighter page is still on its way, and is told the old
        # page's request once more. The notice must not come back.
        page.wait_for_timeout(2600)
        assert not notice.is_visible()  # an immediate check: expect() would wait for it to go
        page.frame_locator("#frame").get_by_role("heading", name="Lite page").wait_for()
        expect(notice).to_be_hidden()
        expect(page.locator("#address")).to_have_text(f"http://{TOR_PROJECT}.onion/lite")
        assert running.detector.hits == []
        context.close()
