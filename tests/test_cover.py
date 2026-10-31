# SPDX-License-Identifier: AGPL-3.0-only
"""Cover mode: to anyone without a sign-in the gateway looks like a plain little website.

A censor that visits the domain to see what it is must learn nothing. Every address answers as
a small web server would, and only a valid sign-in link opens the gateway.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from onionglass.config import ConfigError, load_config
from onionglass.cover import DEFAULT_PAGE, MAX_PAGE_BYTES, NOT_FOUND_PAGE, Cover, load_cover
from onionglass.gateway import Gateway
from onionglass.settings import Settings
from onionglass.store import StoreFullError
from onionglass.teamcli import describe
from onionglass.tickets import KeyRing, TicketIssuer, generate_key
from test_config import Layout
from test_gateway import PAGE, FakeFetcher
from test_review4 import call

GIVEAWAYS = ("onionglass", "gateway", "onion", "sign in", "tor ", "proxy", "report")


class Covered:
    """A team-mode gateway with cover mode on."""

    def __init__(self, cover: Cover | None = None, *, confirm: bool = False) -> None:
        self.key = generate_key()
        keys = KeyRing()
        keys.add("k1", self.key.public_key())
        self.issuer = TicketIssuer(self.key, "k1", "onionglass")
        self.settings = Settings(
            base_domain="gw.example",
            keys=keys,
            cover=cover or Cover(),
            confirm_sign_in=confirm,
            abuse_contact="abuse@example.org",
        )
        self.gateway = Gateway(self.settings, fetcher=FakeFetcher())
        self.client = TestClient(
            self.gateway.app, base_url="https://gw.example", follow_redirects=False
        )

    def ticket(self, **kwargs: Any) -> str:
        return self.issuer.issue(subject="analyst-1", group="team", profile="personal", **kwargs)

    def sign_in(self) -> None:
        assert self.client.get("/enter", params={"t": self.ticket()}).status_code == 303


# --- what a stranger sees ------------------------------------------------------------------------


def test_a_stranger_sees_a_plain_page_that_says_nothing_about_what_this_is() -> None:
    response = Covered().client.get("/")
    assert response.status_code == 200 and response.content == DEFAULT_PAGE
    assert response.headers["content-type"].startswith("text/html")
    lowered = response.text.lower()
    assert not [word for word in GIVEAWAYS if word in lowered]
    assert "set-cookie" not in response.headers


UNKNOWN = [
    "/nothing-here",
    "/abuse",
    "/view",
    "/open",
    "/enter",
    "/enter?t=garbage",
    "/_og/current",
    "/_og/viewer.js",
    "/_og/external?u=http://example.net",
    "/_og/blocked",
    "/_og/health",
    "/_og/metrics",
    "/robots.txt",
    "/index.php",
]


def test_every_other_address_answers_the_way_a_missing_page_does() -> None:
    env = Covered()
    answers = [env.client.get(path) for path in UNKNOWN]
    assert {response.status_code for response in answers} == {404}
    assert {response.content for response in answers} == {NOT_FOUND_PAGE}
    assert len({tuple(sorted(response.headers.items())) for response in answers}) == 1


@pytest.mark.parametrize("path", ["/open", "/enter", "/_og/reader", "/_og/report", "/anything"])
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_other_methods_get_the_same_missing_page(method: str, path: str) -> None:
    response = Covered().client.request(method, path, data={"t": "x"})
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_the_missing_page_and_the_cover_page_do_not_name_the_gateway() -> None:
    for page in (DEFAULT_PAGE, NOT_FOUND_PAGE):
        lowered = page.decode("utf-8").lower()
        assert not [word for word in GIVEAWAYS if word in lowered]


def test_a_host_name_that_is_not_this_gateways_gets_the_same_answer() -> None:
    env = Covered()
    response = env.client.get("/", headers={"host": "another.example"})
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_a_session_host_without_a_sign_in_gets_the_missing_page_not_an_error_page() -> None:
    env = Covered()
    for host in ("a" * 26 + ".gw.example", "b" * 26 + ".gw.example"):
        response = env.client.get("/", headers={"host": host})
        assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


# --- what a visitor with a link sees -------------------------------------------------------------


def test_a_valid_link_still_signs_in_and_then_the_gateway_works() -> None:
    env = Covered()
    ticket = env.ticket()
    first = env.client.get("/enter", params={"t": ticket})
    assert first.status_code == 303 and "og_session" in first.headers["set-cookie"]
    assert "onionglass" in env.client.get("/").text
    assert env.client.get("/abuse").status_code == 200  # signed in, so it is not hidden


def test_a_link_that_was_used_already_gets_the_missing_page_not_a_refusal() -> None:
    env = Covered()
    ticket = env.ticket()
    env.client.get("/enter", params={"t": ticket})
    other = TestClient(env.gateway.app, base_url="https://gw.example", follow_redirects=False)
    replay = other.get("/enter", params={"t": ticket})
    assert replay.status_code == 404 and replay.content == NOT_FOUND_PAGE


def test_a_link_that_asks_for_a_click_shows_the_page_only_to_whoever_holds_it() -> None:
    env = Covered(confirm=True)
    shown = env.client.get("/enter", params={"t": env.ticket()})
    assert shown.status_code == 200 and "Continue" in shown.text
    forged = env.client.post("/enter", data={"t": "garbage"})
    assert forged.status_code == 404 and forged.content == NOT_FOUND_PAGE


def test_a_signed_in_visitor_can_open_a_site_and_a_stranger_cannot_use_their_session_host() -> None:
    env = Covered()
    env.sign_in()
    opened = env.client.post(
        "/open", data={"address": PAGE}, headers={"origin": "https://gw.example"}
    )
    assert opened.status_code == 303
    label = opened.headers["location"].split("l=")[1].split("&")[0]
    stranger = TestClient(env.gateway.app, base_url="https://gw.example", follow_redirects=False)
    response = stranger.get("/", headers={"host": f"{label}.gw.example"})
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


# --- the supervisor's health check ---------------------------------------------------------------


def test_the_health_check_answers_only_this_machine() -> None:
    env = Covered()

    async def ask(client: tuple[str, int]) -> tuple[int, bytes]:
        return await call(env.gateway.app, "GET", "/_og/health", host="gw.example", client=client)

    inside = asyncio.run(ask(("127.0.0.1", 50000)))
    outside = asyncio.run(ask(("203.0.113.7", 50000)))
    assert inside[0] == 200 and b"ok" in inside[1]
    assert outside == (404, NOT_FOUND_PAGE)


# --- the page ------------------------------------------------------------------------------------


def test_the_page_can_be_the_operators_own(tmp_path: Path) -> None:
    page = tmp_path / "cover.html"
    page.write_text("<html><body><h1>Garden club</h1></body></html>", encoding="utf-8")
    env = Covered(load_cover(page))
    assert b"Garden club" in env.client.get("/").content
    assert env.client.get("/missing").content == NOT_FOUND_PAGE


def test_the_page_cannot_run_script_or_load_anything() -> None:
    policy = Covered().client.get("/").headers["content-security-policy"]
    assert "default-src 'none'" in policy and "script-src" not in policy.replace("default", "")
    assert "form-action 'none'" in policy and "frame-ancestors 'none'" in policy


@pytest.mark.parametrize(
    "content",
    [b"", b"   \n", b"\xff\xfe\x00broken", b"x" * (MAX_PAGE_BYTES + 1)],
)
def test_a_page_that_is_empty_too_large_or_not_text_is_refused(
    tmp_path: Path, content: bytes
) -> None:
    page = tmp_path / "cover.html"
    page.write_bytes(content)
    with pytest.raises(ValueError, match="cover"):
        load_cover(page)


def test_a_page_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cover"):
        load_cover(tmp_path / "missing.html")


# --- settings and the config file ----------------------------------------------------------------


def test_cover_mode_is_for_gateways_that_need_a_sign_in() -> None:
    with pytest.raises(ValueError, match="cover"):
        Settings(base_domain="localhost", open_mode=True, cover=Cover())


def turn_on(layout: Layout, extra: str = "") -> Settings:
    layout.config.write_text(
        layout.text() + f"\n[cover]\nenabled = true\n{extra}", encoding="utf-8"
    )
    return load_config(layout.config).settings


def test_the_config_file_turns_cover_mode_on(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    assert load_config(layout.config).settings.cover is None
    assert turn_on(layout).cover == Cover()


def test_the_config_file_can_name_a_page(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    (layout.root / "lists" / "cover.html").write_text("<p>Hello</p>", encoding="utf-8")
    settings = turn_on(layout, 'page_file = "lists/cover.html"\n')
    assert settings.cover is not None and settings.cover.page == b"<p>Hello</p>"


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ('page_file = "lists/missing.html"\n', "cover"),
        ("unknown_setting = 1\n", "unknown_setting"),
        ('page_file = ""\n', "page_file"),
    ],
)
def test_the_cover_settings_are_checked(tmp_path: Path, extra: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        turn_on(Layout(tmp_path), extra)


def test_cover_mode_must_say_true_to_be_on(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    layout.config.write_text(layout.text() + '\n[cover]\nenabled = "yes"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="true or false"):
        load_config(layout.config)
    layout.config.write_text(layout.text().replace('"yes"', "false"), encoding="utf-8")
    assert load_config(layout.config).settings.cover is None


def test_check_config_says_cover_mode_is_on_and_that_the_abuse_page_is_hidden(
    tmp_path: Path,
) -> None:
    layout = Layout(tmp_path)
    turn_on(layout)
    lines = describe(load_config(layout.config))
    assert any("cover mode: on" in line for line in lines)
    assert any("abuse" in line and "hidden" in line for line in lines)


# --- errors do not give the gateway away ---------------------------------------------------------


def test_an_internal_error_is_hidden_from_a_stranger_but_not_from_a_signed_in_visitor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = Covered()

    async def boom(request: Any) -> Any:
        raise RuntimeError("something broke")

    monkeypatch.setattr(env.gateway, "_handle_apex", boom)
    stranger = env.client.get("/enter", params={"t": "x"})
    assert stranger.status_code == 404 and stranger.content == NOT_FOUND_PAGE
    env.client.cookies.set("og_session", "a" * 43)  # a cookie, though not a valid session
    assert env.client.get("/enter", params={"t": "x"}).status_code == 500


def test_a_full_store_is_hidden_from_a_stranger_too(monkeypatch: pytest.MonkeyPatch) -> None:
    env = Covered()

    async def full(request: Any) -> Any:
        raise StoreFullError("full")

    monkeypatch.setattr(env.gateway, "_handle_apex", full)
    response = env.client.get("/enter", params={"t": "x"})
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_two_host_headers_get_the_missing_page_not_a_gateway_error() -> None:
    env = Covered()

    async def ask() -> tuple[int, bytes]:
        return await call(env.gateway.app, "GET", "/", host="gw.example", headers={"host": "x"})

    assert asyncio.run(ask()) == (404, NOT_FOUND_PAGE)
