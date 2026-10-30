# SPDX-License-Identifier: AGPL-3.0-only
"""Reproductions and regression tests for the policy findings of the third independent review.

Each test failed before the fix. They are grouped by the finding they came from.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.audit import MemoryAudit
from onionglass.config import ConfigError, load_config
from onionglass.gateway import Gateway
from onionglass.held import HeldList
from onionglass.namegate import NameGate
from onionglass.onion import parse_onion_url
from onionglass.policy import Decision, PolicyRequest
from onionglass.settings import Profile, Settings
from onionglass.store import InMemoryStore
from onionglass.tickets import KeyRing, generate_key
from onionglass.upstream import UpstreamRequest, UpstreamResponse
from test_config import Layout
from test_gateway import APEX, PAGE, Env, FakeFetcher, reply
from test_review3_availability import typed

# --- the name gate must not let one visitor hold any site ------------------------------------------


def _echo(request: UpstreamRequest) -> UpstreamResponse:
    """A search page that prints back what was asked for, as many sites do."""
    return reply(f"<title>Results for {request.target}</title><p>none</p>")


def test_a_page_that_only_repeats_the_request_does_not_get_the_site_held(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    env = Env(_echo, name_gate=NameGate(["grape"]), held=held)
    label = env.open()
    response = env.get(label, "/search?q=" + quote("grape"))
    assert response.status_code == 403  # the page is still refused
    assert held.reason_for(parse_onion_url(PAGE).origin.host.address) is None


def test_an_encoded_echo_does_not_get_the_site_held_either(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    env = Env(
        lambda r: reply(f"<title>Results for {r.target.replace('%2567', 'g')}</title>"),
        name_gate=NameGate(["grape"]),
        held=held,
    )
    label = env.open()
    # %2567 decodes twice to g, so the listed word only appears after two decodings
    env.get(label, "/search?q=gra%2570e")
    assert held.reason_for(parse_onion_url(PAGE).origin.host.address) is None


def test_a_listed_title_that_was_not_asked_for_still_holds_the_site(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    env = Env(
        lambda _r: reply("<title>Grape store</title><p>x</p>"),
        name_gate=NameGate(["grape"]),
        held=held,
    )
    label = env.open()
    assert env.get(label).status_code == 403
    assert held.reason_for(parse_onion_url(PAGE).origin.host.address) == "held"


def _team_gateway(tmp_path: Path, hold_after: int) -> tuple[Gateway, HeldList]:
    held = HeldList(tmp_path / "held.txt")
    keys = KeyRing()
    keys.add("k1", generate_key().public_key())
    settings = Settings(
        base_domain="gw.example",
        keys=keys,
        profile=Profile(name="personal"),
        name_gate=NameGate(["grape"]),
        name_gate_hold_after=hold_after,
        held=held,
    )
    gateway = Gateway(
        settings,
        fetcher=FakeFetcher(lambda _r: reply("<title>Grape</title>")),
        store=InMemoryStore(),
    )
    return gateway, held


def test_a_team_gateway_holds_a_site_only_after_different_accounts_have_met_it(
    tmp_path: Path,
) -> None:
    gateway, held = _team_gateway(tmp_path, hold_after=2)
    origin = parse_onion_url(PAGE).origin
    page = parse_onion_url(PAGE)

    async def meet(subject: str) -> None:
        session = await gateway._create_session(subject, "team", "personal")
        assert await gateway._name_gate_hit(session, page, "Grape", ())

    asyncio.run(meet("account-a"))
    asyncio.run(meet("account-a"))  # the same account again counts once
    assert held.reason_for(origin.host.address) is None
    asyncio.run(meet("account-b"))
    assert held.reason_for(origin.host.address) == "held"


def test_one_account_can_never_hold_a_site_alone_in_a_team_gateway(tmp_path: Path) -> None:
    gateway, held = _team_gateway(tmp_path, hold_after=2)
    page = parse_onion_url(PAGE)

    async def many() -> None:
        session = await gateway._create_session("account-a", "team", "personal")
        for _ in range(20):
            await gateway._name_gate_hit(session, page, "Grape", ())

    asyncio.run(many())
    assert held.reason_for(page.origin.host.address) is None


def test_personal_mode_holds_on_the_first_hit(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    env = Env(lambda _r: reply("<title>Grape</title>"), name_gate=NameGate(["grape"]), held=held)
    env.get(env.open())
    assert held.reason_for(parse_onion_url(PAGE).origin.host.address) == "held"


# --- the allowance cannot be overspent by requests that arrive together ----------------------------


async def _post(app: Any, path: str, form: dict[str, str]) -> int:
    """One form post straight into the application, so that several can be in flight at once."""
    body = urlencode(form).encode("ascii")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [
            (b"host", APEX.encode("ascii")),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
        "server": ("localhost", 8080),
        "client": ("127.0.0.1", 50000),
    }
    sent = [False]
    status: list[int] = []

    async def receive() -> dict[str, Any]:
        if not sent[0]:
            sent[0] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])

    await app(scope, receive, send)
    return status[0]


class SlowMeter:
    """A meter that takes time to answer, as one reached over a network does."""

    def __init__(self) -> None:
        self.total = 0

    async def used(self, subject: str, profile: str) -> int:
        await asyncio.sleep(0.02)
        return self.total

    async def charge(self, subject: str, profile: str, units: int) -> int:
        await asyncio.sleep(0.02)
        self.total += units
        return self.total

    async def reserve(self, subject: str, profile: str, units: int, limit: int) -> bool:
        await asyncio.sleep(0.02)
        if self.total + units > limit:
            return False
        self.total += units
        return True


def test_requests_that_arrive_together_cannot_spend_more_than_the_allowance() -> None:
    meter = SlowMeter()
    env = Env(
        lambda _r: reply("<p>x</p>"),
        profile=Profile(name="personal", open_cost=1, daily_quota=3),
        quota=meter,
        max_new_sessions_per_minute=1000,
    )

    async def burst() -> list[int]:
        posts = [_post(env.gateway.app, "/open", {"address": typed()}) for _ in range(12)]
        return list(await asyncio.gather(*posts))

    codes = asyncio.run(burst())
    assert codes.count(303) == 3
    assert meter.total == 3


# --- a first visit by link is an open, however the visitor got there --------------------------------


class Spy:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    async def decide(self, request: PolicyRequest) -> Decision:
        self.seen.append((request.origin.host.address, request.action))
        return Decision.allow("spy")


def _linking(request: UpstreamRequest) -> UpstreamResponse:
    if request.origin.host.address == TOR_PROJECT:
        return reply(f"<a href='http://{DUCKDUCKGO}.onion/page'>other</a>")
    return reply("<p>second site</p>")


def _label_of_link(env: Env, label: str) -> str:
    body = env.get(label).text
    link = next(part for part in body.split('"') if part.startswith("http://") and "/page" in part)
    return env.label_in(link)


def test_the_policy_sees_a_followed_link_as_an_open_the_first_time_only() -> None:
    spy = Spy()
    env = Env(_linking, policy=spy)
    label = env.open()
    other = _label_of_link(env, label)
    spy.seen.clear()
    assert env.get(other, "/page").status_code == 200
    assert env.get(other, "/page").status_code == 200
    assert spy.seen == [(DUCKDUCKGO, "open"), (DUCKDUCKGO, "fetch")]


def test_a_typed_address_is_one_open_not_two() -> None:
    spy = Spy()
    env = Env(_linking, policy=spy)
    env.get(env.open())
    assert [action for address, action in spy.seen if address == TOR_PROJECT] == ["open", "fetch"]


def test_following_a_link_to_a_new_site_uses_the_open_allowance() -> None:
    meter = SlowMeter()
    env = Env(
        _linking,
        profile=Profile(name="personal", open_cost=1, daily_quota=1),
        quota=meter,
    )
    label = env.open()  # the one open the allowance covers
    other = _label_of_link(env, label)
    assert env.get(other, "/page").status_code == 429
    assert meter.total == 1
    assert env.get(label).status_code == 200  # the site already opened still works


# --- the settings are read from the config file ----------------------------------------------------


def test_the_config_reads_the_open_limit_and_the_name_gate_threshold(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    assert "max_opens_per_session = 100" in text and "hold_after = 2" in text
    layout.config.write_text(
        text.replace("max_opens_per_session = 100", "max_opens_per_session = 7").replace(
            "hold_after = 2", "hold_after = 5", 1
        ),
        encoding="utf-8",
    )
    settings = load_config(layout.config).settings
    assert settings.max_opens_per_session == 7
    assert settings.name_gate_hold_after == 5
    layout.config.write_text(text.replace("hold_after = 2", "hold_after = 0", 1), encoding="utf-8")
    with pytest.raises(ConfigError, match="name_gate_hold_after"):
        load_config(layout.config)


def test_an_open_refused_for_the_session_limit_is_not_charged_or_recorded() -> None:
    meter = SlowMeter()
    audit = MemoryAudit()
    env = Env(
        lambda _r: reply("<p>x</p>"),
        profile=Profile(name="personal", open_cost=1, daily_quota=100),
        quota=meter,
        audit=audit,
        max_opens_per_session=2,
    )
    codes = [env.client.post("/open", data={"address": typed()}).status_code for _ in range(5)]
    assert codes.count(303) == 2
    assert meter.total == 2
    assert [e.kind for e in audit.events].count("allowed") == 2
