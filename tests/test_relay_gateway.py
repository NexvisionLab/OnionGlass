# SPDX-License-Identifier: AGPL-3.0-only
"""A gateway that sits behind relays: it serves requests a relay signed, and treats anything else
as a stranger, so that finding its address shows a censor nothing."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from onionglass.config import ConfigError, load_config
from onionglass.cover import DEFAULT_PAGE, NOT_FOUND_PAGE, Cover
from onionglass.gateway import Gateway
from onionglass.relayauth import CHECK_HEADER, HEADER, RelaySigner
from onionglass.settings import Settings
from onionglass.teamcli import describe
from onionglass.tickets import KeyRing, TicketIssuer, generate_key
from test_config import Layout, pem_public
from test_gateway import FakeFetcher
from test_review4 import call

HOST = "gw.example"
UNKNOWN = [
    "/nothing-here",
    "/abuse",
    "/open",
    "/view",
    "/_og/current",
    "/_og/metrics",
    "/robots.txt",
]


class Relayed:
    """A team-mode gateway behind relays, and a relay's key to speak to it."""

    def __init__(self, *, require: bool = True, cover: bool = True, **settings: Any) -> None:
        self.ticket_key = generate_key()
        keys = KeyRing()
        keys.add("k1", self.ticket_key.public_key())
        self.relay_key = generate_key()
        self.relay_keys = KeyRing()
        self.relay_keys.add("r1", self.relay_key.public_key())
        self.signer = RelaySigner("r1", self.relay_key)
        self.issuer = TicketIssuer(self.ticket_key, "k1", "onionglass")
        self.settings = Settings(
            base_domain=HOST,
            keys=keys,
            cover=Cover() if cover else None,
            confirm_sign_in=False,
            abuse_contact="abuse@example.org",
            relay_keys=self.relay_keys,
            relay_required=require,
            **settings,
        )
        self.gateway = Gateway(self.settings, fetcher=FakeFetcher())
        self.client = TestClient(
            self.gateway.app, base_url=f"https://{HOST}", follow_redirects=False
        )

    def ticket(self) -> str:
        return self.issuer.issue(subject="analyst-1", group="team", profile="personal")

    def signed(self, target: str, method: str = "GET", host: str = HOST, **kwargs: Any) -> Any:
        """A request the way a relay sends it."""
        headers = {
            "host": host,
            HEADER: self.signer.sign(method, host, target),
            **kwargs.pop("headers", {}),
        }
        return self.client.request(method, target, headers=headers, **kwargs)

    def sign_in(self) -> None:
        assert self.signed(f"/enter?t={self.ticket()}").status_code == 303


# --- a stranger who finds the gateway's own address ----------------------------------------------


def test_a_visitor_who_did_not_come_through_a_relay_sees_the_cover_page() -> None:
    response = Relayed().client.get("/")
    assert response.status_code == 200 and response.content == DEFAULT_PAGE
    assert "set-cookie" not in response.headers


def test_every_other_address_is_a_missing_page_for_a_visitor_who_did_not_come_through_a_relay() -> (
    None
):
    env = Relayed()
    answers = [env.client.get(path) for path in UNKNOWN]
    assert {response.status_code for response in answers} == {404}
    assert {response.content for response in answers} == {NOT_FOUND_PAGE}
    assert len({tuple(sorted(response.headers.items())) for response in answers}) == 1


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_other_methods_without_a_relay_get_the_missing_page(method: str) -> None:
    response = Relayed().client.request(method, "/open", data={"address": "x"})
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_a_valid_sign_in_link_does_nothing_without_a_relay() -> None:
    env = Relayed()
    response = env.client.get("/enter", params={"t": env.ticket()})
    assert response.status_code == 404 and "set-cookie" not in response.headers
    assert response.content == NOT_FOUND_PAGE


def test_a_session_host_without_a_relay_gets_the_missing_page() -> None:
    response = Relayed().client.get("/", headers={"host": "a" * 26 + "." + HOST})
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_the_health_check_works_from_this_machine_and_only_from_this_machine() -> None:
    env = Relayed()

    async def ask(client: tuple[str, int]) -> tuple[int, bytes]:
        return await call(env.gateway.app, "GET", "/_og/health", host=HOST, client=client)

    assert asyncio.run(ask(("127.0.0.1", 5000)))[0] == 200
    status, body = asyncio.run(ask(("203.0.113.9", 5000)))
    assert status == 404 and body == NOT_FOUND_PAGE


def test_the_metrics_page_still_needs_its_token_and_is_otherwise_missing() -> None:
    env = Relayed(metrics_token="x" * 24)
    assert env.client.get("/_og/metrics").status_code == 404
    good = env.client.get("/_og/metrics", headers={"authorization": "Bearer " + "x" * 24})
    assert good.status_code == 200


# --- a request a relay signed --------------------------------------------------------------------


def test_a_signed_sign_in_link_works_and_the_gateway_then_serves_the_signed_in_visitor() -> None:
    env = Relayed()
    first = env.signed(f"/enter?t={env.ticket()}")
    assert first.status_code == 303 and "og_session" in first.headers["set-cookie"]
    again = env.signed("/abuse")
    assert again.status_code == 200 and "abuse@example.org" in again.text


def test_a_signed_request_for_the_cover_page_gets_the_cover_page() -> None:
    response = Relayed().signed("/")
    assert response.status_code == 200 and response.content == DEFAULT_PAGE


def test_the_cookie_alone_does_not_get_a_visitor_past_a_missing_signature() -> None:
    env = Relayed()
    env.sign_in()
    assert env.client.get("/abuse").status_code == 404  # the cookie is there, the signature is not


def test_a_signature_made_for_another_address_is_a_stranger() -> None:
    env = Relayed()
    headers = {HEADER: env.signer.sign("GET", HOST, "/")}
    response = env.client.get("/abuse", headers=headers)
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_the_query_is_part_of_what_is_signed() -> None:
    env = Relayed()
    headers = {HEADER: env.signer.sign("GET", HOST, "/enter?t=a")}
    assert env.client.get("/enter?t=b", headers=headers).status_code == 404


def test_the_same_signature_cannot_be_used_for_a_second_request() -> None:
    env = Relayed()
    env.sign_in()
    headers = {HEADER: env.signer.sign("GET", HOST, "/abuse")}
    assert env.client.get("/abuse", headers=headers).status_code == 200
    repeat = env.client.get("/abuse", headers=headers)
    assert repeat.status_code == 404 and repeat.content == NOT_FOUND_PAGE


def test_a_signature_from_a_relay_that_was_taken_out_stops_working() -> None:
    env = Relayed()
    assert env.signed("/").status_code == 200
    env.relay_keys.remove("r1")
    response = env.signed("/abuse")
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_a_signature_from_any_other_key_is_a_stranger() -> None:
    env = Relayed()
    other = RelaySigner("r1", generate_key())
    response = env.client.get("/abuse", headers={HEADER: other.sign("GET", HOST, "/abuse")})
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_two_signature_headers_make_a_stranger_even_if_both_are_good() -> None:
    env = Relayed()
    env.sign_in()
    cookie = ("cookie", f"og_session={env.client.cookies['og_session']}")

    async def ask(count: int) -> tuple[int, bytes]:
        headers = [(HEADER, env.signer.sign("GET", HOST, "/abuse")) for _ in range(count)]
        return await call(env.gateway.app, "GET", "/abuse", host=HOST, headers=[*headers, cookie])

    status, _ = asyncio.run(ask(1))  # the same request with one signature is served
    assert status == 200
    status, body = asyncio.run(ask(2))
    assert status == 404 and body == NOT_FOUND_PAGE


def test_a_broken_signature_header_makes_a_stranger() -> None:
    env = Relayed()
    assert env.client.get("/abuse", headers={HEADER: "r1.abc.def"}).status_code == 404
    assert env.client.get("/abuse", headers={HEADER: ""}).status_code == 404


# --- the check a relay's operator runs -----------------------------------------------------------


def test_the_relay_check_answers_only_a_signed_request_and_names_the_key() -> None:
    env = Relayed()
    ok = env.signed("/_og/relay-check", headers={CHECK_HEADER: "1"})
    assert ok.status_code == 200 and ok.text == "ok r1\n"
    assert ok.headers["cache-control"] == "no-store"
    plain = env.client.get("/_og/relay-check")
    assert plain.status_code == 404 and plain.content == NOT_FOUND_PAGE


@pytest.mark.parametrize("path", ["/_og/relay-check", "/_og/relay%2Dcheck", "/_og/relay-check/"])
@pytest.mark.parametrize("require", [True, False])
def test_a_signed_request_without_the_operators_marker_is_not_a_relay_check(
    path: str, require: bool
) -> None:
    # Every visitor's request is signed by the relay, so the signature alone cannot be what lets
    # the check answer: a censor could ask the public domain for the path and learn the answer.
    env = Relayed(require=require)
    response = env.signed(path)
    assert response.status_code == 404 and response.content == NOT_FOUND_PAGE


def test_the_marker_must_say_exactly_what_the_relay_says() -> None:
    env = Relayed()
    for value in ("", "0", "yes", "1 "):
        response = env.signed("/_og/relay-check", headers={CHECK_HEADER: value})
        assert response.status_code == 404, value


def test_the_relay_check_only_answers_reads() -> None:
    env = Relayed()
    posted = env.signed("/_og/relay-check", method="POST", data={}, headers={CHECK_HEADER: "1"})
    assert posted.status_code != 200


# --- changing over: keys known, but a direct visit still works -----------------------------------


def test_when_relays_are_not_yet_required_a_direct_visitor_is_served_as_before() -> None:
    env = Relayed(require=False)
    signed_in = env.client.get("/enter", params={"t": env.ticket()})
    assert signed_in.status_code == 303
    assert env.client.get("/abuse").status_code == 200


def test_when_relays_are_not_yet_required_the_relay_check_still_works_for_a_relay() -> None:
    env = Relayed(require=False)
    assert env.signed("/_og/relay-check", headers={CHECK_HEADER: "1"}).text == "ok r1\n"
    assert env.client.get("/_og/relay-check").status_code != 200


def test_a_gateway_without_relay_keys_ignores_the_header() -> None:
    env = Relayed()
    plain = TestClient(
        Gateway(
            Settings(base_domain=HOST, keys=env.settings.keys, cover=Cover()), fetcher=FakeFetcher()
        ).app,
        base_url=f"https://{HOST}",
    )
    response = plain.get(
        "/_og/relay-check", headers={HEADER: env.signer.sign("GET", HOST, "/_og/relay-check")}
    )
    assert response.status_code == 404


# --- counters ------------------------------------------------------------------------------------


def test_the_gateway_counts_visits_that_did_not_come_through_a_relay() -> None:
    env = Relayed()
    for _ in range(3):
        env.client.get("/")
    env.signed("/")
    shown = env.gateway.metrics.render({}, "test")
    assert 'reason="not-relayed"} 3' in shown


# --- the settings --------------------------------------------------------------------------------


def test_relays_cannot_be_required_without_cover_mode() -> None:
    with pytest.raises(ValueError, match="cover"):
        Settings(base_domain=HOST, keys=KeyRing(), relay_keys=KeyRing(), relay_required=True)


def test_relays_cannot_be_required_without_a_key() -> None:
    with pytest.raises(ValueError, match="relay"):
        Settings(base_domain=HOST, keys=KeyRing(), cover=Cover(), relay_required=True)


def test_relays_are_not_for_personal_mode() -> None:
    with pytest.raises(ValueError, match="relay"):
        Settings(base_domain="localhost", open_mode=True, relay_keys=KeyRing())


@pytest.mark.parametrize("skew", [0, 4, 601])
def test_the_allowed_clock_difference_has_sensible_limits(skew: int) -> None:
    with pytest.raises(ValueError, match="clock"):
        Settings(
            base_domain=HOST, keys=KeyRing(), cover=Cover(), relay_keys=KeyRing(), relay_skew=skew
        )


# --- the config file -----------------------------------------------------------------------------


def with_relays(layout: Layout, extra: str = "", *, cover: bool = True, key: bool = True) -> Path:
    layout.config.write_text(
        layout.text() + ("\n[cover]\nenabled = true\n" if cover else ""), encoding="utf-8"
    )
    if key:
        (layout.root / "keys" / "relay-r1.public.pem").write_bytes(pem_public(generate_key()))
    block = "\n[relays]\n" + extra
    if key:
        block += '\n[[relays.keys]]\nid = "r1"\npublic_key_file = "keys/relay-r1.public.pem"\n'
    layout.config.write_text(layout.text() + block, encoding="utf-8")
    return layout.config


def test_the_config_file_names_the_relays_and_whether_they_are_required(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    assert load_config(layout.config).settings.relay_keys is None
    settings = load_config(with_relays(layout, "require = true\nmax_skew_seconds = 30\n")).settings
    assert settings.relay_keys is not None and settings.relay_keys.ids() == ["r1"]
    assert settings.relay_required is True and settings.relay_skew == 30


def test_relays_are_not_required_unless_the_file_says_so(tmp_path: Path) -> None:
    settings = load_config(with_relays(Layout(tmp_path))).settings
    assert settings.relay_required is False and settings.relay_skew == 60


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("unknown_setting = 1\n", "unknown_setting"),
        ('require = "yes"\n', "true or false"),
        ("max_skew_seconds = 0\n", "clock"),
        ('max_skew_seconds = "ten"\n', "whole number"),
    ],
)
def test_the_relay_settings_are_checked(tmp_path: Path, extra: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(with_relays(Layout(tmp_path), extra))


def test_a_relays_section_with_no_key_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="at least one key"):
        load_config(with_relays(Layout(tmp_path), "require = true\n", key=False))


def test_requiring_relays_without_cover_mode_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cover"):
        load_config(with_relays(Layout(tmp_path), "require = true\n", cover=False))


def test_check_config_says_which_relays_the_gateway_knows_and_whether_they_are_required(
    tmp_path: Path,
) -> None:
    lines = describe(load_config(with_relays(Layout(tmp_path), "require = true\n")))
    assert any("relays: r1" in line and "only requests a relay signed" in line for line in lines)


def test_check_config_says_when_relays_are_not_required_yet(tmp_path: Path) -> None:
    lines = describe(load_config(with_relays(Layout(tmp_path))))
    assert any("relays: r1" in line and "not required yet" in line for line in lines)


def test_check_config_says_nothing_about_relays_when_there_are_none(tmp_path: Path) -> None:
    assert not [line for line in describe(load_config(Layout(tmp_path).config)) if "relay" in line]


# --- a relay on the gateway's own machine --------------------------------------------------------


@pytest.mark.parametrize("require", [True, False])
def test_a_visitor_cannot_reach_the_health_check_through_a_relay_on_this_machine(
    require: bool,
) -> None:
    env = Relayed(require=require)

    async def health(*, through_a_relay: bool) -> tuple[int, bytes]:
        headers = {HEADER: env.signer.sign("GET", HOST, "/_og/health")} if through_a_relay else None
        return await call(
            env.gateway.app,
            "GET",
            "/_og/health",
            host=HOST,
            headers=headers,
            client=("127.0.0.1", 5000),
        )

    assert asyncio.run(health(through_a_relay=False))[0] == 200  # a supervisor on this machine
    status, body = asyncio.run(health(through_a_relay=True))  # a visitor, through a local relay
    assert status == 404 and body == NOT_FOUND_PAGE


@pytest.mark.parametrize("require", [True, False])
@pytest.mark.parametrize("kind", ["garbage", "stale", "unknown_key", "revoked"])
def test_a_request_with_a_signature_that_fails_is_still_not_the_machines_own(
    kind: str, require: bool
) -> None:
    # A relay on this machine whose clock is wrong, whose key was just revoked or not yet loaded,
    # must not be taken for the supervisor either, or its visitors would see the health check.
    env = Relayed(require=require)
    target = "/_og/health"
    if kind == "garbage":
        value = "r1.abc.def"
    elif kind == "stale":
        late = RelaySigner("r1", env.relay_key, clock=lambda: time.time() - 1000)
        value = late.sign("GET", HOST, target)
    elif kind == "unknown_key":
        value = RelaySigner("zz", generate_key()).sign("GET", HOST, target)
    else:
        value = env.signer.sign("GET", HOST, target)
        env.relay_keys.remove("r1")

    status, body = asyncio.run(
        call(
            env.gateway.app,
            "GET",
            target,
            host=HOST,
            headers={HEADER: value},
            client=("127.0.0.1", 5000),
        )
    )
    assert status == 404 and body == NOT_FOUND_PAGE


# --- a key id used twice -------------------------------------------------------------------------


def test_a_relay_key_id_used_twice_is_refused(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    path = with_relays(layout)
    block = '\n[[relays.keys]]\nid = "r1"\npublic_key_file = "keys/relay-r1.public.pem"\n'
    path.write_text(layout.text() + block, encoding="utf-8")
    with pytest.raises(ConfigError, match="used twice"):
        load_config(path)


def test_a_sign_in_key_id_used_twice_is_refused(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    line = '  { id = "signin-2026-10", public_key_file = "keys/signin-2026-10.public.pem" },'
    layout.edit(line, line + "\n" + line)
    with pytest.raises(ConfigError, match="used twice"):
        load_config(layout.config)


def test_the_supervisors_health_check_and_the_metrics_scrape_are_not_counted_as_strangers() -> None:
    env = Relayed(metrics_token="x" * 24)

    async def serve() -> list[int]:
        statuses = []
        for _ in range(3):
            status, _ = await call(
                env.gateway.app, "GET", "/_og/health", host=HOST, client=("127.0.0.1", 5000)
            )
            statuses.append(status)
        scrape = {"authorization": "Bearer " + "x" * 24}
        status, _ = await call(
            env.gateway.app,
            "GET",
            "/_og/metrics",
            host=HOST,
            headers=scrape,
            client=("198.51.100.20", 1),
        )
        return [*statuses, status]

    assert asyncio.run(serve()) == [200, 200, 200, 200]
    assert 'reason="not-relayed"} 0' in env.gateway.metrics.render({}, "test")
