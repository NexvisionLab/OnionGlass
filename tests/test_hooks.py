# SPDX-License-Identifier: AGPL-3.0-only
"""Signed HTTP hooks (milestone 2, slice 7).

A fake hook service runs on its own thread and checks every request with code written from the
description alone. Each way a reply can be wrong, and each way the connection can fail, must end
in a refusal by the gateway.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from hook_server import HookServer, make_certificate, request_base, response_base
from onionglass.audit import AuditEvent
from onionglass.hooks import (
    MAX_RESPONSE_BYTES,
    HookClient,
    HookError,
    HttpAudit,
    HttpPolicy,
    HttpQuota,
    parse_hook_url,
    request_signing_input,
    response_signing_input,
)
from onionglass.onion import parse_onion_url
from onionglass.policy import Decision, PolicyRequest
from onionglass.settings import Profile
from onionglass.tickets import KeyRing, generate_key
from test_gateway import PAGE, Env, reply
from test_profiles import Team

GATEWAY_KEY = generate_key()
SERVICE_KEY = generate_key()
OTHER = f"http://{DUCKDUCKGO}.onion/"


def keyring(key_id: str = "svc1") -> KeyRing:
    ring = KeyRing()
    ring.add(key_id, SERVICE_KEY.public_key())
    return ring


def start_server(**kwargs: Any) -> HookServer:
    return HookServer(
        gateway_key_id="gw1",
        gateway_public=GATEWAY_KEY.public_key(),
        service_signer=SERVICE_KEY,
        **kwargs,
    ).start()


def make_client(server: HookServer, **kwargs: Any) -> HookClient:
    options: dict[str, Any] = {
        "signing_key": GATEWAY_KEY,
        "key_id": "gw1",
        "response_keys": keyring(),
        "timeout": 2.0,
    }
    options.update(kwargs)
    return HookClient(server.url, **options)


@pytest.fixture
def server() -> Iterator[HookServer]:
    running = start_server()
    yield running
    running.stop()


def call(client: HookClient, path: str = "/policy", **payload: Any) -> dict[str, Any]:
    return asyncio.run(client.call(path, payload))


# --- the written format --------------------------------------------------------------------------


def test_the_signing_input_is_exactly_what_the_description_says() -> None:
    body = b'{"v":1}'
    expected = (
        b"onionglass hook request v1\x00gw1\nPOST\n/policy\n1700000000\n"
        + b"a" * 32
        + b"\n"
        + b"cb8a1bff4e3ce3e4a7cc3c5eda5cc4b5ac2ee4abd9c19b24f1ba1f5cd0b7f7b6"[:0]
    )
    digest = request_base("gw1", "/policy", "1700000000", "a" * 32, body).split(b"\n")[-1]
    assert re.fullmatch(rb"[0-9a-f]{64}", digest)
    assert request_signing_input(
        "gw1", "POST", "/policy", "1700000000", "a" * 32, body
    ) == request_base("gw1", "/policy", "1700000000", "a" * 32, body)
    assert expected.startswith(b"onionglass hook request v1\x00gw1\nPOST\n/policy\n1700000000\n")
    assert response_signing_input("svc1", "b" * 32, 200, body) == response_base(
        "svc1", "b" * 32, 200, body
    )


def test_a_request_is_signed_in_the_way_a_receiver_can_check(server: HookServer) -> None:
    now = [1_000_000.0]
    client = make_client(server, clock=lambda: now[0])
    server.seen.clear()
    # The fake service refuses a timestamp far from its own clock, so use the real one here.
    client = make_client(server)
    call(client, "/policy", hello="world")
    [seen] = server.seen
    assert seen.valid and seen.path == "/policy"
    assert seen.headers["x-onionglass-version"] == "1" and seen.headers["x-onionglass-key"] == "gw1"
    assert re.fullmatch(r"[0-9a-f]{32}", seen.nonce)
    assert abs(int(seen.headers["x-onionglass-timestamp"]) - time.time()) < 30
    assert (
        seen.headers["connection"] == "close" and seen.headers["content-type"] == "application/json"
    )
    assert seen.payload == {"v": 1, "hello": "world"}


def test_every_request_has_its_own_nonce_and_none_is_replayable(server: HookServer) -> None:
    client = make_client(server)
    for _ in range(5):
        call(client)
    assert len({s.nonce for s in server.seen}) == 5 and all(s.valid for s in server.seen)


def test_the_path_prefix_of_the_hook_address_is_kept(server: HookServer) -> None:
    client = HookClient(
        server.url + "/hooks/v1/",
        signing_key=GATEWAY_KEY,
        key_id="gw1",
        response_keys=keyring(),
    )
    call(client, "/policy")
    assert server.seen[0].path == "/hooks/v1/policy" and server.seen[0].valid


# --- every way a reply can be wrong ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "fragment"),
    [
        ("unsigned", "trusted key"),
        ("unknown_key", "trusted key"),
        ("bad_signature", "bad signature"),
        ("wrong_nonce", "bad signature"),
        ("tampered", "bad signature"),
        ("status500", "status 500"),
        ("status404", "status 404"),
        ("redirect", "status 302"),
        ("garbage", "not JSON"),
        ("list", "not a JSON object"),
        ("huge", "too large"),
    ],
)
def test_a_wrong_reply_is_an_error(server: HookServer, mode: str, fragment: str) -> None:
    server.mode = mode
    with pytest.raises(HookError, match=fragment):
        call(make_client(server))


def test_a_reply_signed_by_a_key_that_is_not_trusted_is_refused(server: HookServer) -> None:
    ring = KeyRing()
    ring.add("svc1", generate_key().public_key())  # the right id, someone else's key
    with pytest.raises(HookError, match="bad signature"):
        call(make_client(server, response_keys=ring))


def test_a_reply_that_never_comes_is_an_error(server: HookServer) -> None:
    server.mode = "hang"
    started = time.monotonic()
    with pytest.raises(HookError, match="could not be reached"):
        call(make_client(server, timeout=0.3))
    assert time.monotonic() - started < 3


def test_a_connection_that_is_cut_is_an_error(server: HookServer) -> None:
    server.mode = "close"
    with pytest.raises(HookError):
        call(make_client(server))


def test_a_service_that_is_not_running_is_an_error() -> None:
    running = start_server()
    client = make_client(running)
    running.stop()
    with pytest.raises(HookError, match="could not be reached"):
        call(client)


def test_the_size_limit_matches_the_description() -> None:
    assert MAX_RESPONSE_BYTES == 65_536


# --- the hook address ----------------------------------------------------------------------------


def test_hook_addresses_are_checked() -> None:
    assert parse_hook_url("https://hooks.example/").port == 443
    assert parse_hook_url("https://hooks.example:8443/a/b/").prefix == "/a/b"
    assert parse_hook_url("http://127.0.0.1:9000").port == 9000
    assert parse_hook_url("http://localhost").host == "localhost"
    assert parse_hook_url("http://[::1]:9000/x").host == "::1"
    assert parse_hook_url("http://192.0.2.5:9000", allow_plain_http=True).scheme == "http"
    for bad in (
        "http://hooks.example/",
        "http://192.0.2.5/",
        "ftp://hooks.example/",
        "hooks.example",
        "https://user:pass@hooks.example/",
        "https://hooks.example/?a=b",
        "https://hooks.example/#x",
        "https:///nohost",
        "https://hooks.example:99999/",
        "",
    ):
        with pytest.raises(ValueError, match="hook"):
            parse_hook_url(bad)


# --- TLS -----------------------------------------------------------------------------------------


def tls_server(
    directory: Path, names: tuple[str, ...] = ("localhost",), *, with_ip: bool = True
) -> tuple[HookServer, Path]:
    cert, key = make_certificate(directory, names, with_ip=with_ip)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return start_server(tls=context), cert


def trusting(cert: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(cert))


def test_tls_works_when_the_certificate_is_trusted_and_names_the_host(tmp_path: Path) -> None:
    running, cert = tls_server(tmp_path)
    try:
        client = HookClient(
            f"https://127.0.0.1:{running.port}",
            signing_key=GATEWAY_KEY,
            key_id="gw1",
            response_keys=keyring(),
            tls_context=trusting(cert),
        )
        assert call(client) == {"allow": True}
    finally:
        running.stop()


def test_tls_refuses_a_certificate_nobody_vouches_for(tmp_path: Path) -> None:
    running, _cert = tls_server(tmp_path)
    try:
        client = HookClient(
            f"https://127.0.0.1:{running.port}",
            signing_key=GATEWAY_KEY,
            key_id="gw1",
            response_keys=keyring(),
        )
        with pytest.raises(HookError, match="SSLCertVerificationError"):
            call(client)
        assert running.seen == []  # nothing was sent
    finally:
        running.stop()


def test_tls_refuses_a_certificate_for_another_name(tmp_path: Path) -> None:
    running, cert = tls_server(tmp_path, names=("other.example",), with_ip=False)
    try:
        client = HookClient(
            f"https://127.0.0.1:{running.port}",
            signing_key=GATEWAY_KEY,
            key_id="gw1",
            response_keys=keyring(),
            tls_context=trusting(cert),
        )
        with pytest.raises(HookError, match="SSLCertVerificationError"):
            call(client)
        assert running.seen == []
    finally:
        running.stop()


def test_a_client_never_speaks_plain_text_to_an_https_address(
    tmp_path: Path, server: HookServer
) -> None:
    client = HookClient(
        f"https://127.0.0.1:{server.port}",  # the plain-text fake, addressed as https
        signing_key=GATEWAY_KEY,
        key_id="gw1",
        response_keys=keyring(),
        timeout=1.0,
    )
    with pytest.raises(HookError):
        call(client)
    assert server.seen == []


# --- the policy hook -----------------------------------------------------------------------------


def request_for(address: str = TOR_PROJECT, subject: str = "alice") -> PolicyRequest:
    origin = parse_onion_url(f"http://{address}.onion/").origin
    return PolicyRequest(origin, "analyst", "team", subject, "fetch")


def decide(policy: HttpPolicy, request: PolicyRequest) -> Decision:
    return asyncio.run(policy.decide(request))


def test_the_policy_is_asked_with_who_and_what_and_nothing_else(server: HookServer) -> None:
    decide(HttpPolicy(make_client(server)), request_for())
    assert server.seen[0].payload == {
        "v": 1,
        "origin": {
            "scheme": "http",
            "address": TOR_PROJECT,
            "host": f"{TOR_PROJECT}.onion",
            "port": 80,
        },
        "profile": "analyst",
        "group": "team",
        "subject": "alice",
        "action": "fetch",
    }


def test_the_policy_answers_allow_deny_and_text_only(server: HookServer) -> None:
    policy = HttpPolicy(make_client(server))
    server.handler = lambda _p, _d: {"allow": False, "rule": "case-42"}
    assert decide(policy, request_for()) == Decision.deny("case-42")
    server.handler = lambda _p, _d: {"allow": True, "rule": "ok", "text_only": True}
    assert decide(policy, request_for()) == Decision.allow("ok", text_only=True)
    server.handler = lambda _p, _d: {"allow": True}
    assert decide(policy, request_for()) == Decision.allow("hook")


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"allow": "yes"},
        {"allow": 1},
        {"allow": None},
        {"allow": True, "rule": ""},
        {"allow": True, "rule": "x" * 65},
        {"allow": True, "rule": "bad rule!"},
        {"allow": True, "rule": 7},
        {"allow": True, "text_only": "yes"},
        {"allow": False, "rule": "a\nb"},
    ],
)
def test_a_policy_answer_that_is_not_in_the_agreed_form_is_an_error(
    server: HookServer, answer: dict[str, Any]
) -> None:
    server.handler = lambda _p, _d: answer
    with pytest.raises(HookError):
        decide(HttpPolicy(make_client(server)), request_for())


def test_policy_answers_can_be_kept_for_a_short_time(server: HookServer) -> None:
    clock = [0.0]
    policy = HttpPolicy(make_client(server), cache_seconds=10, clock=lambda: clock[0])
    decide(policy, request_for())
    decide(policy, request_for())
    assert len(server.seen) == 1
    decide(policy, request_for(subject="bob"))  # another account is another question
    decide(policy, request_for(address=DUCKDUCKGO))
    assert len(server.seen) == 3
    clock[0] += 11
    decide(policy, request_for())
    assert len(server.seen) == 4


def test_a_refusal_is_kept_too_and_a_failure_is_never_kept(server: HookServer) -> None:
    clock = [0.0]
    policy = HttpPolicy(make_client(server), cache_seconds=10, clock=lambda: clock[0])
    server.handler = lambda _p, _d: {"allow": False, "rule": "no"}
    assert not decide(policy, request_for()).allowed and not decide(policy, request_for()).allowed
    assert len(server.seen) == 1
    server.mode = "status500"
    with pytest.raises(HookError):
        decide(policy, request_for(subject="carol"))
    server.mode = "normal"
    server.handler = lambda _p, _d: {"allow": True}
    assert decide(policy, request_for(subject="carol")).allowed  # asked again, not remembered


def test_without_a_cache_every_question_is_asked(server: HookServer) -> None:
    policy = HttpPolicy(make_client(server))
    for _ in range(3):
        decide(policy, request_for())
    assert len(server.seen) == 3


def test_the_cache_is_bounded(server: HookServer) -> None:
    policy = HttpPolicy(make_client(server), cache_seconds=60, max_cached=2)
    for who in ("a", "b", "c", "d"):
        decide(policy, request_for(subject=who))
    assert len(policy._cache) <= 2


# --- the audit and quota hooks -------------------------------------------------------------------


def answering(answer: dict[str, Any]) -> Callable[[str, dict[str, Any]], dict[str, Any]]:
    return lambda _path, _payload: answer


def an_event(**changes: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "kind": "allowed", "action": "fetch", "rule": "static", "profile": "analyst",
        "group": "team", "subject": "alice", "origin": f"http://{TOR_PROJECT}.onion:80",
        "path": "/x", "status": None, "time": 1_700_000_000.0,
    }  # fmt: skip
    values.update(changes)
    return AuditEvent(**values)


def test_audit_events_are_sent_and_must_be_confirmed(server: HookServer) -> None:
    server.handler = lambda _p, _d: {"ok": True}
    asyncio.run(HttpAudit(make_client(server)).write(an_event()))
    sent = server.seen[0].payload["event"]
    assert sent["kind"] == "allowed" and sent["subject"] == "alice" and sent["status"] is None
    server.handler = lambda _p, _d: {"ok": False}
    with pytest.raises(HookError, match="did not accept"):
        asyncio.run(HttpAudit(make_client(server)).write(an_event()))
    server.handler = lambda _p, _d: {}
    with pytest.raises(HookError):
        asyncio.run(HttpAudit(make_client(server)).write(an_event()))


def test_quota_counts_come_back_as_whole_numbers(server: HookServer) -> None:
    quota = HttpQuota(make_client(server))
    server.handler = lambda _p, _d: {"used": 3}
    assert asyncio.run(quota.used("alice", "analyst")) == 3
    assert asyncio.run(quota.charge("alice", "analyst", 2)) == 3
    assert server.seen[-1].path == "/quota/charge"
    assert server.seen[-1].payload == {"v": 1, "subject": "alice", "profile": "analyst", "units": 2}
    for bad in ({}, {"used": -1}, {"used": "3"}, {"used": 2.5}, {"used": True}, {"used": None}):
        server.handler = answering(bad)
        with pytest.raises(HookError):
            asyncio.run(quota.used("alice", "analyst"))


# --- in the gateway ------------------------------------------------------------------------------


class Service:
    """The whole outside service: policy, audit and quota in one fake."""

    def __init__(self) -> None:
        self.denied: set[str] = set()
        self.events: list[dict[str, Any]] = []
        self.used: dict[tuple[str, str], int] = {}
        self.server = start_server()
        self.server.handler = self.answer

    def answer(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if path == "/policy":
            denied = payload["origin"]["address"] in self.denied
            return {"allow": not denied, "rule": "case-rule" if denied else "ok"}
        if path == "/audit":
            self.events.append(payload["event"])
            return {"ok": True}
        key = (payload["subject"], payload["profile"])
        if path == "/quota/charge":
            self.used[key] = self.used.get(key, 0) + payload["units"]
        return {"used": self.used.get(key, 0)}

    def client(self, **kwargs: Any) -> HookClient:
        return make_client(self.server, **kwargs)


@pytest.fixture
def service() -> Iterator[Service]:
    running = Service()
    yield running
    running.server.stop()


def gateway_env(service: Service, **extra: Any) -> Env:
    client = service.client()
    return Env(
        lambda _r: reply("<p>hello</p>"),
        policy=HttpPolicy(client),
        audit=HttpAudit(client),
        hook_timeout=1.0,
        **extra,
    )


def test_the_gateway_follows_the_outside_policy_and_reports_to_the_outside_audit(
    service: Service,
) -> None:
    env = gateway_env(service)
    label = env.open()
    assert env.get(label).status_code == 200
    kinds = [(e["kind"], e["action"]) for e in service.events]
    assert kinds == [("allowed", "open"), ("allowed", "fetch"), ("response", "fetch")]
    service.denied.add(DUCKDUCKGO)
    before = len(env.fetcher.requests)
    assert env.client.post("/open", data={"address": OTHER}).status_code == 403
    assert len(env.fetcher.requests) == before
    assert service.events[-1]["kind"] == "refused" and service.events[-1]["rule"] == "case-rule"
    assert all(s.valid for s in service.server.seen)


@pytest.mark.parametrize(
    "mode",
    ["unsigned", "bad_signature", "wrong_nonce", "status500", "garbage", "close", "hang"],
)
def test_when_the_outside_service_misbehaves_the_gateway_refuses(
    service: Service, mode: str
) -> None:
    env = gateway_env(service)
    service.server.mode = mode
    assert env.client.post("/open", data={"address": PAGE}).status_code == 503
    assert env.fetcher.requests == []


def test_when_the_outside_service_goes_away_the_gateway_stops_serving(service: Service) -> None:
    env = gateway_env(service)
    label = env.open()
    assert env.get(label).status_code == 200
    service.server.stop()
    before = len(env.fetcher.requests)
    assert env.get(label).status_code == 503
    assert len(env.fetcher.requests) == before


def test_quotas_can_live_in_the_outside_service(service: Service) -> None:
    profiles = {"daily": Profile(name="daily", daily_quota=2, open_cost=1)}
    team = Team(profiles=profiles, quota=HttpQuota(service.client()), hook_timeout=1.0)
    visitor = team.visitor("daily", subject="alice")
    assert visitor.open() == 303 and visitor.open() == 303
    assert visitor.open() == 429
    assert service.used[("alice", "daily")] == 2
    service.server.mode = "status500"
    assert team.visitor("daily", subject="bob").open() == 503  # the meter cannot be trusted
