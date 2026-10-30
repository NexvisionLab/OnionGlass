# SPDX-License-Identifier: AGPL-3.0-only
"""Policy, kill switches and the audit log (milestone 2, slice 1).

The tests that matter most are the last group. Each dependency of the gateway is broken in turn,
by failing, hanging or answering nonsense, and the gateway must stop serving rather than carry
on without it (property P7).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.audit import AuditError, AuditEvent, JsonLinesAudit, MemoryAudit
from onionglass.gateway import Gateway
from onionglass.killswitch import BROKEN, KillSwitch, parse_kill_file
from onionglass.onion import parse_onion_url
from onionglass.policy import (
    Decision,
    PolicyConfigError,
    PolicyRequest,
    StaticPolicy,
    address_of,
    load_address_list,
    parse_address_list,
)
from onionglass.settings import Settings
from onionglass.tickets import KeyRing, TicketIssuer, generate_key
from test_gateway import PAGE, Env, FakeFetcher, reply

OTHER = f"http://{DUCKDUCKGO}.onion/"


# --- the address lists ---------------------------------------------------------------------------


def test_address_lists_take_bare_addresses_hosts_comments_and_blank_lines() -> None:
    text = f"""
# these are blocked
{TOR_PROJECT}
{DUCKDUCKGO.upper()}.onion   # trailing comment

www.{TOR_PROJECT}.onion
"""
    assert parse_address_list(text) == {TOR_PROJECT, DUCKDUCKGO}


@pytest.mark.parametrize("bad", ["example.org", "abc", f"{TOR_PROJECT}x", "http://" + TOR_PROJECT])
def test_a_bad_line_is_an_error_that_names_the_line(bad: str) -> None:
    with pytest.raises(PolicyConfigError, match="line 2"):
        parse_address_list(f"{TOR_PROJECT}\n{bad}\n")


def test_a_list_file_that_cannot_be_read_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyConfigError):
        load_address_list(tmp_path / "missing.txt")
    with pytest.raises(PolicyConfigError):
        load_address_list(tmp_path)  # a folder
    broken = tmp_path / "bad.txt"
    broken.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(PolicyConfigError):
        load_address_list(broken)
    good = tmp_path / "good.txt"
    good.write_text(f"{TOR_PROJECT}\n", encoding="utf-8")
    assert load_address_list(good) == {TOR_PROJECT}


def _request(address: str = TOR_PROJECT) -> PolicyRequest:
    origin = parse_onion_url(f"http://{address}.onion/").origin
    return PolicyRequest(origin, "personal", "local", "local", "fetch")


def test_the_static_policy_blocks_an_address_and_all_its_subdomains() -> None:
    policy = StaticPolicy(blocked=[TOR_PROJECT])
    assert asyncio.run(policy.decide(_request(TOR_PROJECT))) == Decision.deny("blocklist")
    assert asyncio.run(policy.decide(_request(DUCKDUCKGO))).allowed
    sub = parse_onion_url(f"http://blog.{TOR_PROJECT}.onion/").origin
    request = PolicyRequest(sub, "personal", "local", "local", "fetch")
    assert not asyncio.run(policy.decide(request)).allowed


def test_the_static_policy_can_allow_only_listed_addresses() -> None:
    policy = StaticPolicy(allowed=[TOR_PROJECT])
    assert asyncio.run(policy.decide(_request(TOR_PROJECT))).allowed
    assert asyncio.run(policy.decide(_request(DUCKDUCKGO))) == Decision.deny("not-on-allowlist")
    # the blocklist wins over the allowlist
    both = StaticPolicy(blocked=[TOR_PROJECT], allowed=[TOR_PROJECT])
    assert not asyncio.run(both.decide(_request(TOR_PROJECT))).allowed
    assert address_of(f"{TOR_PROJECT}.onion") == TOR_PROJECT


# --- the kill file -------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_without_a_file_nothing_is_stopped(tmp_path: Path) -> None:
    kill = KillSwitch(tmp_path / "nothing")
    assert kill.engaged(profile="personal", address=TOR_PROJECT) is None


def test_each_scope_stops_what_it_names_and_nothing_else(tmp_path: Path) -> None:
    path = tmp_path / "kill"
    kill = KillSwitch(path)
    path.write_text("profile restricted\n", encoding="utf-8")
    assert kill.engaged(profile="restricted", address=TOR_PROJECT) == "profile:restricted"
    assert kill.engaged(profile="personal", address=TOR_PROJECT) is None
    path = tmp_path / "kill2"
    kill = KillSwitch(path)
    path.write_text(f"# blocked\nonion {DUCKDUCKGO}.onion\n", encoding="utf-8")
    assert kill.engaged(profile="personal", address=DUCKDUCKGO) == "onion"
    assert kill.engaged(profile="personal", address=TOR_PROJECT) is None
    path = tmp_path / "kill3"
    kill = KillSwitch(path)
    path.write_text("all\n", encoding="utf-8")
    assert kill.engaged(profile="anything", address=TOR_PROJECT) == "all"


def test_the_file_is_read_at_most_once_per_refresh_interval(tmp_path: Path) -> None:
    clock = Clock()
    path = tmp_path / "kill"
    kill = KillSwitch(path, clock=clock, refresh=1.0)
    assert kill.engaged(profile="p", address=TOR_PROJECT) is None
    path.write_text("all\n", encoding="utf-8")
    assert kill.engaged(profile="p", address=TOR_PROJECT) is None  # still the cached answer
    clock.now += 1.0
    assert kill.engaged(profile="p", address=TOR_PROJECT) == "all"
    path.unlink()
    clock.now += 1.0
    assert kill.engaged(profile="p", address=TOR_PROJECT) is None  # deleting the file ends it


@pytest.mark.parametrize(
    "content",
    [
        b"stop\n",
        b"all now\n",
        b"profile\n",
        b"profile a b\n",
        b"onion nonsense\n",
        b"\xff\xfe",
        b"a" * 70000,
    ],
)
def test_a_file_nobody_understands_stops_everything(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "kill"
    path.write_bytes(content)
    assert KillSwitch(path).engaged(profile="personal", address=TOR_PROJECT) == BROKEN


def test_a_kill_path_that_cannot_be_read_stops_everything(tmp_path: Path) -> None:
    assert KillSwitch(tmp_path).engaged(profile="personal", address=TOR_PROJECT) == BROKEN


def test_the_parser_reports_a_clean_file_as_not_broken() -> None:
    assert not parse_kill_file("# nothing\n\n").broken


# --- the audit log -------------------------------------------------------------------------------


def _event(**changes: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "kind": "allowed",
        "action": "fetch",
        "rule": "static",
        "profile": "personal",
        "group": "team",
        "subject": "analyst-1",
        "origin": f"http://{TOR_PROJECT}.onion:80",
        "path": "/secret/page?token=abc",
        "status": 200,
        "time": 1_700_000_000.0,
    }
    values.update(changes)
    return AuditEvent(**values)


def test_audit_lines_hold_the_origin_by_default_and_never_the_path(tmp_path: Path) -> None:
    sink = JsonLinesAudit(tmp_path / "audit.log")
    record = json.loads(sink.render(_event()))
    assert record["target"] == f"http://{TOR_PROJECT}.onion:80"
    assert "secret" not in json.dumps(record) and "token" not in json.dumps(record)
    assert record["time"] == "2023-11-14T22:13:20Z"
    assert set(record) == {
        "time", "kind", "action", "rule", "profile", "group", "subject", "status", "target",
    }  # fmt: skip


def test_audit_address_forms(tmp_path: Path) -> None:
    full = json.loads(JsonLinesAudit(tmp_path / "a", address_form="full").render(_event()))
    assert full["target"].endswith("/secret/page?token=abc")
    none = json.loads(JsonLinesAudit(tmp_path / "b", address_form="none").render(_event()))
    assert "target" not in none
    salt = b"s" * 32
    one = json.loads(
        JsonLinesAudit(tmp_path / "c", address_form="hash", salt=salt).render(_event())
    )
    two = json.loads(
        JsonLinesAudit(tmp_path / "d", address_form="hash", salt=salt).render(_event())
    )
    other = json.loads(
        JsonLinesAudit(tmp_path / "e", address_form="hash", salt=b"t" * 32).render(_event())
    )
    assert one["target"] == two["target"] and one["target"] != other["target"]
    assert TOR_PROJECT not in one["target"] and re.fullmatch(r"h:[0-9a-f]{16}", one["target"])
    with pytest.raises(ValueError, match="address form"):
        JsonLinesAudit(tmp_path / "f", address_form="everything")  # type: ignore[arg-type]


def test_a_hostile_subject_stays_on_one_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    sink = JsonLinesAudit(path)
    asyncio.run(sink.write(_event(subject='x"}\n{"kind":"forged"\r\n' + "y" * 1000)))
    lines = path.read_bytes().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["kind"] == "allowed" and len(json.loads(lines[0])["subject"]) <= 200


def test_concurrent_writes_make_whole_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    sink = JsonLinesAudit(path)

    async def burst() -> None:
        await asyncio.gather(*(sink.write(_event(subject=f"s{i}")) for i in range(60)))

    asyncio.run(burst())
    subjects = {
        json.loads(line)["subject"] for line in path.read_text(encoding="utf-8").splitlines()
    }
    assert subjects == {f"s{i}" for i in range(60)}


def test_a_log_that_cannot_be_written_raises(tmp_path: Path) -> None:
    sink = JsonLinesAudit(tmp_path)  # a folder cannot be appended to
    with pytest.raises(AuditError):
        asyncio.run(sink.write(_event()))


@pytest.mark.skipif(os.name == "nt", reason="file modes are not meaningful on Windows")
def test_the_audit_file_is_private_to_its_owner(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    asyncio.run(JsonLinesAudit(path).write(_event()))
    assert (path.stat().st_mode & 0o077) == 0


# --- in the gateway ------------------------------------------------------------------------------


def serve(**settings: Any) -> Env:
    return Env(lambda _r: reply("<p>hello</p>"), **settings)


def test_the_audit_log_records_the_open_and_the_fetch_but_no_content() -> None:
    audit = MemoryAudit()
    env = serve(audit=audit)
    label = env.open()
    assert env.get(label).status_code == 200
    kinds = [(e.kind, e.action) for e in audit.events]
    assert kinds == [("allowed", "open"), ("allowed", "fetch"), ("response", "fetch")]
    assert audit.events[-1].status == 200
    assert all(e.profile == "personal" and e.origin.endswith(":80") for e in audit.events)
    assert "hello" not in repr(audit.events)


def test_a_blocked_address_is_refused_before_anything_is_created_or_fetched() -> None:
    audit = MemoryAudit()
    env = serve(policy=StaticPolicy(blocked=[TOR_PROJECT]), audit=audit)
    response = env.client.post("/open", data={"address": PAGE})
    assert response.status_code == 403
    assert "does not open that address" in response.text
    assert "blocklist" not in response.text.lower()  # the visitor is never told which rule
    assert "set-cookie" not in response.headers  # no session was made
    assert env.fetcher.requests == []
    assert [(e.kind, e.rule) for e in audit.events] == [("refused", "blocklist")]


def test_a_link_to_a_blocked_address_is_refused_when_followed() -> None:
    page = f'<a href="{OTHER}x">there</a>'
    env = Env(lambda _r: reply(page), policy=StaticPolicy(blocked=[DUCKDUCKGO]))
    label = env.open()
    body = env.get(label).text
    link = re.search(r'href="(http://[a-z2-7]{26}\.localhost:\d+/x)"', body)
    assert link, body
    target = Env.label_in(link.group(1))
    before = len(env.fetcher.requests)
    assert env.get(target, "/x").status_code == 403
    assert len(env.fetcher.requests) == before


def test_an_allowlist_policy_refuses_everything_else() -> None:
    env = serve(policy=StaticPolicy(allowed=[DUCKDUCKGO]))
    assert env.client.post("/open", data={"address": PAGE}).status_code == 403
    assert env.client.post("/open", data={"address": OTHER}).status_code == 303


def test_a_ticket_for_a_blocked_onion_is_refused_too() -> None:
    key = generate_key()
    keys = KeyRing()
    keys.add("k1", key.public_key())
    issuer = TicketIssuer(key, "k1", "onionglass")
    settings = Settings(
        base_domain="gw.example",
        keys=keys,
        policy=StaticPolicy(blocked=[TOR_PROJECT]),
        confirm_sign_in=False,
    )
    gateway = Gateway(settings, fetcher=FakeFetcher())
    client = TestClient(gateway.app, base_url="https://gw.example", follow_redirects=False)
    ticket = issuer.issue(subject="a", group="g", profile="personal", onion=TOR_PROJECT)
    assert client.get("/enter", params={"t": ticket}).status_code == 403


def test_the_policy_is_told_who_but_never_the_visitors_address() -> None:
    seen: list[PolicyRequest] = []

    class Spy:
        async def decide(self, request: PolicyRequest) -> Decision:
            seen.append(request)
            return Decision.allow("spy")

    env = serve(policy=Spy())
    label = env.open()
    env.get(label)
    assert {r.action for r in seen} == {"open", "fetch"}
    assert all(r.profile == "personal" and r.subject == "local" for r in seen)
    assert not any(hasattr(r, "address") or hasattr(r, "ip") for r in seen)


# --- break each dependency in turn ---------------------------------------------------------------


class Failing:
    async def decide(self, request: PolicyRequest) -> Decision:
        raise RuntimeError("the policy service is down")


class Hanging:
    async def decide(self, request: PolicyRequest) -> Decision:
        await asyncio.sleep(30)
        return Decision.allow()


class Nonsense:
    async def decide(self, request: PolicyRequest) -> Any:
        return True  # not a Decision


class BrokenAudit:
    def __init__(self, *, only: str | None = None) -> None:
        self.only = only
        self.written: list[AuditEvent] = []

    async def write(self, event: AuditEvent) -> None:
        if self.only is None or event.kind == self.only:
            raise AuditError("the audit service is down")
        self.written.append(event)


class HangingAudit:
    async def write(self, event: AuditEvent) -> None:
        await asyncio.sleep(30)


@pytest.mark.parametrize(
    "policy", [Failing(), Hanging(), Nonsense()], ids=["fails", "hangs", "nonsense"]
)
def test_when_the_policy_cannot_answer_nothing_is_opened_or_fetched(policy: Any) -> None:
    audit = MemoryAudit()
    env = serve(policy=policy, audit=audit, hook_timeout=0.05)
    response = env.client.post("/open", data={"address": PAGE})
    assert response.status_code == 503 and "could not check" in response.text
    assert env.fetcher.requests == []
    assert [e.rule for e in audit.events] == ["policy-unavailable"]


def test_when_the_policy_dies_mid_session_the_next_fetch_is_refused() -> None:
    state = {"up": True}

    class Flaky:
        async def decide(self, request: PolicyRequest) -> Decision:
            if not state["up"]:
                raise RuntimeError("down")
            return Decision.allow()

    env = serve(policy=Flaky())
    label = env.open()
    assert env.get(label).status_code == 200
    state["up"] = False
    before = len(env.fetcher.requests)
    assert env.get(label).status_code == 503
    assert len(env.fetcher.requests) == before


@pytest.mark.parametrize("sink", [BrokenAudit(), HangingAudit()], ids=["fails", "hangs"])
def test_when_the_audit_log_is_down_nothing_is_opened_or_fetched(sink: Any) -> None:
    env = serve(audit=sink, hook_timeout=0.05)
    assert env.client.post("/open", data={"address": PAGE}).status_code == 503
    assert env.fetcher.requests == []


def test_when_the_audit_log_dies_mid_session_the_next_fetch_is_refused() -> None:
    audit = BrokenAudit(only="allowed")
    audit.only = "never"  # works at first
    env = serve(audit=audit)
    label = env.open()
    assert env.get(label).status_code == 200
    audit.only = "allowed"
    before = len(env.fetcher.requests)
    assert env.get(label).status_code == 503
    assert len(env.fetcher.requests) == before


def test_when_the_outcome_cannot_be_recorded_the_reply_is_withheld_and_cookies_dropped() -> None:
    audit = BrokenAudit(only="response")
    cookies = {"on": True}

    def handler(request: Any) -> Any:
        extra = (("set-cookie", "sid=secret; Path=/"),) if cookies["on"] else ()
        return reply("<p>the reply</p>", headers=extra)

    env = Env(handler, audit=audit)
    label = env.open()
    response = env.get(label)
    assert response.status_code == 503 and "the reply" not in response.text
    cookies["on"] = False
    audit.only = "never"
    assert env.get(label).status_code == 200
    assert "Cookie" not in env.fetcher.requests[-1].headers  # the withheld cookie was not stored


def _kill(tmp_path: Path, content: str, clock: Clock | None = None) -> tuple[KillSwitch, Path]:
    path = tmp_path / "kill"
    path.write_text(content, encoding="utf-8")
    return KillSwitch(path, clock=clock or Clock()), path


def test_kill_all_stops_opening_and_fetching(tmp_path: Path) -> None:
    clock = Clock()
    audit = MemoryAudit()
    kill, path = _kill(tmp_path, "", clock)
    env = serve(kill=kill, audit=audit)
    label = env.open()
    assert env.get(label).status_code == 200
    path.write_text("all\n", encoding="utf-8")
    clock.now += 2
    before = len(env.fetcher.requests)
    stopped = env.get(label)
    assert stopped.status_code == 503 and "paused" in stopped.text.lower()
    assert env.client.post("/open", data={"address": OTHER}).status_code == 503
    assert len(env.fetcher.requests) == before
    assert audit.events[-1].rule == "kill:all"
    # the health check stays up, so a supervisor does not restart a gateway that was stopped on purpose
    assert env.client.get("/_og/health").status_code == 200
    path.unlink()
    clock.now += 2
    assert env.get(label).status_code == 200


def test_kill_by_profile_and_by_onion(tmp_path: Path) -> None:
    clock = Clock()
    kill, path = _kill(tmp_path, "profile personal\n", clock)
    env = serve(kill=kill)
    assert env.client.post("/open", data={"address": PAGE}).status_code == 503
    path.write_text("profile somebody-else\n", encoding="utf-8")
    clock.now += 2
    assert env.client.post("/open", data={"address": PAGE}).status_code == 303
    path.write_text(f"onion {TOR_PROJECT}\n", encoding="utf-8")
    clock.now += 2
    assert env.client.post("/open", data={"address": PAGE}).status_code == 503
    assert env.client.post("/open", data={"address": OTHER}).status_code == 303


def test_a_broken_kill_file_stops_the_gateway(tmp_path: Path) -> None:
    kill, _ = _kill(tmp_path, "this is a typo\n")
    env = serve(kill=kill)
    assert env.client.post("/open", data={"address": PAGE}).status_code == 503
    assert env.fetcher.requests == []
    assert KillSwitch(tmp_path).engaged(profile="p", address=TOR_PROJECT) == BROKEN
