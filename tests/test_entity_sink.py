# SPDX-License-Identifier: AGPL-3.0-only
"""Sending the entities a page names to another system, only when the visitor presses the button.

Nothing leaves the gateway on its own. The visitor asks, the gateway sends what it found itself
on the page they are looking at, and every send is on the audit record.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from helpers import DUCKDUCKGO, TOR_PROJECT
from hook_server import HookServer
from onionglass.audit import MemoryAudit
from onionglass.config import ConfigError, load_config
from onionglass.entities import Entity, EntityBatch, SinkError
from onionglass.hooks import HookClient, HttpEntitySink
from onionglass.settings import Profile, Settings
from test_config import Layout, add_hooks, without_sections
from test_entities import GENESIS, SEGWIT
from test_gateway import APEX, PAGE, Env, reply
from test_hooks import GATEWAY_KEY, keyring, make_client, start_server
from test_policy_ops import BrokenAudit

SAME = {"sec-fetch-site": "same-origin", "origin": f"http://{APEX}"}
PAGE_TEXT = (
    "<title>Private title Zebra</title>"
    f"<p>Pay {GENESIS} or {SEGWIT}, write to Ops@Example.org</p>"
    "<p>Some sentence from the page that must not be sent on.</p>"
)
SENDER = Profile(name="personal", show_entities=True, send_entities=True)


class MemorySink:
    """Keeps what it is sent. ``fail`` is how many sends to refuse before it starts working."""

    def __init__(self, fail: int = 0) -> None:
        self.batches: list[EntityBatch] = []
        self.fail = fail

    async def send(self, batch: EntityBatch) -> None:
        if self.fail > 0:
            self.fail -= 1
            raise SinkError("the case system is down")
        self.batches.append(batch)


def served(sink: MemorySink | None, profile: Profile = SENDER, **extra: Any) -> Env:
    extra.setdefault("audit", MemoryAudit())  # every send must be on record
    return Env(lambda _r: reply(PAGE_TEXT), profile=profile, entity_sink=sink, **extra)


def look(env: Env, address: str = PAGE) -> str:
    label = env.open(address)
    assert env.get(label, headers={"sec-fetch-dest": "iframe"}).status_code == 200
    return label


def send(env: Env, headers: dict[str, str] | None = None, **body: str) -> Any:
    return env.client.post(
        "/_og/send-entities", data=body, headers=SAME if headers is None else headers
    )


def test_the_visitor_sends_what_the_gateway_found_on_the_page() -> None:
    sink = MemorySink()
    env = served(sink)
    look(env)
    response = send(env)
    assert response.status_code == 200 and json.loads(response.text) == {
        "message": "Sent 3 entities."
    }
    assert len(sink.batches) == 1
    batch = sink.batches[0]
    assert (batch.subject, batch.group, batch.profile) == ("local", "local", "personal")
    assert {(e.kind, e.value) for e in batch.entities} == {
        ("bitcoin", GENESIS),
        ("bitcoin", SEGWIT),
        ("email", "ops@example.org"),
    }
    assert batch.origin == f"http://{TOR_PROJECT}.onion:80" and batch.time > 0


def test_the_page_text_and_title_are_not_sent() -> None:
    sink = MemorySink()
    env = served(sink)
    look(env)
    send(env)
    text = repr(sink.batches[0])
    assert "Zebra" not in text and "sentence from the page" not in text


def test_the_visitor_cannot_choose_what_is_sent() -> None:
    sink = MemorySink()
    env = served(sink)
    look(env)
    send(
        env, entities="bitcoin:made-up", value="invented@example.org", origin="http://evil.example"
    )
    sent = {(e.kind, e.value) for e in sink.batches[0].entities}
    assert ("email", "invented@example.org") not in sent
    assert all("made-up" not in value for _, value in sent)
    assert sink.batches[0].origin.endswith(".onion:80")


def test_a_profile_without_the_switch_cannot_send() -> None:
    sink = MemorySink()
    env = served(sink, profile=Profile(name="personal", show_entities=True))
    look(env)
    assert send(env).status_code == 403
    assert sink.batches == []


def test_with_no_sink_configured_the_button_and_the_endpoint_are_absent() -> None:
    env = Env(lambda _r: reply(PAGE_TEXT), profile=Profile(name="personal", show_entities=True))
    label = look(env)
    assert send(env).status_code == 403
    viewer = env.client.get("/view", params={"l": label, "p": "/"})
    assert 'id="entities-send"' not in viewer.text


def test_the_viewer_has_the_send_button_only_when_it_may_be_used() -> None:
    env = served(MemorySink())
    label = look(env)
    viewer = env.client.get("/view", params={"l": label, "p": "/"})
    assert 'id="entities-send"' in viewer.text
    quiet = served(MemorySink(), profile=Profile(name="personal", show_entities=True))
    other = look(quiet)
    assert 'id="entities-send"' not in quiet.client.get("/view", params={"l": other, "p": "/"}).text


def test_a_request_from_another_site_or_without_a_session_is_refused() -> None:
    sink = MemorySink()
    env = served(sink)
    look(env)
    for headers in ({"sec-fetch-site": "cross-site"}, {"origin": "https://evil.example"}):
        assert send(env, headers).status_code == 403
    stranger = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    assert stranger.post("/_og/send-entities", headers=SAME).status_code == 403
    assert sink.batches == []


def test_there_is_nothing_to_send_before_a_page_has_been_viewed() -> None:
    sink = MemorySink()
    env = served(sink)
    env.open()
    response = send(env)
    assert response.status_code == 400 and "nothing" in json.loads(response.text)["message"].lower()
    assert sink.batches == []


def test_a_page_that_names_nothing_sends_nothing() -> None:
    sink = MemorySink()
    env = Env(
        lambda _r: reply("<title>x</title><p>plain</p>"),
        profile=SENDER,
        entity_sink=sink,
        audit=MemoryAudit(),
    )
    look(env)
    assert send(env).status_code == 400
    assert sink.batches == []


def test_a_session_can_send_only_so_many_times() -> None:
    sink = MemorySink()
    env = served(sink, max_entity_sends_per_session=2)
    look(env)
    assert [send(env).status_code for _ in range(3)] == [200, 200, 429]
    assert len(sink.batches) == 2


def test_a_send_that_fails_is_reported_and_does_not_use_up_the_allowance() -> None:
    sink = MemorySink(fail=1)
    env = served(sink, max_entity_sends_per_session=1)
    look(env)
    failed = send(env)
    assert failed.status_code == 502 and "could not be sent" in json.loads(failed.text)["message"]
    assert send(env).status_code == 200
    assert len(sink.batches) == 1


def test_every_send_is_on_the_audit_record_before_it_happens() -> None:
    audit = MemoryAudit()
    sink = MemorySink()
    env = served(sink, audit=audit)
    look(env)
    send(env)
    sent = [e for e in audit.events if e.kind == "entities"]
    assert len(sent) == 1 and sent[0].action == "send" and sent[0].rule == "3"
    assert sent[0].profile == "personal" and sent[0].subject == "local"


def test_if_the_audit_record_cannot_be_written_nothing_is_sent() -> None:
    sink = MemorySink()
    env = served(sink, audit=BrokenAudit(only="entities"))
    look(env)
    response = send(env)
    assert response.status_code == 503
    assert sink.batches == []


def test_a_sink_that_hangs_does_not_hang_the_gateway() -> None:
    class Hanging:
        async def send(self, batch: EntityBatch) -> None:
            await asyncio.sleep(30)

    env = Env(
        lambda _r: reply(PAGE_TEXT),
        profile=SENDER,
        entity_sink=Hanging(),
        hook_timeout=0.05,
        audit=MemoryAudit(),
    )
    look(env)
    assert send(env).status_code == 502


def test_each_site_is_sent_as_its_own_batch() -> None:
    sink = MemorySink()
    env = served(sink)
    look(env)
    look(env, f"http://{DUCKDUCKGO}.onion/")
    send(env)
    assert [b.origin for b in sink.batches] == [f"http://{DUCKDUCKGO}.onion:80"]


# --- settings and the config file ----------------------------------------------------------------


def test_sending_needs_the_panel() -> None:
    with pytest.raises(ValueError, match="show_entities"):
        Profile(name="x", send_entities=True)


def test_a_profile_that_sends_needs_a_sink() -> None:
    with pytest.raises(ValueError, match="sink"):
        Settings(base_domain="localhost", open_mode=True, profile=SENDER)


def test_the_send_limit_must_be_above_zero() -> None:
    with pytest.raises(ValueError, match="max_entity_sends_per_session"):
        Settings(base_domain="localhost", open_mode=True, max_entity_sends_per_session=0)


def test_the_restricted_preset_does_not_send() -> None:
    assert Profile.restricted().send_entities is False


def sink_config(layout: Layout, *, use: str) -> Settings:
    layout.config.write_text(without_sections(layout.text(), "audit"), encoding="utf-8")
    add_hooks(layout, use=use)
    layout.edit("[profiles.analyst]", "[profiles.analyst]\nsend_entities = true")
    return load_config(layout.config).settings


def test_the_config_file_can_turn_on_the_sink_and_the_switch(tmp_path: Path) -> None:
    settings = sink_config(Layout(tmp_path), use='["audit", "entities"]')
    assert isinstance(settings.entity_sink, HttpEntitySink)
    assert settings.profile_named("analyst").send_entities is True  # type: ignore[union-attr]
    assert settings.profile.send_entities is False


def test_a_profile_that_sends_but_has_no_sink_in_the_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="sink"):
        sink_config(Layout(tmp_path), use='["audit"]')


def test_the_send_limit_can_be_set_in_the_config_file(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    assert load_config(layout.config).settings.max_entity_sends_per_session == 20
    layout.edit("max_entity_sends_per_session = 20", "max_entity_sends_per_session = 3")
    assert load_config(layout.config).settings.max_entity_sends_per_session == 3


# --- the signed HTTP form ------------------------------------------------------------------------


@pytest.fixture
def server() -> Iterator[HookServer]:
    running = start_server()
    running.handler = lambda _p, _d: {"ok": True}
    yield running
    running.stop()


def a_batch(**changes: Any) -> EntityBatch:
    fields: dict[str, Any] = {
        "subject": "alice",
        "group": "team",
        "profile": "analyst",
        "origin": f"http://{TOR_PROJECT}.onion:80",
        "path": "/page?x=1",
        "entities": (Entity("bitcoin", GENESIS), Entity("email", "ops@example.org")),
        "time": 1_700_000_000.0,
    }
    fields.update(changes)
    return EntityBatch(**fields)


def test_the_service_gets_who_sent_it_where_from_and_the_entities(server: HookServer) -> None:
    sink = HttpEntitySink(make_client(server), address_form="full")
    asyncio.run(sink.send(a_batch()))
    seen = server.seen[0]
    assert seen.path == "/entities" and seen.valid
    sent = seen.payload["batch"]
    assert sent["subject"] == "alice" and sent["group"] == "team" and sent["profile"] == "analyst"
    assert (sent["origin"], sent["path"]) == (f"http://{TOR_PROJECT}.onion:80", "/page?x=1")
    assert sent["entities"] == [
        {"kind": "bitcoin", "value": GENESIS},
        {"kind": "email", "value": "ops@example.org"},
    ]
    assert sent["time"] == 1_700_000_000


@pytest.mark.parametrize(
    ("form", "origin", "path"),
    [
        ("full", f"http://{TOR_PROJECT}.onion:80", "/page?x=1"),
        ("origin", f"http://{TOR_PROJECT}.onion:80", ""),
        ("none", "", ""),
    ],
)
def test_the_site_is_named_only_in_the_chosen_form(
    server: HookServer, form: Any, origin: str, path: str
) -> None:
    asyncio.run(HttpEntitySink(make_client(server), address_form=form).send(a_batch()))
    sent = server.seen[0].payload["batch"]
    assert (sent["origin"], sent["path"]) == (origin, path)


def test_the_default_form_drops_the_path(server: HookServer) -> None:
    asyncio.run(HttpEntitySink(make_client(server)).send(a_batch()))
    assert server.seen[0].payload["batch"]["path"] == ""


def test_a_keyed_hash_replaces_the_address_when_hashing(server: HookServer) -> None:
    sink = HttpEntitySink(make_client(server), address_form="hash", salt=b"s" * 32)
    asyncio.run(sink.send(a_batch()))
    sent = server.seen[0].payload["batch"]
    assert sent["origin"].startswith("h:") and TOR_PROJECT not in json.dumps(sent)


@pytest.mark.parametrize("reply_body", [{"ok": False}, {}, {"ok": "yes"}])
def test_an_answer_that_is_not_a_clear_yes_is_a_failure(
    server: HookServer, reply_body: dict[str, Any]
) -> None:
    server.handler = lambda _p, _d: reply_body
    with pytest.raises(SinkError):
        asyncio.run(HttpEntitySink(make_client(server)).send(a_batch()))


def test_a_service_that_is_down_is_a_failure() -> None:
    client = HookClient(
        "http://127.0.0.1:9",
        signing_key=GATEWAY_KEY,
        key_id="gw1",
        response_keys=keyring(),
        allow_plain_http=True,
        timeout=0.5,
    )
    with pytest.raises(SinkError):
        asyncio.run(HttpEntitySink(client).send(a_batch()))


def test_an_unknown_address_form_is_refused(server: HookServer) -> None:
    with pytest.raises(ValueError, match="address form"):
        HttpEntitySink(make_client(server), address_form="everything")  # type: ignore[arg-type]
