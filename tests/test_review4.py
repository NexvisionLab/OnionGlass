# SPDX-License-Identifier: AGPL-3.0-only
"""Findings from the fourth independent review, each shown by a test that failed first.

1. A translation holding text that cannot be encoded made the page an internal error.
2. The send limit could be passed by sends that arrive together, and failed sends were free.
3. Sending entities ignored the kill switch, the held list and the policy.
4. A translation service or entity sink could be set up with no audit log to record sends.
5. Translated text had no limit on the size of the page it made.
6. Collecting text for translation cost time in proportion to how deeply it was nested.
7. Translation had no limit on how many pages were being translated at once.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from helpers import TOR_PROJECT, FakeMapper, base_url
from onionglass.audit import MemoryAudit
from onionglass.config import ConfigError, load_config
from onionglass.entities import EntityBatch, SinkError
from onionglass.held import HeldList
from onionglass.killswitch import KillSwitch
from onionglass.policy import Decision, PolicyRequest
from onionglass.rewrite.html import (
    NOT_TRANSLATED_NOTICE,
    TRANSLATED_NOTICE,
    HtmlOptions,
    rewrite_html,
)
from onionglass.settings import Profile, Settings
from onionglass.translate import LibreTranslate, TranslateError
from test_config import Layout
from test_entity_sink import MemorySink, look, served
from test_gateway import APEX, PORT, Env, reply
from test_translate import Service
from test_translate_page import PAGE, FakeTranslator

SAME = {"sec-fetch-site": "same-origin", "origin": f"http://{APEX}"}
ALLOWED = Profile(name="personal", allow_translate=True)


async def call(
    app: Any,
    method: str,
    path: str,
    *,
    host: str = APEX,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    client: tuple[str, int] = ("127.0.0.1", 50000),
) -> tuple[int, bytes]:
    """One request straight into the application, so that several can be in flight together."""
    pairs = [(b"host", host.encode("ascii")), (b"content-length", str(len(body)).encode("ascii"))]
    pairs += [(k.lower().encode("ascii"), v.encode("ascii")) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": pairs,
        "server": ("localhost", PORT),
        "client": client,
    }
    sent = [False]
    status: list[int] = []
    parts: list[bytes] = []

    async def receive() -> dict[str, Any]:
        if not sent[0]:
            sent[0] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])
        elif message["type"] == "http.response.body":
            parts.append(message.get("body", b""))

    await app(scope, receive, send)
    return status[0], b"".join(parts)


def signed_in(env: Env) -> dict[str, str]:
    cookie = env.client.cookies.get("og_session")
    assert cookie
    return {**SAME, "cookie": f"og_session={cookie}"}


# --- 1. text that cannot be encoded ---------------------------------------------------------------


def test_a_translation_with_text_that_cannot_be_encoded_leaves_the_page_in_its_own_language() -> (
    None
):
    broken = chr(0xD800)
    env = Env(
        lambda _r: reply(PAGE),
        profile=ALLOWED,
        translator=FakeTranslatorReturning(broken),
        audit=MemoryAudit(),
    )
    label = env.open()
    env.client.post("/_og/translate", data={"on": "1"}, headers=SAME)
    response = env.get(label, headers={"sec-fetch-dest": "iframe"})
    assert response.status_code == 200
    assert "Le chat" in response.text and NOT_TRANSLATED_NOTICE in response.text


class FakeTranslatorReturning:
    def __init__(self, text: str) -> None:
        self.text = text

    async def translate(self, texts: list[str]) -> list[str]:
        return [self.text for _ in texts]


def test_the_client_refuses_a_translation_that_cannot_be_encoded() -> None:
    running = Service()
    try:
        slash = chr(92)
        running.handler = lambda _b, _s: (
            200,
            b'{"translatedText": ["' + slash.encode() + b'ud800"]}',
        )
        client = LibreTranslate(running.url, timeout=3.0)
        with pytest.raises(TranslateError, match="text"):
            asyncio.run(client.translate(["x"]))
    finally:
        running.stop()


# --- 2. the send limit ----------------------------------------------------------------------------


class SlowSink:
    """A sink that takes time to answer, as one reached over a network does."""

    def __init__(self, *, fail: bool = False, delay: float = 0.15) -> None:
        self.attempts = 0
        self.batches: list[EntityBatch] = []
        self.fail = fail
        self.delay = delay

    async def send(self, batch: EntityBatch) -> None:
        self.attempts += 1
        await asyncio.sleep(self.delay)
        if self.fail:
            raise SinkError("the case system is down")
        self.batches.append(batch)


def test_sends_that_arrive_together_cannot_pass_the_limit() -> None:
    sink = SlowSink()
    env = served(sink, max_entity_sends_per_session=2)  # type: ignore[arg-type]
    look(env)
    headers = signed_in(env)

    async def burst() -> list[int]:
        posts = [
            call(env.gateway.app, "POST", "/_og/send-entities", headers=headers) for _ in range(8)
        ]
        return [status for status, _ in await asyncio.gather(*posts)]

    codes = asyncio.run(burst())
    assert codes.count(200) == 2 and sink.attempts == 2
    assert all(code == 429 for code in codes if code != 200)


def test_sends_that_keep_failing_are_cut_off_too() -> None:
    sink = SlowSink(fail=True, delay=0)
    env = served(sink, max_entity_sends_per_session=2)  # type: ignore[arg-type]
    look(env)
    codes = [env.client.post("/_og/send-entities", headers=SAME).status_code for _ in range(30)]
    assert codes.count(502) == sink.attempts and sink.attempts <= 8
    assert codes[-1] == 429


def test_a_send_that_fails_still_does_not_use_up_the_allowance() -> None:
    sink = MemorySink(fail=3)
    env = served(sink, max_entity_sends_per_session=1)
    look(env)
    codes = [env.client.post("/_og/send-entities", headers=SAME).status_code for _ in range(4)]
    assert codes == [502, 502, 502, 200]


def test_the_profile_request_limit_applies_to_sending() -> None:
    sink = MemorySink()
    profile = Profile(
        name="personal", show_entities=True, send_entities=True, max_requests_per_minute=3
    )
    env = served(sink, profile=profile)
    look(env)  # the open and the page view use two of the three
    first = env.client.post("/_og/send-entities", headers=SAME)
    second = env.client.post("/_og/send-entities", headers=SAME)
    assert (first.status_code, second.status_code) == (200, 429)
    assert len(sink.batches) == 1


class SlowReports:
    def __init__(self) -> None:
        self.received = 0

    async def submit(self, address: str, category: str, subject: str) -> str:
        await asyncio.sleep(0.1)
        self.received += 1
        return "received"


def test_reports_that_arrive_together_cannot_pass_the_limit() -> None:
    queue = SlowReports()
    env = Env(lambda _r: reply("<p>x</p>"), reports=queue, max_reports_per_session=2)
    env.get(env.open(), headers={"sec-fetch-dest": "iframe"})
    headers = {**signed_in(env), "content-type": "application/x-www-form-urlencoded"}

    async def burst() -> list[int]:
        posts = [
            call(env.gateway.app, "POST", "/_og/report", headers=headers, body=b"category=scam")
            for _ in range(8)
        ]
        return [status for status, _ in await asyncio.gather(*posts)]

    codes = asyncio.run(burst())
    assert codes.count(200) == 2 and queue.received == 2


# --- 3. the kill switch, the held list and the policy ---------------------------------------------


def stopped_after_viewing(tmp_path: Path, how: str) -> tuple[Env, MemorySink]:
    sink = MemorySink()
    kill = KillSwitch(tmp_path / "kill", refresh=0.0)
    held = HeldList(tmp_path / "held.txt", refresh=0.0)
    env = served(sink, kill=kill, held=held)
    look(env)
    if how == "kill":
        (tmp_path / "kill").write_text("all\n", encoding="utf-8")
    elif how == "held":
        line = f"{TOR_PROJECT} 2026-10-31T00:00:00Z reviewing\n"
        (tmp_path / "held.txt").write_text(line, encoding="utf-8")
    return env, sink


@pytest.mark.parametrize(("how", "status"), [("kill", 503), ("held", 403)])
def test_a_site_that_is_stopped_after_it_was_viewed_cannot_have_its_entities_sent(
    tmp_path: Path, how: str, status: int
) -> None:
    env, sink = stopped_after_viewing(tmp_path, how)
    assert env.client.post("/_og/send-entities", headers=SAME).status_code == status
    assert sink.batches == []


def test_a_site_that_is_not_stopped_can_still_have_its_entities_sent(tmp_path: Path) -> None:
    env, sink = stopped_after_viewing(tmp_path, "none")
    assert env.client.post("/_og/send-entities", headers=SAME).status_code == 200
    assert len(sink.batches) == 1


def test_a_policy_is_asked_about_the_site_before_entities_are_sent() -> None:
    asked: list[tuple[str, str]] = []

    class Spy:
        async def decide(self, request: PolicyRequest) -> Decision:
            asked.append((request.origin.host.address, request.action))
            return Decision.deny("blocked") if len(asked) > 2 else Decision.allow("ok")

    sink = MemorySink()
    env = served(sink, policy=Spy())
    look(env)  # the open and the first fetch are allowed
    response = env.client.post("/_og/send-entities", headers=SAME)
    assert response.status_code == 403 and sink.batches == []
    assert asked[-1] == (TOR_PROJECT, "fetch")  # an action a policy service already knows


# --- 4. every send needs an audit log -------------------------------------------------------------


def test_an_entity_sink_needs_an_audit_log() -> None:
    with pytest.raises(ValueError, match="audit"):
        Settings(base_domain="localhost", open_mode=True, entity_sink=MemorySink())


def test_a_translator_needs_an_audit_log() -> None:
    with pytest.raises(ValueError, match="audit"):
        Settings(base_domain="localhost", open_mode=True, translator=FakeTranslator())


def test_with_an_audit_log_both_are_accepted() -> None:
    Settings(
        base_domain="localhost",
        open_mode=True,
        audit=MemoryAudit(),
        translator=FakeTranslator(),
        entity_sink=MemorySink(),
    )


def test_the_config_file_refuses_translation_without_an_audit_log(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    start = text.index("[audit]")
    end = text.index("[held]")
    block = '\n[translate]\nurl = "https://translate.internal.example.net"\n'
    layout.config.write_text(text[:start] + text[end:] + block, encoding="utf-8")
    with pytest.raises(ConfigError, match="audit"):
        load_config(layout.config)


# --- 5. the size of a translated page -------------------------------------------------------------


def test_a_translation_that_would_make_an_enormous_page_is_not_used() -> None:
    paragraph = "x" * 4000
    page = "".join(f"<p>{paragraph}</p>" for _ in range(20))
    ampersands = FakeTranslatorReturning("&" * 80_000)
    env = Env(
        lambda _r: reply(page),
        profile=Profile(name="personal", allow_translate=True, max_page_bytes=1_000_000),
        translator=ampersands,
        audit=MemoryAudit(),
    )
    label = env.open()
    env.client.post("/_og/translate", data={"on": "1"}, headers=SAME)
    response = env.get(label, headers={"sec-fetch-dest": "iframe"})
    assert response.status_code == 200 and NOT_TRANSLATED_NOTICE in response.text
    assert len(response.content) <= 1_000_000


def test_the_client_refuses_far_more_text_than_it_sent() -> None:
    running = Service()
    try:
        running.handler = lambda body, _s: (
            200,
            (
                '{"translatedText": ['
                + ",".join('"' + "y" * 90_000 + '"' for _ in body["q"])
                + "]}"
            ).encode(),
        )
        client = LibreTranslate(running.url, timeout=10.0)
        texts = ["z" * 5000 for _ in range(60)]
        with pytest.raises(TranslateError, match="too much"):
            asyncio.run(client.translate(texts))
    finally:
        running.stop()


# --- 6. the cost of collecting text ---------------------------------------------------------------


def test_collecting_text_does_not_cost_more_the_deeper_it_is_nested() -> None:
    depth, texts = 380, 14_000
    page = "<div>" * depth + "".join(f"<p>word {n}</p>" for n in range(texts)) + "</div>" * depth

    def best(options: HtmlOptions) -> float:
        times = []
        for _ in range(3):
            started = time.perf_counter()
            rewrite_html(page.encode(), base_url(), FakeMapper(), options=options)
            times.append(time.perf_counter() - started)
        return min(times)

    plain = best(HtmlOptions(reader=True))
    slotted = best(HtmlOptions(reader=True, translate_slots=True))
    assert slotted < 4 * plain + 0.25


# --- 7. how many pages are translated at once -----------------------------------------------------


class Gate:
    def __init__(self) -> None:
        self.calls = 0

    async def translate(self, texts: list[str]) -> list[str]:
        self.calls += 1
        await asyncio.sleep(0.3)
        return [f"TR({t})" for t in texts]


def test_only_so_many_pages_are_translated_at_once() -> None:
    gate = Gate()
    env = Env(
        lambda _r: reply(PAGE),
        profile=ALLOWED,
        translator=gate,
        audit=MemoryAudit(),
        max_concurrent_translations=1,
        max_fetches_per_session=6,
    )
    label = env.open()
    env.client.post("/_og/translate", data={"on": "1"}, headers=SAME)
    host = f"{label}.localhost:{PORT}"
    headers = {"sec-fetch-site": "same-origin", "sec-fetch-dest": "iframe"}

    async def pair() -> list[bytes]:
        gets = [call(env.gateway.app, "GET", "/", host=host, headers=headers) for _ in range(3)]
        return [body for _, body in await asyncio.gather(*gets)]

    bodies = [body.decode("utf-8") for body in asyncio.run(pair())]
    assert gate.calls == 1
    assert sum(TRANSLATED_NOTICE in body for body in bodies) == 1
    assert sum(NOT_TRANSLATED_NOTICE in body for body in bodies) == 2
    assert all("Le chat" in body or "TR(Le chat)" in body for body in bodies)


def test_the_translation_limit_must_be_above_zero() -> None:
    with pytest.raises(ValueError, match="max_concurrent_translations"):
        Settings(base_domain="localhost", open_mode=True, max_concurrent_translations=0)


def test_the_translation_limit_can_be_set_in_the_config_file(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    assert load_config(layout.config).settings.max_concurrent_translations == 8
    layout.edit("max_concurrent_translations = 8", "max_concurrent_translations = 3")
    assert load_config(layout.config).settings.max_concurrent_translations == 3
