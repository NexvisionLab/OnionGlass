# SPDX-License-Identifier: AGPL-3.0-only
"""Translating a page: the text a visitor reads goes to the operator's service and comes back.

Only the visible text is sent. What comes back is put in as text, never as markup. If the service
cannot help, the page is shown in its own language, with a note saying so.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from helpers import TOR_PROJECT, FakeMapper, assert_safe_output, base_url
from onionglass.audit import MemoryAudit
from onionglass.config import ConfigError, load_config
from onionglass.rewrite.html import (
    MAX_TRANSLATED_TEXT,
    MAX_TRANSLATION_SLOTS,
    NOT_TRANSLATED_NOTICE,
    PARTLY_TRANSLATED_NOTICE,
    TRANSLATED_NOTICE,
    HtmlOptions,
    RewriteResult,
    add_notice,
    fill_slots,
    rewrite_html,
)
from onionglass.settings import Profile, Settings
from onionglass.translate import LibreTranslate, TranslateError
from test_config import Layout, secret
from test_entities import GENESIS
from test_gateway import APEX, Env, reply
from test_policy_ops import BrokenAudit
from test_translate import Service

MAPPER = FakeMapper()
BASE = base_url()
PAGE = (
    "<title>Titre secret</title><h1>Bonjour</h1>"
    "<p>Le chat <b>noir</b> dort. <a href='/suite'>Lire la suite</a></p>"
    "<pre>code reste</pre><p>12345</p><ul><li>Un</li><li>Deux</li></ul>"
)
TEXTS = ["Bonjour", "Le chat", "noir", "dort.", "Lire la suite", "Un", "Deux"]
SAME = {"sec-fetch-site": "same-origin", "origin": f"http://{APEX}"}


def slotted(page: str = PAGE, **options: Any) -> RewriteResult:
    return rewrite_html(
        page.encode("utf-8"),
        BASE,
        MAPPER,
        options=HtmlOptions(reader=True, translate_slots=True, **options),
    )


def marked(texts: list[str]) -> list[str]:
    return [f"TR({t})" for t in texts]


# --- the rewriter step ---------------------------------------------------------------------------


def test_the_visible_text_is_collected_in_order_and_taken_out_of_the_page() -> None:
    result = slotted()
    assert list(result.slots) == TEXTS
    body = result.body.decode("utf-8")
    assert "Le chat" not in body and result.slot_token in body


def test_filling_the_slots_puts_the_translations_in_with_the_spacing_kept() -> None:
    result = slotted()
    filled = fill_slots(result.body.decode("utf-8"), result, marked(TEXTS))
    assert "<b>TR(noir)</b> TR(dort.) <a" in filled
    assert "<p>TR(Le chat) <b>" in filled
    assert result.slot_token not in filled
    assert_safe_output(filled.encode("utf-8"), MAPPER)


def test_filling_with_nothing_gives_the_original_text_back() -> None:
    result = slotted()
    filled = fill_slots(result.body.decode("utf-8"), result, None)
    assert "<p>Le chat <b>noir</b> dort. <a" in filled and result.slot_token not in filled


def test_code_numbers_the_title_and_the_notice_are_not_collected() -> None:
    result = slotted()
    joined = " ".join(result.slots)
    for text in ("code reste", "12345", "Titre secret", "Reader view"):
        assert text not in joined
    assert "code reste" in result.body.decode("utf-8")  # shown as it was


def test_text_in_nested_code_stays_as_it_was() -> None:
    result = slotted("<p>avant</p><pre><code>ligne un</code></pre><kbd>Ctrl</kbd>")
    assert list(result.slots) == ["avant"]


def test_a_translation_with_markup_in_it_is_text_not_markup() -> None:
    result = slotted()
    hostile = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", *TEXTS[2:]]
    filled = fill_slots(result.body.decode("utf-8"), result, hostile)
    assert "<script>" not in filled and "<img" not in filled
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in filled
    assert_safe_output(filled.encode("utf-8"), MAPPER)


def test_a_translation_that_looks_like_a_slot_is_not_filled_again() -> None:
    result = slotted()
    tricky = [f"{result.slot_token}1e", *TEXTS[1:]]
    filled = fill_slots(result.body.decode("utf-8"), result, tricky)
    assert filled.count(f"{result.slot_token}1e") == 1


def test_the_wrong_number_of_translations_is_refused() -> None:
    result = slotted()
    with pytest.raises(ValueError, match="one text for each"):
        fill_slots(result.body.decode("utf-8"), result, ["only one"])


def test_each_rewrite_has_its_own_token() -> None:
    assert slotted().slot_token != slotted().slot_token


def test_a_page_with_more_text_than_the_limit_is_cut_and_says_so() -> None:
    page = "".join(f"<p>mot {n}</p>" for n in range(MAX_TRANSLATION_SLOTS + 50))
    result = slotted(page)
    assert len(result.slots) == MAX_TRANSLATION_SLOTS and result.slots_cut is True
    filled = fill_slots(result.body.decode("utf-8"), result, None)
    assert f"mot {MAX_TRANSLATION_SLOTS + 49}" in filled  # the rest is still on the page


def test_one_very_long_text_is_left_alone() -> None:
    result = slotted("<p>" + "a" * (MAX_TRANSLATED_TEXT + 1) + "</p><p>court</p>")
    assert list(result.slots) == ["court"] and result.slots_cut is True


def test_slots_only_exist_in_the_reader_form() -> None:
    plain = rewrite_html(PAGE.encode(), BASE, MAPPER, options=HtmlOptions(translate_slots=True))
    assert plain.slots == () and "Le chat" in plain.body.decode("utf-8")
    ordinary = rewrite_html(PAGE.encode(), BASE, MAPPER, options=HtmlOptions(reader=True))
    assert ordinary.slots == () and "Le chat" in ordinary.body.decode("utf-8")


def test_a_notice_goes_into_the_reader_banner() -> None:
    result = slotted()
    document = add_notice(result.body.decode("utf-8"), TRANSLATED_NOTICE)
    assert TRANSLATED_NOTICE in document and document.index(TRANSLATED_NOTICE) < document.index(
        result.slot_token
    )


# --- through the gateway -------------------------------------------------------------------------


class FakeTranslator:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.calls: list[list[str]] = []

    async def translate(self, texts: list[str]) -> list[str]:
        self.calls.append(list(texts))
        if self.mode == "fail":
            raise TranslateError("the service is down")
        if self.mode == "hang":
            await asyncio.sleep(30)
        if self.mode == "short":
            return texts[:-1]
        if self.mode == "markup":
            return [f"<script>x</script>{t}" for t in texts]
        return marked(texts)


ALLOWED = Profile(name="personal", allow_translate=True)


def served(translator: FakeTranslator | None, profile: Profile = ALLOWED, **extra: Any) -> Env:
    extra.setdefault("audit", MemoryAudit())  # every send must be on record
    return Env(lambda _r: reply(PAGE), profile=profile, translator=translator, **extra)


def switch(client: TestClient, on: bool, headers: dict[str, str] | None = None) -> Any:
    return client.post(
        "/_og/translate",
        data={"on": "1" if on else "0"},
        headers=SAME if headers is None else headers,
    )


def page(env: Env, label: str) -> str:
    response = env.get(label, headers={"sec-fetch-dest": "iframe"})
    assert response.status_code == 200
    return str(response.text)


def test_a_visitor_can_turn_translation_on_and_off() -> None:
    translator = FakeTranslator()
    env = served(translator)
    label = env.open()
    assert "Le chat" in page(env, label)
    on = switch(env.client, True)
    assert on.status_code == 200 and json.loads(on.text) == {"translate": True}
    text = page(env, label)
    assert "TR(Le chat)" in text and TRANSLATED_NOTICE in text and "<form" not in text
    switch(env.client, False)
    assert "Le chat" in page(env, label) and "TR(" not in page(env, label)


def test_only_the_visible_text_goes_to_the_service() -> None:
    translator = FakeTranslator()
    env = served(translator)
    label = env.open()
    switch(env.client, True)
    page(env, label)
    assert translator.calls == [TEXTS]
    sent = json.dumps(translator.calls)
    for private in (TOR_PROJECT, "Titre secret", "Reader view", "/suite", label, "localhost"):
        assert private not in sent


def test_the_page_is_in_the_reader_form_whatever_the_reader_button_says() -> None:
    env = served(FakeTranslator())
    label = env.open()
    switch(env.client, True)
    assert 'name="og-view"' in page(env, label)
    assert json.loads(env.client.get("/_og/current").text)["translate"] is True


def test_a_translation_with_markup_in_it_cannot_run_anything() -> None:
    env = served(FakeTranslator("markup"))
    label = env.open()
    switch(env.client, True)
    text = page(env, label)
    assert "<script>x" not in text and "&lt;script&gt;x&lt;/script&gt;Bonjour" in text


@pytest.mark.parametrize("mode", ["fail", "short"])
def test_when_the_service_cannot_help_the_page_is_shown_as_it_was(mode: str) -> None:
    translator = FakeTranslator(mode)
    env = served(translator)
    label = env.open()
    switch(env.client, True)
    text = page(env, label)
    assert "Le chat <b>noir</b>" in text and NOT_TRANSLATED_NOTICE in text
    assert "TR(" not in text and "og-t" not in text


def test_a_service_that_hangs_does_not_hang_the_page() -> None:
    env = served(FakeTranslator("hang"), translate_timeout=0.1)
    label = env.open()
    switch(env.client, True)
    text = page(env, label)
    assert "Le chat" in text and NOT_TRANSLATED_NOTICE in text


def test_the_page_says_when_only_part_of_it_was_translated() -> None:
    many = "".join(f"<p>mot {n}</p>" for n in range(MAX_TRANSLATION_SLOTS + 5))
    env = Env(
        lambda _r: reply(many), profile=ALLOWED, translator=FakeTranslator(), audit=MemoryAudit()
    )
    label = env.open()
    switch(env.client, True)
    text = page(env, label)
    assert PARTLY_TRANSLATED_NOTICE in text and "TR(mot 0)" in text


def test_every_translation_is_on_the_audit_record_before_it_is_sent() -> None:
    audit = MemoryAudit()
    translator = FakeTranslator()
    env = served(translator, audit=audit)
    label = env.open()
    switch(env.client, True)
    page(env, label)
    events = [e for e in audit.events if e.kind == "translate"]
    assert len(events) == 1 and events[0].action == "translate"
    assert events[0].rule == str(sum(len(t) for t in TEXTS))


def test_if_the_audit_record_cannot_be_written_nothing_is_sent() -> None:
    translator = FakeTranslator()
    env = served(translator, audit=BrokenAudit(only="translate"))
    label = env.open()
    switch(env.client, True)
    text = page(env, label)
    assert translator.calls == [] and "Le chat" in text and NOT_TRANSLATED_NOTICE in text


def test_a_profile_without_the_switch_cannot_turn_it_on() -> None:
    translator = FakeTranslator()
    env = served(translator, profile=Profile(name="personal", allow_translate=False))
    label = env.open()
    assert switch(env.client, True).status_code == 403
    assert "Le chat" in page(env, label) and translator.calls == []


def test_with_no_service_configured_there_is_no_button_and_no_switch() -> None:
    env = Env(lambda _r: reply(PAGE), profile=Profile(name="personal"))
    label = env.open()
    assert switch(env.client, True).status_code == 403
    assert (
        'id="translate-toggle"' not in env.client.get("/view", params={"l": label, "p": "/"}).text
    )


def test_the_viewer_has_the_button_only_when_it_may_be_used() -> None:
    env = served(FakeTranslator())
    label = env.open()
    assert 'id="translate-toggle"' in env.client.get("/view", params={"l": label, "p": "/"}).text
    quiet = served(FakeTranslator(), profile=Profile(name="personal"))
    other = quiet.open()
    assert (
        'id="translate-toggle"' not in quiet.client.get("/view", params={"l": other, "p": "/"}).text
    )


def test_a_request_from_another_site_or_without_a_session_is_refused() -> None:
    env = served(FakeTranslator())
    label = env.open()
    for headers in ({"sec-fetch-site": "cross-site"}, {"origin": "https://evil.example"}):
        assert switch(env.client, True, headers).status_code == 403
    stranger = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    assert switch(stranger, True).status_code == 403
    assert "Le chat" in page(env, label)


def test_a_bad_value_is_refused_and_changes_nothing() -> None:
    env = served(FakeTranslator())
    label = env.open()
    switch(env.client, True)
    for body in ({"on": "maybe"}, {}, {"on": "1" * 5000}):
        assert env.client.post("/_og/translate", data=body, headers=SAME).status_code in (400, 413)
    assert "TR(Le chat)" in page(env, label)


def test_one_visitors_choice_does_not_reach_another() -> None:
    env = served(FakeTranslator())
    env.open()
    switch(env.client, True)
    other = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    opened = other.post("/open", data={"address": f"http://{TOR_PROJECT}.onion/"})
    label = Env.viewer_label(opened.headers["location"])
    headers = {
        "host": f"{label}.localhost:8080",
        "sec-fetch-site": "same-origin",
        "sec-fetch-dest": "iframe",
    }
    assert "Le chat" in other.get("/", headers=headers).text


def test_entities_are_still_found_in_the_original_text() -> None:
    env = Env(
        lambda _r: reply(f"<title>x</title><p>Payez {GENESIS} maintenant</p>"),
        profile=Profile(name="personal", allow_translate=True, show_entities=True),
        translator=FakeTranslator(),
        audit=MemoryAudit(),
    )
    label = env.open()
    switch(env.client, True)
    page(env, label)
    shown = json.loads(env.client.get("/_og/current").text)["entities"]
    assert {"kind": "bitcoin", "value": GENESIS} in shown


def test_the_reader_button_still_works_alongside() -> None:
    env = served(FakeTranslator())
    label = env.open()
    env.client.post("/_og/reader", data={"on": "1"}, headers=SAME)
    assert 'name="og-view"' in page(env, label) and "Le chat" in page(env, label)


# --- settings and the config file ----------------------------------------------------------------


def test_a_profile_that_translates_needs_a_translator() -> None:
    with pytest.raises(ValueError, match="translator"):
        Settings(base_domain="localhost", open_mode=True, profile=ALLOWED)


@pytest.mark.parametrize("value", [0, -1, 1000])
def test_the_translate_time_limit_is_checked(value: float) -> None:
    with pytest.raises(ValueError, match="translate_timeout"):
        Settings(base_domain="localhost", open_mode=True, translate_timeout=value)


def test_the_restricted_preset_does_not_translate() -> None:
    assert Profile.restricted().allow_translate is False


TRANSLATE_BLOCK = """
[translate]
url = "https://translate.internal.example.net"
target = "de"
timeout = 12
"""


def with_translation(layout: Layout, extra: str = "") -> Any:
    layout.config.write_text(layout.text() + TRANSLATE_BLOCK + extra, encoding="utf-8")
    layout.edit("[profiles.analyst]", "[profiles.analyst]\nallow_translate = true")
    return load_config(layout.config).settings


def test_the_config_file_turns_translation_on(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    assert load_config(layout.config).settings.translator is None
    settings = with_translation(layout)
    assert isinstance(settings.translator, LibreTranslate) and settings.translate_timeout == 12
    assert settings.profile_named("analyst").allow_translate is True
    assert settings.profile.allow_translate is False


def test_the_api_key_comes_from_a_file(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    key = secrets.token_urlsafe(24)
    secret(layout.root / "secrets" / "translate.key", key.encode())
    running = Service()
    try:
        block = TRANSLATE_BLOCK.replace("https://translate.internal.example.net", running.url)
        layout.config.write_text(layout.text() + block, encoding="utf-8")
        layout.edit("timeout = 12", 'timeout = 12\napi_key_file = "secrets/translate.key"')
        layout.edit("[profiles.analyst]", "[profiles.analyst]\nallow_translate = true")
        translator = load_config(layout.config).settings.translator
        assert translator is not None and key not in repr(translator)
        asyncio.run(translator.translate(["x"]))
        assert running.seen.requests[0]["api_key"] == key
    finally:
        running.stop()


def test_a_profile_that_translates_with_no_section_is_an_error(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    layout.edit("[profiles.analyst]", "[profiles.analyst]\nallow_translate = true")
    with pytest.raises(ConfigError, match="translator"):
        load_config(layout.config)


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("unknown_setting = 1\n", "unknown_setting"),
        ('target = "english"\n', "language"),
        ('allow_plain_http = "yes"\n', "true or false"),
    ],
)
def test_the_translate_settings_are_checked(tmp_path: Path, extra: str, message: str) -> None:
    layout = Layout(tmp_path)
    block = TRANSLATE_BLOCK.replace('target = "de"\n', "") + extra
    layout.config.write_text(layout.text() + block, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_config(layout.config)


def test_a_service_that_is_not_https_is_refused_in_the_config_file(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    block = TRANSLATE_BLOCK.replace("https://", "http://")
    layout.config.write_text(layout.text() + block, encoding="utf-8")
    with pytest.raises(ConfigError, match="https"):
        load_config(layout.config)
