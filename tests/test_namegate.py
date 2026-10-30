# SPDX-License-Identifier: AGPL-3.0-only
"""The name gate, the held list and text-only display for unrated sites (milestone 2, slice 4).

The word lists in these tests are harmless on purpose. The repository never holds a real list.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.audit import MemoryAudit
from onionglass.cli import build_gateway
from onionglass.held import BROKEN, HeldError, HeldList
from onionglass.namegate import NameGate, load_name_gate, parse_name_list
from onionglass.policy import Decision, PolicyConfigError, PolicyRequest, StaticPolicy
from onionglass.settings import Profile, Settings
from test_gateway import PAGE, Env, reply

OTHER = f"http://{DUCKDUCKGO}.onion/"
PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 20


# --- the name gate -------------------------------------------------------------------------------


def test_a_phrase_matches_whole_words_only() -> None:
    gate = NameGate(["grape", "red fox"])
    assert gate.check("Grape juice") and gate.check("The Red Fox!") and gate.check("red, fox")
    assert not gate.check("grapefruit") and not gate.check("red box fox") and not gate.check("")
    assert not gate.check("a grapevine", "the fox is red")


def test_a_trailing_star_matches_words_that_start_with_it() -> None:
    gate = NameGate(["blue*"])
    assert gate.check("bluebird") and gate.check("Blue") and gate.check("my blueberries")
    assert not gate.check("ablue", "true blu")


def test_accents_width_variants_and_hidden_characters_do_not_hide_a_word() -> None:
    gate = NameGate(["grape"])
    assert gate.check("Gr" + chr(0xE4) + "pe")  # an accented letter
    assert gate.check("".join(chr(ord(c) + 0xFEE0) for c in "grape"))  # full-width letters
    assert gate.check("gr" + chr(0x200B) + "ape")  # a zero-width space inside the word
    assert gate.check("gr" + chr(0x0301) + "ape")  # a combining mark


def test_look_alike_digits_and_symbols_do_not_hide_a_word() -> None:
    gate = NameGate(["grape", "easy"])
    assert (
        gate.check("gr4p3")
        and gate.check("gr@pe")
        and gate.check("3asy")
        and gate.check("$ale grape")
    )
    assert not gate.check("room 404")


def test_bad_entries_are_errors_that_name_the_entry() -> None:
    with pytest.raises(PolicyConfigError, match="entry 2"):
        NameGate(["fine", "***"])
    with pytest.raises(PolicyConfigError, match="single word"):
        NameGate(["two words*"])


def test_lists_are_read_with_comments_and_loaded_from_files(tmp_path: Path) -> None:
    assert parse_name_list("# header\n grape  # trailing\n\nred fox\n") == ["grape", "red fox"]
    path = tmp_path / "names.txt"
    path.write_text("grape\n", encoding="utf-8")
    assert load_name_gate(path).check("grape")
    with pytest.raises(PolicyConfigError):
        load_name_gate(tmp_path / "missing.txt")
    with pytest.raises(PolicyConfigError):
        load_name_gate(tmp_path)
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(PolicyConfigError):
        load_name_gate(path)


def test_a_long_title_is_checked_quickly() -> None:
    gate = NameGate([f"word{i}" for i in range(2000)] + ["pre*"])
    assert not gate.check("x " * 5000)
    assert gate.check("a " * 4000 + "prefix")


# --- the held list -------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_a_site_is_held_in_memory_and_in_the_file(tmp_path: Path) -> None:
    path = tmp_path / "held.txt"
    held = HeldList(path)
    assert held.reason_for(TOR_PROJECT) is None
    asyncio.run(held.hold(TOR_PROJECT, "name-gate"))
    assert held.reason_for(TOR_PROJECT) == "held"
    line = path.read_text(encoding="utf-8").strip()
    assert re.fullmatch(rf"{TOR_PROJECT} \d{{4}}-\d\d-\d\dT\d\d:\d\d:\d\dZ name-gate", line)
    assert HeldList(path).reason_for(TOR_PROJECT) == "held"  # a restart keeps it
    assert HeldList(path).reason_for(DUCKDUCKGO) is None


def test_deleting_a_line_releases_the_site(tmp_path: Path) -> None:
    clock = Clock()
    path = tmp_path / "held.txt"
    path.write_text(f"# queue\n{TOR_PROJECT} 2026-10-30T00:00:00Z name-gate\n", encoding="utf-8")
    held = HeldList(path, clock=clock)
    assert held.reason_for(TOR_PROJECT) == "held"
    path.write_text("", encoding="utf-8")
    assert held.reason_for(TOR_PROJECT) == "held"  # the cached answer
    clock.now += 3
    assert held.reason_for(TOR_PROJECT) is None


def test_a_held_list_nobody_understands_holds_everything(tmp_path: Path) -> None:
    path = tmp_path / "held.txt"
    path.write_text("this is not an address\n", encoding="utf-8")
    assert HeldList(path).reason_for(TOR_PROJECT) == BROKEN
    assert HeldList(tmp_path).reason_for(TOR_PROJECT) == BROKEN  # a folder


def test_a_site_stays_held_even_when_the_file_cannot_be_written(tmp_path: Path) -> None:
    held = HeldList(tmp_path)  # a folder cannot be appended to
    with pytest.raises(HeldError):
        asyncio.run(held.hold(TOR_PROJECT, "name-gate"))
    assert held.reason_for(TOR_PROJECT) in ("held", BROKEN)


def test_a_reason_cannot_break_the_line_format(tmp_path: Path) -> None:
    path = tmp_path / "held.txt"
    asyncio.run(HeldList(path).hold(TOR_PROJECT, "bad\nreason " + "x" * 500))
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


# --- in the gateway ------------------------------------------------------------------------------


def page_with(title: str = "Shop", heading: str = "Welcome", body: str = "hello") -> Any:
    html = f"<title>{title}</title><h1>{heading}</h1><p>{body}</p>"
    return lambda _r: reply(html)


def test_a_page_with_a_listed_title_is_refused_and_its_site_is_held(tmp_path: Path) -> None:
    audit = MemoryAudit()
    held = HeldList(tmp_path / "held.txt")
    env = Env(
        page_with(title="Grape Market"), name_gate=NameGate(["grape"]), held=held, audit=audit
    )
    label = env.open()
    refused = env.get(label)
    assert refused.status_code == 403 and "Grape" not in refused.text
    assert "does not open that address" in refused.text
    assert (tmp_path / "held.txt").read_text(encoding="utf-8").startswith(TOR_PROJECT)
    before = len(env.fetcher.requests)
    assert env.get(label, "/other").status_code == 403  # held: refused before any fetch
    assert len(env.fetcher.requests) == before
    assert env.client.post("/open", data={"address": PAGE}).status_code == 403
    rules = [e.rule for e in audit.events if e.kind == "refused"]
    assert rules[0] == "name-gate" and "held" in rules


def test_a_listed_heading_counts_too_and_other_sites_are_not_affected(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    env = Env(page_with(heading="all about grape"), name_gate=NameGate(["grape"]), held=held)
    assert env.get(env.open()).status_code == 403
    clean = Env(page_with(heading="all about plums"), name_gate=NameGate(["grape"]), held=held)
    other = clean.open(OTHER)
    assert clean.get(other).status_code == 200


def test_only_the_title_and_first_headings_are_read(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    env = Env(page_with(body="grape grape grape"), name_gate=NameGate(["grape"]), held=held)
    assert env.get(env.open()).status_code == 200  # the body is not read
    assert held.reason_for(TOR_PROJECT) is None


def test_a_held_site_stays_held_after_a_restart_until_released(tmp_path: Path) -> None:
    path = tmp_path / "held.txt"
    first = Env(page_with(title="Grape"), name_gate=NameGate(["grape"]), held=HeldList(path))
    first.get(first.open())
    again = Env(page_with(title="Shop"), held=HeldList(path))
    assert again.client.post("/open", data={"address": PAGE}).status_code == 403
    path.write_text("", encoding="utf-8")
    clock = Clock()
    clock.now += 5
    released = Env(page_with(title="Shop"), held=HeldList(path, clock=clock))
    assert released.client.post("/open", data={"address": PAGE}).status_code == 303


def test_a_name_gate_without_a_held_list_is_refused_when_the_gateway_is_set_up() -> None:
    with pytest.raises(ValueError, match="held list"):
        Settings(base_domain="localhost", open_mode=True, name_gate=NameGate(["grape"]))


def test_an_unreadable_held_list_stops_the_gateway(tmp_path: Path) -> None:
    env = Env(page_with(), held=HeldList(tmp_path))
    assert env.client.post("/open", data={"address": PAGE}).status_code == 403
    assert env.fetcher.requests == []


# --- unrated sites are shown as text only ---------------------------------------------------------

RICH = (
    '<h1>Page</h1><img src="/a.png" alt="picture"><form method="post" action="/x">'
    '<input name="user"><input type="password" name="pw"><button>Go</button></form>'
)


def rich_site(request: Any) -> Any:
    if request.target.startswith("/a.png"):
        return reply(PNG, content_type="image/png")
    return reply(RICH)


def rated_env(**settings: Any) -> Env:
    profile = Profile(name="personal", allow_images=True)
    return Env(rich_site, profile=profile, policy=StaticPolicy(rated=[TOR_PROJECT]), **settings)


def test_a_rated_site_is_served_normally_and_an_unrated_one_as_text() -> None:
    env = rated_env()
    rated = env.open(PAGE)
    unrated = env.open(OTHER)
    rich = env.get(rated).text
    plain = env.get(unrated).text
    assert 'src="' in rich and 'type="password"' in rich and "<form" in rich
    assert 'src="' not in plain and "password" not in plain.lower() and "<form" not in plain
    assert env.get(rated, "/a.png").status_code == 200
    assert env.get(unrated, "/a.png").status_code != 200


def test_an_unrated_site_cannot_be_posted_to_even_by_hand() -> None:
    env = rated_env()
    rated, unrated = env.open(PAGE), env.open(OTHER)
    headers = {"sec-fetch-site": "same-origin"}
    before = len(env.fetcher.requests)
    refused = env.client.post(
        "/x",
        data={"a": "b"},
        headers={"host": f"{unrated}.localhost:{env.settings.port}", **headers},
    )
    assert refused.status_code == 403 and "does not allow" in refused.text
    assert len(env.fetcher.requests) == before
    allowed = env.client.post(
        "/x", data={"a": "b"}, headers={"host": f"{rated}.localhost:{env.settings.port}", **headers}
    )
    assert allowed.status_code == 200


def test_the_audit_log_says_a_site_was_unrated() -> None:
    audit = MemoryAudit()
    env = rated_env(audit=audit)
    env.get(env.open(OTHER))
    assert any(e.kind == "allowed" and e.rule == "unrated" for e in audit.events)


def test_the_blocklist_still_wins_over_the_rated_list() -> None:
    policy = StaticPolicy(blocked=[TOR_PROJECT], rated=[TOR_PROJECT])
    env = Env(rich_site, policy=policy)
    assert env.client.post("/open", data={"address": PAGE}).status_code == 403


def test_a_custom_policy_can_ask_for_text_only() -> None:
    class Cautious:
        async def decide(self, request: PolicyRequest) -> Decision:
            return Decision.allow("cautious", text_only=True)

    env = Env(rich_site, profile=Profile(allow_images=True), policy=Cautious())
    text = env.get(env.open()).text
    assert "<form" not in text and 'src="' not in text


def test_the_text_only_form_of_a_profile_turns_everything_risky_off() -> None:
    plain = Profile(
        name="x", allow_images=True, allow_uploads=True, max_requests_per_minute=7
    ).text_only()
    assert not (plain.allow_images or plain.allow_fonts or plain.allow_post_forms)
    assert not (plain.allow_uploads or plain.allow_password_fields)
    assert plain.name == "x" and plain.max_requests_per_minute == 7  # the rest is kept


# --- the command line ----------------------------------------------------------------------------


def test_the_options_are_wired_in_and_a_name_list_needs_a_held_file(tmp_path: Path) -> None:
    names = tmp_path / "names.txt"
    names.write_text("grape\n", encoding="utf-8")
    rated = tmp_path / "rated.txt"
    rated.write_text(f"{TOR_PROJECT}\n", encoding="utf-8")
    gateway = build_gateway(
        port=9000, name_list=names, held_file=tmp_path / "held.txt", rated_list=rated
    )
    assert gateway.settings.name_gate is not None and gateway.settings.held is not None
    assert gateway.settings.policy is not None
    with pytest.raises(PolicyConfigError, match="held-file"):
        build_gateway(port=9000, name_list=names)
