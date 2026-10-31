# SPDX-License-Identifier: AGPL-3.0-only
"""The entity panel: what a page names, shown beside it for profiles that are allowed to see it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from helpers import DUCKDUCKGO
from onionglass.config import PROFILE_FIELDS, PROFILE_KINDS, load_config
from onionglass.settings import Profile
from test_config import Layout
from test_entities import GENESIS, SEGWIT, monero_address
from test_gateway import Env, reply

PAGE_TEXT = (
    "<title>Pay here</title><h1>Wallets</h1>"
    f"<p>Bitcoin {GENESIS}, email Ops@Example.org, second {SEGWIT}.</p>"
    f"<p>Mirror: http://{DUCKDUCKGO}.onion/</p><p>XMR {{xmr}}</p>"
    f"<script>var hidden = '{GENESIS}'; var mail = 'secret@example.org';</script>"
    "<style>.x::after{content:'ghost@example.org'}</style>"
    f"<a href='/p' title='attr@example.org' data-x='{GENESIS}'>link</a>"
)


def served(profile: Profile, **extra: Any) -> Env:
    page = PAGE_TEXT.replace("{xmr}", monero_address())
    return Env(lambda _r: reply(page), profile=profile, **extra)


def current(env: Env, label: str) -> dict[str, Any]:
    assert env.get(label, headers={"sec-fetch-dest": "iframe"}).status_code == 200
    data: dict[str, Any] = json.loads(env.client.get("/_og/current").text)
    return data


def listed(data: dict[str, Any]) -> list[tuple[str, str]]:
    return [(item["kind"], item["value"]) for item in data["entities"]]


def test_a_profile_that_may_see_entities_gets_them_with_the_current_page() -> None:
    env = served(Profile(name="personal", show_entities=True))
    found = listed(current(env, env.open()))
    assert ("bitcoin", GENESIS) in found and ("bitcoin", SEGWIT) in found
    assert ("email", "ops@example.org") in found
    assert ("onion", DUCKDUCKGO + ".onion") in found
    assert [kind for kind, _ in found].count("monero") == 1


def test_text_that_is_not_shown_on_the_page_is_not_read() -> None:
    env = served(Profile(name="personal", show_entities=True))
    values = {value for _, value in listed(current(env, env.open()))}
    assert "secret@example.org" not in values and "ghost@example.org" not in values
    assert "attr@example.org" not in values


def test_a_profile_without_the_switch_gets_none_and_the_page_has_no_panel() -> None:
    env = served(Profile(name="personal"))
    label = env.open()
    assert "entities" not in current(env, label)
    viewer = env.client.get("/view", params={"l": label, "p": "/"})
    assert viewer.status_code == 200 and 'id="entities"' not in viewer.text


def test_the_viewer_has_the_panel_when_the_profile_allows_it() -> None:
    env = served(Profile(name="personal", show_entities=True))
    label = env.open()
    viewer = env.client.get("/view", params={"l": label, "p": "/"})
    assert 'id="entities"' in viewer.text and 'id="entities-list"' in viewer.text


def test_a_page_with_nothing_to_report_has_an_empty_list() -> None:
    env = Env(
        lambda _r: reply("<title>x</title><p>nothing here</p>"),
        profile=Profile(name="personal", show_entities=True),
    )
    assert current(env, env.open())["entities"] == []


def test_entities_are_not_kept_for_a_request_that_is_not_a_page_view() -> None:
    env = served(Profile(name="personal", show_entities=True))
    label = env.open()
    env.get(label)  # no sec-fetch-dest: a sub-request, not what the visitor is looking at
    assert "entities" not in json.loads(env.client.get("/_og/current").text or "{}")


@pytest.mark.parametrize("field", ["show_entities"])
def test_the_switch_is_off_in_the_restricted_preset_and_in_text_only_form(field: str) -> None:
    assert getattr(Profile.restricted(), field) is False
    assert getattr(Profile(name="x", show_entities=True).text_only(), field) is True


def test_the_config_file_can_switch_the_panel_on(tmp_path: Path) -> None:
    """A switch that the config file accepts but ignores would leave the panel off for ever."""
    layout = Layout(tmp_path)
    settings = load_config(layout.config).settings
    assert settings.profile_named("analyst").show_entities is True  # type: ignore[union-attr]
    assert settings.profile.show_entities is False
    layout.edit("[profile]", "[profile]\nshow_entities = true")
    assert load_config(layout.config).settings.profile.show_entities is True


def test_every_profile_field_can_be_set_from_the_config_file() -> None:
    """The file check accepts every profile field, so each must also be applied."""
    assert set(PROFILE_KINDS) == set(PROFILE_FIELDS)
