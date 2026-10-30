# SPDX-License-Identifier: AGPL-3.0-only
"""Signing in through a link asks the visitor to confirm, so a hostile page cannot do it for them.

Without the step, any page the visitor looks at could send their browser to a sign-in link of the
attacker's own, and the visitor would then be browsing as the attacker's account: their opens
counted against it, and recorded under its name.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from onionglass.config import load_config
from test_config import Layout
from test_gateway import Deployed

SAME = {"sec-fetch-site": "same-origin", "origin": "https://gw.example"}


def asked(env: Deployed, ticket: str) -> str:
    """The confirmation page for a ticket, which must not have signed anyone in."""
    page = env.client.get("/enter", params={"t": ticket})
    assert page.status_code == 200, page.text
    assert "set-cookie" not in page.headers
    return page.text


def test_following_a_sign_in_link_shows_a_page_and_does_not_sign_in() -> None:
    env = Deployed(confirm_sign_in=True)
    text = asked(env, env.ticket())
    assert 'method="post" action="/enter"' in text and 'name="t"' in text
    assert "Continue" in text
    assert env.client.get("/").text.lower().count("sign in") >= 1  # still signed out


def test_confirming_signs_in_once_and_the_link_cannot_be_used_again() -> None:
    env = Deployed(confirm_sign_in=True)
    ticket = env.ticket()
    asked(env, ticket)
    asked(env, ticket)  # looking at the page does not use the link up
    done = env.client.post("/enter", data={"t": ticket}, headers=SAME)
    assert done.status_code == 303 and "og_session" in done.headers["set-cookie"]
    assert env.client.post("/enter", data={"t": ticket}, headers=SAME).status_code == 403


def test_a_confirmation_that_came_from_another_site_is_refused_and_spends_nothing() -> None:
    env = Deployed(confirm_sign_in=True)
    ticket = env.ticket()
    for headers in (
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-site"},
        {"origin": "https://evil.example"},
        {"origin": "null"},
    ):
        refused = env.client.post("/enter", data={"t": ticket}, headers=headers)
        assert refused.status_code == 403 and "set-cookie" not in refused.headers
    assert env.client.post("/enter", data={"t": ticket}, headers=SAME).status_code == 303


def test_a_bad_ticket_is_refused_at_the_page_and_at_the_confirmation() -> None:
    env = Deployed(confirm_sign_in=True)
    assert env.client.get("/enter", params={"t": "garbage"}).status_code == 403
    assert env.client.get("/enter").status_code == 403
    assert env.client.post("/enter", data={"t": "garbage"}, headers=SAME).status_code == 403
    assert env.client.post("/enter", data={}, headers=SAME).status_code == 403


def test_a_ticket_for_a_profile_this_gateway_lacks_is_refused_before_asking() -> None:
    env = Deployed(confirm_sign_in=True)
    ghost = env.issuer.issue(subject="a", group="g", profile="ghost")
    assert env.client.get("/enter", params={"t": ghost}).status_code == 403


def test_the_ticket_is_escaped_on_the_page_and_nothing_else_about_it_is_shown() -> None:
    env = Deployed(confirm_sign_in=True)
    ticket = env.ticket(onion="2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid")
    text = asked(env, ticket)
    assert f'value="{ticket}"' in text
    assert (
        "analyst-1" not in text
        and "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid" not in text
    )


def test_a_ticket_that_opens_an_onion_still_does_so_after_confirming() -> None:
    env = Deployed(confirm_sign_in=True)
    ticket = env.ticket(onion="2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid")
    done = env.client.post("/enter", data={"t": ticket}, headers=SAME)
    assert done.status_code == 303 and done.headers["location"].startswith(
        "https://gw.example/view"
    )


def test_with_the_step_turned_off_the_link_signs_in_directly() -> None:
    env = Deployed(confirm_sign_in=False)
    assert env.client.get("/enter", params={"t": env.ticket()}).status_code == 303


def test_the_confirmation_page_cannot_be_framed_or_run_scripts() -> None:
    env = Deployed(confirm_sign_in=True)
    page = env.client.get("/enter", params={"t": env.ticket()})
    policy = page.headers["content-security-policy"]
    assert "script-src 'none'" in policy and "frame-ancestors 'none'" in policy
    assert "form-action 'self'" in policy


def test_the_config_asks_for_confirmation_unless_told_not_to(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    assert load_config(layout.config).settings.confirm_sign_in is True
    text = layout.text()
    assert "[tickets]" in text
    layout.config.write_text(
        text.replace("[tickets]", "[tickets]\nconfirm_sign_in = false", 1), encoding="utf-8"
    )
    assert load_config(layout.config).settings.confirm_sign_in is False
    layout.config.write_text(
        text.replace("[tickets]", '[tickets]\nconfirm_sign_in = "no"', 1), encoding="utf-8"
    )
    with pytest.raises(Exception, match="true or false"):
        load_config(layout.config)


def test_a_stranger_cannot_use_the_post_to_learn_whether_a_ticket_was_spent() -> None:
    env = Deployed(confirm_sign_in=True)
    ticket = env.ticket()
    env.client.post("/enter", data={"t": ticket}, headers=SAME)
    other = TestClient(env.gateway.app, base_url="https://gw.example", follow_redirects=False)
    spent = other.post("/enter", data={"t": ticket}, headers=SAME)
    garbage = other.post("/enter", data={"t": "garbage"}, headers=SAME)
    assert spent.status_code == garbage.status_code == 403
    assert spent.text == garbage.text
