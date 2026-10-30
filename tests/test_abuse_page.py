# SPDX-License-Identifier: AGPL-3.0-only
"""The abuse page: where anyone, signed in or not, learns how to report a site or complain.

The operator's contact comes from the configuration. The page says what to send (the address,
never the material) and what the gateway does with a report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from onionglass.config import ConfigError, load_config
from onionglass.pages import REPORT_LABELS
from onionglass.reports import CATEGORIES
from onionglass.settings import Profile, Settings
from onionglass.teamcli import describe
from test_config import Layout
from test_gateway import Env, reply

CONTACT = "abuse@example.org"


def served(**extra: Any) -> Env:
    return Env(lambda _r: reply("<p>x</p>"), **extra)


def test_the_abuse_page_names_the_contact_and_what_to_send() -> None:
    page = served(abuse_contact=CONTACT).client.get("/abuse")
    assert page.status_code == 200
    assert f'href="mailto:{CONTACT}"' in page.text
    assert "address" in page.text and "not the material" in page.text
    assert "script-src 'none'" in page.headers["content-security-policy"]
    assert "<script" not in page.text


def test_the_page_lists_the_reasons_a_visitor_can_choose() -> None:
    text = served(abuse_contact=CONTACT).client.get("/abuse").text
    for name in CATEGORIES:
        assert REPORT_LABELS[name] in text


def test_a_web_address_contact_becomes_a_link_and_is_escaped() -> None:
    url = "https://gateway.example.org/contact?topic=abuse&lang=en"
    text = served(abuse_contact=url).client.get("/abuse").text
    assert 'href="https://gateway.example.org/contact?topic=abuse&amp;lang=en"' in text
    assert "&lang=" not in text.replace("&amp;lang=", "")


def test_without_a_contact_the_page_says_so_instead_of_inventing_one() -> None:
    text = served().client.get("/abuse").text
    assert "has not published a contact" in text
    assert "mailto:" not in text


def test_the_entry_page_links_to_the_abuse_page_only_when_there_is_a_contact() -> None:
    assert 'href="/abuse"' in served(abuse_contact=CONTACT).client.get("/").text
    assert 'href="/abuse"' not in served().client.get("/").text


def test_the_abuse_page_needs_no_sign_in_and_only_reads() -> None:
    env = served(abuse_contact=CONTACT)
    assert env.client.head("/abuse").status_code == 200
    assert env.client.post("/abuse").status_code == 404


@pytest.mark.parametrize(
    "contact",
    [
        "",
        "abuse",
        "abuse@",
        "two words@example.org",
        "abuse@example.org\nBcc: x@example.org",
        "javascript:alert(1)",
        "http://gateway.example.org/contact",
        "https://",
        "https://gateway.example.org/a b",
        "mailto:abuse@example.org",
        "a" * 300 + "@example.org",
        "abuse@example.org\x00",
    ],
)
def test_a_contact_that_is_not_an_email_address_or_https_link_is_refused(contact: str) -> None:
    with pytest.raises(ValueError, match="abuse contact"):
        Settings(
            base_domain="localhost",
            scheme="http",
            open_mode=True,
            profile=Profile(name="personal"),
            abuse_contact=contact,
        )


def test_the_config_reads_the_contact_and_check_config_warns_when_it_is_missing(
    tmp_path: Path,
) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    assert "[abuse]" in text
    layout.config.write_text(text, encoding="utf-8")
    config = load_config(layout.config)
    assert config.settings.abuse_contact is not None
    assert not any("abuse contact" in line for line in describe(config))
    without = text.replace("[abuse]", "[abuse_gone]")  # a section that is not there at all
    layout.config.write_text(without, encoding="utf-8")
    with pytest.raises(ConfigError, match="abuse_gone"):
        load_config(layout.config)


def test_the_config_refuses_an_empty_or_unknown_abuse_setting(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    for edited in (
        text.replace("contact = ", 'contact = ""  # ', 1),
        text.replace("[abuse]", '[abuse]\nphone = "1"', 1),
    ):
        layout.config.write_text(edited, encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(layout.config)


def test_check_config_warns_when_no_contact_is_published(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    lines = [line for line in layout.text().splitlines() if not line.startswith("contact =")]
    layout.config.write_text("\n".join(lines), encoding="utf-8")
    config = load_config(layout.config)
    assert config.settings.abuse_contact is None
    assert any(line.startswith("warning: no abuse contact") for line in describe(config))
