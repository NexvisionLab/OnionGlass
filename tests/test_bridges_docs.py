# SPDX-License-Identifier: AGPL-3.0-only
"""The Tor bridge guide: it points to the Tor Project's own instructions, says what it has and has
not been tried, keeps the bridges away from the gateway's server, and is reachable from the other
guides."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PAGE = DOCS / "bridges.md"


def page() -> str:
    assert PAGE.exists(), "docs/bridges.md is missing"
    return PAGE.read_text(encoding="utf-8")


def test_the_guide_links_to_the_tor_projects_own_instructions() -> None:
    text = page()
    for url in (
        "https://community.torproject.org/relay/setup/webtunnel/",
        "https://community.torproject.org/relay/setup/webtunnel/docker/",
        "https://community.torproject.org/relay/setup/snowflake/standalone/docker/",
    ):
        assert url in text, url


def test_the_guide_tells_the_operator_to_use_a_separate_server() -> None:
    opening = page().lower().split("\n## ", 2)[1]  # the first section after the title block
    assert "separate server" in opening and "gateway" in opening


def test_the_guide_says_what_it_shipped_and_what_it_did_not_try() -> None:
    lowered = page().lower()
    assert "onionglass does not ship" in lowered  # no bundle, no image of our own
    assert "not tried" in lowered  # the commands have not been run here
    assert "2026-11-01" in page()  # when the Tor Project pages were read


def test_the_guide_shows_the_commands_the_tor_project_gives() -> None:
    text = page()
    assert "docker compose up -d snowflake-proxy" in text
    assert "docker compose up -d" in text
    assert "get-bridge-line.sh" in text  # how the WebTunnel operator reads the bridge line


def test_the_guide_does_not_oversell_bridges() -> None:
    lowered = page().lower()
    for claim in ("cannot be blocked", "can not be blocked", "guarantee", "uncensorable"):
        assert claim not in lowered
    assert "can still be blocked" in lowered


def test_the_guide_tells_the_operator_not_to_publish_the_bridge_line() -> None:
    lowered = page().lower()
    assert "bridge line" in lowered and "do not publish" in lowered


def test_every_link_to_another_page_or_heading_goes_somewhere() -> None:
    for target in re.findall(r"\]\(((?!https?:)[^)\s]+)\)", page()):
        name, _, anchor = target.partition("#")
        path = DOCS / name if name else PAGE
        assert path.exists(), target
        if anchor:
            titles = re.findall(r"^#{1,6} (.+)$", path.read_text(encoding="utf-8"), re.MULTILINE)
            slugs = {
                re.sub(r"[^a-z0-9 -]", "", t.lower()).strip().replace(" ", "-") for t in titles
            }
            assert anchor in slugs, target


def test_the_other_guides_point_to_it() -> None:
    assert "bridges.md" in (DOCS / "censorship.md").read_text(encoding="utf-8")
    assert "bridges.md" in (DOCS / "deploying.md").read_text(encoding="utf-8")
    assert "docs/bridges.md" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_guide_is_plain_ascii() -> None:
    assert page().isascii()
