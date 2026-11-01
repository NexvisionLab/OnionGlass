# SPDX-License-Identifier: AGPL-3.0-only
"""The page on handing out domains and links: what it says about tickets is true of the code, the
commands in it exist, it claims nothing it cannot do, and the other pages lead to it."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from onionglass.teamcli import _parser
from onionglass.tickets import _CLAIM_KEYS, CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PAGE = DOCS / "distribution.md"


def page() -> str:
    assert PAGE.exists(), "docs/distribution.md is missing"
    return PAGE.read_text(encoding="utf-8")


def slugs(path: Path) -> set[str]:
    titles = re.findall(r"^#{1,6} (.+)$", path.read_text(encoding="utf-8"), re.MULTILINE)
    return {re.sub(r"[^a-z0-9 -]", "", t.lower()).strip().replace(" ", "-") for t in titles}


def test_the_page_says_first_that_nothing_hands_out_addresses_safely_and_whose_job_it_is() -> None:
    opening = page().split("\n## ", 2)[1].lower()
    assert "nothing" in opening and "scrape" in opening
    assert "sign-in service" in opening and "yours" in opening


def test_the_page_never_claims_to_beat_the_censor() -> None:
    lowered = page().lower()
    for claim in (
        "cannot be blocked",
        "can not be blocked",
        "guarantee",
        "uncensorable",
        "unscrapable",
    ):
        assert claim not in lowered
    assert "unblockable" not in lowered.replace("nothing is unblockable", "")


def test_the_page_is_plain_ascii() -> None:
    assert page().isascii()


def test_every_ticket_claim_the_page_names_is_a_claim_a_ticket_has() -> None:
    named = set(re.findall(r"`(sub|grp|prf|jti|iat|exp|aud|onion)`", page()))
    assert named, "the page should name the ticket fields it relies on"
    assert named <= _CLAIM_KEYS


def test_the_page_names_the_fields_that_matter_for_handing_out_a_link() -> None:
    named = set(re.findall(r"`(sub|grp|prf|jti|iat|exp|aud|onion)`", page()))
    assert {"grp", "aud", "exp", "jti", "prf"} <= named


def test_the_numbers_the_page_gives_for_a_ticket_are_the_codes() -> None:
    text = page()
    assert f"{MAX_LIFETIME_SECONDS} seconds" in text
    assert f"{CLOCK_SKEW_SECONDS} seconds" in text


def test_the_page_says_a_link_can_be_used_once_and_that_a_relay_sees_it() -> None:
    lowered = page().lower()
    assert "once" in lowered and "relay" in lowered and "continue" in lowered


def test_every_command_the_page_names_exists() -> None:
    parser = _parser()
    text = re.sub(r"\\\n\s*", " ", page())
    found = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not re.match(r"onionglass (domains|relays?|ticket|keys) ", line):
            continue
        cleaned = re.sub(r"<[^>]*>", "x", line)
        tokens = ["x" if t == "..." else t for t in shlex.split(cleaned, comments=True)[1:]]
        parser.parse_args(tokens)
        found += 1
    assert found >= 2


def test_every_link_to_another_page_or_heading_goes_somewhere() -> None:
    for target in re.findall(r"\]\(((?!https?:)[^)\s]+)\)", page()):
        name, _, anchor = target.partition("#")
        path = DOCS / name if name else PAGE
        assert path.exists(), target
        if anchor:
            assert anchor in slugs(path), target


def test_the_other_pages_lead_to_it() -> None:
    for name in ("censorship.md", "relays.md", "bridges.md"):
        assert "distribution.md" in (DOCS / name).read_text(encoding="utf-8"), name
    assert "docs/distribution.md" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_page_says_that_onionglass_does_not_decide_who_gets_a_link_and_has_no_trust_ladder() -> (
    None
):
    lowered = page().lower()
    assert "does not decide" in lowered
    assert "no trust ladder" in lowered or "does not have a trust ladder" in lowered
