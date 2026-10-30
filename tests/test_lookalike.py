# SPDX-License-Identifier: AGPL-3.0-only
"""The look-alike warning: an address that starts like a well-known one is checked before opening.

The copy has to be a valid address, so the tests make real ones that share the start of a listed
address with a different end.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.audit import MemoryAudit
from onionglass.cli import build_gateway
from onionglass.config import ConfigError, load_config
from onionglass.lookalike import MIN_SHARED_PREFIX, KnownSites, load_known_sites, parse_known_sites
from onionglass.policy import PolicyConfigError
from onionglass.settings import Profile
from test_config import Layout
from test_gateway import Env, reply

LIST = f"{TOR_PROJECT} The Tor Project\n{DUCKDUCKGO} DuckDuckGo\n"


def copy_of(address: str, *, shared_bytes: int = 5) -> str:
    """A valid address that begins with the same bytes as ``address`` and is a different site."""
    original = base64.b32decode(address.upper())[:32]
    key = original[:shared_bytes] + os.urandom(32 - shared_bytes)
    version = bytes([3])
    checksum = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    return base64.b32encode(key + checksum + version).decode("ascii").lower()


def served(**extra: Any) -> Env:
    return Env(lambda _r: reply("<p>x</p>"), known_sites=parse_known_sites(LIST), **extra)


def test_the_helper_makes_a_real_copy_that_shares_the_start() -> None:
    copy = copy_of(TOR_PROJECT)
    assert copy != TOR_PROJECT and copy[:MIN_SHARED_PREFIX] == TOR_PROJECT[:MIN_SHARED_PREFIX]
    assert KnownSites([]).lookalike_of(copy) is None


def test_an_address_that_starts_like_a_listed_one_gets_a_warning_before_anything_is_fetched() -> (
    None
):
    env = served()
    copy = copy_of(TOR_PROJECT)
    response = env.client.post("/open", data={"address": f"{copy}.onion"})
    assert response.status_code == 200
    assert "The Tor Project" in response.text
    assert TOR_PROJECT in response.text and copy in response.text
    assert 'name="confirm" value="1"' in response.text
    assert env.fetcher.requests == []
    assert "set-cookie" not in response.headers  # no session is made for a warning


def test_the_listed_address_itself_and_unrelated_addresses_open_without_a_warning() -> None:
    env = served()
    assert env.client.post("/open", data={"address": f"{TOR_PROJECT}.onion"}).status_code == 303
    other = copy_of(DUCKDUCKGO, shared_bytes=0)
    assert env.client.post("/open", data={"address": f"{other}.onion"}).status_code == 303


def test_a_shorter_shared_start_is_not_a_warning() -> None:
    copy = copy_of(TOR_PROJECT, shared_bytes=3)  # 24 bits, under the six characters checked
    assert copy[:MIN_SHARED_PREFIX] != TOR_PROJECT[:MIN_SHARED_PREFIX]
    assert served().client.post("/open", data={"address": f"{copy}.onion"}).status_code == 303


def test_confirming_opens_it_and_keeps_the_path_and_is_recorded_like_any_open() -> None:
    audit = MemoryAudit()
    env = served(audit=audit)
    copy = copy_of(DUCKDUCKGO)
    typed = f"http://{copy}.onion/some/page?q=1"
    warned = env.client.post("/open", data={"address": typed})
    assert warned.status_code == 200 and "&amp;" not in typed
    assert f'value="{typed}"' in warned.text
    assert audit.events == []  # a warning is not a request
    opened = env.client.post("/open", data={"address": typed, "confirm": "1"})
    assert opened.status_code == 303
    assert [e.kind for e in audit.events] == ["allowed"] and audit.events[0].action == "open"
    assert env.fetcher.requests == [] or env.fetcher.requests[-1].origin.host.address == copy


def test_the_warning_costs_nothing_and_does_not_use_the_open_allowance() -> None:
    class Meter:
        total = 0

        async def used(self, subject: str, profile: str) -> int:
            return self.total

        async def charge(self, subject: str, profile: str, units: int) -> int:
            self.total += units
            return self.total

        async def reserve(self, subject: str, profile: str, units: int, limit: int) -> bool:
            if self.total + units > limit:
                return False
            self.total += units
            return True

    meter = Meter()
    env = served(profile=Profile(name="personal", open_cost=1, daily_quota=5), quota=meter)
    copy = copy_of(TOR_PROJECT)
    for _ in range(4):
        assert env.client.post("/open", data={"address": copy + ".onion"}).status_code == 200
    assert meter.total == 0


def test_a_name_in_the_list_cannot_inject_markup_into_the_warning() -> None:
    sites = parse_known_sites(f"{TOR_PROJECT} <b>Bold</b> &amp; co\n")
    env = Env(lambda _r: reply("<p>x</p>"), known_sites=sites)
    text = env.client.post("/open", data={"address": copy_of(TOR_PROJECT) + ".onion"}).text
    assert "<b>Bold</b>" not in text and "&lt;b&gt;Bold&lt;/b&gt;" in text


def test_the_warning_shows_addresses_as_text_never_as_links() -> None:
    text = served().client.post("/open", data={"address": copy_of(TOR_PROJECT) + ".onion"}).text
    assert f'href="http://{TOR_PROJECT}' not in text and '.onion/"' not in text
    assert "<script" not in text


def test_without_a_list_nothing_is_warned() -> None:
    env = Env(lambda _r: reply("<p>x</p>"))
    assert (
        env.client.post("/open", data={"address": copy_of(TOR_PROJECT) + ".onion"}).status_code
        == 303
    )


# --- reading the list --------------------------------------------------------------------------------


def test_the_list_gives_each_site_a_name_and_a_default_when_it_has_none() -> None:
    sites = parse_known_sites(f"# the sites\n{TOR_PROJECT}\n{DUCKDUCKGO}   Duck   Duck  # note\n\n")
    assert len(sites) == 2
    assert sites.lookalike_of(copy_of(TOR_PROJECT)).name == "a well-known site"  # type: ignore[union-attr]
    assert sites.lookalike_of(copy_of(DUCKDUCKGO)).name == "Duck Duck"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "line",
    [
        "not-an-address The Name",
        f"{TOR_PROJECT[:-1]} short",
        f"{TOR_PROJECT} bad\x07name",
        f"{TOR_PROJECT} " + "n" * 81,
        f"{TOR_PROJECT} caf\N{LATIN SMALL LETTER E WITH ACUTE}",
    ],
)
def test_a_bad_line_is_an_error_that_names_the_line(line: str) -> None:
    with pytest.raises(PolicyConfigError, match="line 2"):
        parse_known_sites(f"{DUCKDUCKGO} ok\n{line}\n")


def test_a_missing_or_huge_list_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyConfigError, match="cannot read"):
        load_known_sites(tmp_path / "none.txt")
    big = tmp_path / "big.txt"
    big.write_bytes(b"#" * 1_000_001)
    with pytest.raises(PolicyConfigError, match="too large"):
        load_known_sites(big)
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(PolicyConfigError, match="UTF-8"):
        load_known_sites(bad)


def test_two_listed_sites_that_share_a_start_both_work() -> None:
    twin = copy_of(TOR_PROJECT)
    sites = parse_known_sites(f"{TOR_PROJECT} Real\n{twin} Twin\n")
    third = copy_of(TOR_PROJECT)
    assert sites.lookalike_of(third) is not None
    assert sites.lookalike_of(twin) is None and sites.lookalike_of(TOR_PROJECT) is None


# --- the configuration -------------------------------------------------------------------------------


def test_the_config_loads_the_list_and_refuses_a_missing_file(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    assert "[known_sites]" in text
    layout.config.write_text(text, encoding="utf-8")
    config = load_config(layout.config)
    assert config.settings.known_sites is not None and len(config.settings.known_sites) >= 1
    layout.config.write_text(
        text.replace("lists/known-sites.txt", "lists/missing.txt"), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(layout.config)


def test_the_personal_command_takes_a_known_sites_file(tmp_path: Path) -> None:
    listing = tmp_path / "known.txt"
    listing.write_text(LIST, encoding="utf-8")
    gateway = build_gateway(port=9000, known_sites=listing)
    assert gateway.settings.known_sites is not None
    assert gateway.settings.known_sites.lookalike_of(copy_of(TOR_PROJECT)) is not None
    listing.write_text("garbage line\n", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="line 1"):
        build_gateway(port=9000, known_sites=listing)


def test_what_was_typed_is_escaped_when_it_goes_back_into_the_warning_form() -> None:
    typed = f"http://{copy_of(TOR_PROJECT)}.onion/x?a=1&b=2&c=%3C"
    page = served().client.post("/open", data={"address": typed})
    assert page.status_code == 200, page.text
    assert 'value="' + typed.replace("&", "&amp;") + '"' in page.text
