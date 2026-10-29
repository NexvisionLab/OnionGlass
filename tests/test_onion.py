# SPDX-License-Identifier: AGPL-3.0-only
"""Property P5: only valid version 3 onion addresses can become destinations."""

from __future__ import annotations

import base64
import contextlib
import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from onionglass.onion import (
    InvalidOnionError,
    is_valid_address,
    normalise_address,
    parse_onion_host,
    parse_onion_url,
)

# Addresses published by the Tor Project and DuckDuckGo. They are benign and well known.
TOR_PROJECT = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"
DUCKDUCKGO = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
KELVIN_SIGN = chr(0x212A)
CYRILLIC_A = chr(0x430)
E_ACUTE = chr(0xE9)
ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def make_address(public_key: bytes, version: int = 3) -> str:
    """An independent construction of an address, used to cross-check the validator."""
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + bytes([version])).digest()[:2]
    raw = public_key + checksum + bytes([version])
    return base64.b32encode(raw).decode("ascii").lower()


def test_real_addresses_are_valid() -> None:
    assert normalise_address(TOR_PROJECT) == TOR_PROJECT
    assert normalise_address(DUCKDUCKGO) == DUCKDUCKGO


def test_upper_case_is_normalised() -> None:
    assert normalise_address(TOR_PROJECT.upper()) == TOR_PROJECT


@given(st.binary(min_size=32, max_size=32))
def test_independently_built_addresses_validate(public_key: bytes) -> None:
    assert normalise_address(make_address(public_key)) == make_address(public_key)


def test_changing_any_checksum_or_version_character_is_rejected() -> None:
    # Characters 51 to 55 cover the checksum bytes and the version byte.
    for position in range(51, 56):
        for char in ALPHABET:
            if char == TOR_PROJECT[position]:
                continue
            changed = TOR_PROJECT[:position] + char + TOR_PROJECT[position + 1 :]
            assert not is_valid_address(changed)


def test_changing_a_key_character_agrees_with_an_independent_check() -> None:
    # Changing one key character breaks the checksum except for a rare collision (about one
    # in 65536 per change; the second character becoming "3" is one). The validator must
    # agree with the independent construction in every case, collisions included.
    accepted = 0
    for position in range(51):
        for char in ALPHABET:
            if char == TOR_PROJECT[position]:
                continue
            changed = TOR_PROJECT[:position] + char + TOR_PROJECT[position + 1 :]
            public_key = base64.b32decode(changed.upper())[:32]
            expected = make_address(public_key) == changed
            assert is_valid_address(changed) is expected
            accepted += expected
    assert accepted <= 2


def test_wrong_version_is_rejected() -> None:
    for version in (0, 1, 2, 4, 255):
        assert not is_valid_address(make_address(bytes(range(32)), version))


@pytest.mark.parametrize(
    "text",
    [
        "",
        "a" * 16,
        "a" * 55,
        "a" * 57,
        "abcdefghijklmnop",
        TOR_PROJECT[:-1],
        TOR_PROJECT + "a",
        " " + TOR_PROJECT,
        TOR_PROJECT + " ",
        TOR_PROJECT + "\n",
        TOR_PROJECT + "\x00",
        TOR_PROJECT.replace("a", "1", 1),
        TOR_PROJECT.replace("a", "-", 1),
    ],
)
def test_malformed_addresses_are_rejected(text: str) -> None:
    with pytest.raises(InvalidOnionError):
        normalise_address(text)


def test_non_ascii_lookalikes_are_rejected() -> None:
    # The Kelvin sign lower-cases to a plain "k". Lower-casing first would let it through.
    assert KELVIN_SIGN.lower() == "k"
    lookalike = DUCKDUCKGO.replace("k", KELVIN_SIGN, 1)
    assert len(lookalike) == 56
    with pytest.raises(InvalidOnionError):
        normalise_address(lookalike)
    with pytest.raises(InvalidOnionError):
        normalise_address(TOR_PROJECT.replace("a", CYRILLIC_A, 1))  # Cyrillic a


@given(st.text())
def test_arbitrary_text_never_raises_anything_but_invalid_onion(text: str) -> None:
    for parser in (normalise_address, parse_onion_host, parse_onion_url):
        with contextlib.suppress(InvalidOnionError):
            parser(text)


def test_host_accepts_trailing_dot_case_and_subdomains() -> None:
    assert parse_onion_host(f"{TOR_PROJECT}.onion").hostname == f"{TOR_PROJECT}.onion"
    assert parse_onion_host(f"{TOR_PROJECT.upper()}.ONION.").address == TOR_PROJECT
    host = parse_onion_host(f"www.blog.{TOR_PROJECT}.onion")
    assert host.address == TOR_PROJECT
    assert host.subdomains == ("www", "blog")
    assert host.hostname == f"www.blog.{TOR_PROJECT}.onion"


@pytest.mark.parametrize(
    "host",
    [
        "",
        ".",
        "onion",
        "a.onion",
        f"{TOR_PROJECT}.com",
        f"{TOR_PROJECT}.onion.example",
        f"{TOR_PROJECT}.onion..",
        f"..{TOR_PROJECT}.onion",
        f"-x.{TOR_PROJECT}.onion",
        f"x-.{TOR_PROJECT}.onion",
        f"a_b.{TOR_PROJECT}.onion",
        f"{'a' * 64}.{TOR_PROJECT}.onion",
        f"a.b.c.d.e.{TOR_PROJECT}.onion",
        f"{TOR_PROJECT}.onion\n",
        "127.0.0.1",
        "localhost",
    ],
)
def test_bad_hosts_are_rejected(host: str) -> None:
    with pytest.raises(InvalidOnionError):
        parse_onion_host(host)


def test_url_round_trip_and_defaults() -> None:
    parsed = parse_onion_url(f"https://{TOR_PROJECT}.onion:443/path/x?q=1#fragment")
    assert parsed.scheme == "https"
    assert parsed.port == 443
    assert parsed.path == "/path/x"
    assert parsed.query == "q=1"
    assert parsed.url == f"https://{TOR_PROJECT}.onion/path/x?q=1"
    assert parse_onion_url(f"http://{TOR_PROJECT}.onion").path == "/"
    assert parse_onion_url(f"HTTP://{TOR_PROJECT}.onion/").scheme == "http"


def test_url_ports_are_restricted_unless_allowed() -> None:
    with pytest.raises(InvalidOnionError):
        parse_onion_url(f"http://{TOR_PROJECT}.onion:8080/")
    allowed = parse_onion_url(f"http://{TOR_PROJECT}.onion:8080/", allowed_ports=frozenset({8080}))
    assert allowed.port == 8080
    assert allowed.url == f"http://{TOR_PROJECT}.onion:8080/"


@pytest.mark.parametrize(
    "url",
    [
        f"ftp://{TOR_PROJECT}.onion/",
        f"//{TOR_PROJECT}.onion/",
        f"{TOR_PROJECT}.onion/",
        f"http://{TOR_PROJECT}.onion:22/",
        f"http://{TOR_PROJECT}.onion:0/",
        f"http://{TOR_PROJECT}.onion:99999/",
        f"http://{TOR_PROJECT}.onion:80:90/",
        f"http://{TOR_PROJECT}.onion:/",
        f"http://user@{TOR_PROJECT}.onion/",
        f"http://{TOR_PROJECT}.onion:80@evil.example/",
        f"http://evil.example\\@{TOR_PROJECT}.onion/",
        f"http:\\\\{TOR_PROJECT}.onion/",
        f"http://{TOR_PROJECT}.onion/a\tb",
        f"http://{TOR_PROJECT}.onion/a\nb",
        f"http://{TOR_PROJECT}.onion/a b",
        f"http://{TOR_PROJECT}.onion/\x00",
        f"http://{TOR_PROJECT}.onion/{E_ACUTE}",
        "http://127.0.0.1/",
        "http://[::1]/",
        f"http://[::1]/{TOR_PROJECT}.onion",
        "http://evil.example/",
        f"http://evil.example/{TOR_PROJECT}.onion",
        f"http://evil.example#@{TOR_PROJECT}.onion/",
        f"http://{TOR_PROJECT}.onion.evil.example/",
        f"http://{TOR_PROJECT}.evil.example/",
        "http:///path",
        "",
        "http://" + "a" * 9000,
    ],
)
def test_bad_urls_are_rejected(url: str) -> None:
    with pytest.raises(InvalidOnionError):
        parse_onion_url(url)
