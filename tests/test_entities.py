# SPDX-License-Identifier: AGPL-3.0-only
"""Finding wallets, email addresses and onion addresses in the text of a page.

The checksums are tested against published examples, and Monero, which has none that are easy to
quote, against addresses the test builds with its own encoder.
"""

from __future__ import annotations

import os
import time

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT, fresh_address
from onionglass.entities import (
    MAX_ENTITIES,
    MAX_PER_KIND,
    Entity,
    extract_entities,
    keccak256,
    valid_bitcoin_legacy,
    valid_bitcoin_segwit,
    valid_ethereum,
    valid_monero,
)

GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
SCRIPT = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
SEGWIT = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
SEGWIT_UPPER = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
TAPROOT = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
EIP55 = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def monero_address(prefix: int = 0x12) -> str:
    """A Monero address made the way the format says, to test the decoder against."""
    body = bytes([prefix]) + os.urandom(64)
    raw = body + keccak256(body)[:4]
    sizes = (0, 2, 3, 5, 6, 7, 9, 10, 11)
    out = ""
    for start in range(0, len(raw), 8):
        block = raw[start : start + 8]
        number = int.from_bytes(block, "big")
        digits = ""
        for _ in range(sizes[len(block)]):
            number, rest = divmod(number, 58)
            digits = _B58[rest] + digits
        out += digits
    return out


def kinds(text: str) -> list[tuple[str, str]]:
    return [(e.kind, e.value) for e in extract_entities(text)]


# --- the hash ------------------------------------------------------------------------------------------


def test_keccak_matches_the_published_values_and_is_not_sha3() -> None:
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    assert keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )
    assert keccak256(b"a" * 200) != keccak256(b"a" * 199)  # more than one block
    assert keccak256(b"abc") != __import__("hashlib").sha3_256(b"abc").digest()


# --- each kind -----------------------------------------------------------------------------------------


def test_bitcoin_addresses_of_every_form_are_found_only_if_their_checksum_holds() -> None:
    for good in (GENESIS, SCRIPT, SEGWIT, SEGWIT_UPPER, TAPROOT):
        assert valid_bitcoin_legacy(good) or valid_bitcoin_segwit(good), good
    assert kinds(f"pay {GENESIS} or {SCRIPT}") == [("bitcoin", GENESIS), ("bitcoin", SCRIPT)]
    assert kinds(SEGWIT_UPPER) == [("bitcoin", SEGWIT_UPPER.lower())]
    assert kinds(TAPROOT) == [("bitcoin", TAPROOT)]
    wrong = GENESIS[:-1] + ("b" if GENESIS[-1] != "b" else "c")
    assert kinds(wrong) == []
    assert kinds(SEGWIT[:-1] + "x") == []
    assert kinds(SEGWIT[:10] + SEGWIT[10:].upper()) == []  # mixed case is not allowed


def test_ethereum_addresses_need_their_capitals_to_be_right_when_they_have_any() -> None:
    for good in EIP55:
        assert valid_ethereum(good)
        assert kinds(f"send to {good}.") == [("ethereum", good)]
        flipped = good[:3] + good[3].swapcase() + good[4:]
        if flipped != good and any(c.isalpha() for c in good[3:5]):
            assert not valid_ethereum(flipped) or good[3].isdigit()
    plain = "0x" + "ab12" * 10
    assert kinds(plain) == [("ethereum", plain)]  # no capitals, nothing to check
    assert kinds("0x" + "ab12" * 10 + "f") == []  # one digit too many
    broken = EIP55[0][:-1] + EIP55[0][-1].swapcase()
    assert kinds(broken) == []


def test_monero_addresses_are_found_only_if_their_checksum_holds() -> None:
    good = monero_address()
    assert len(good) == 95 and valid_monero(good)
    assert kinds(f"donate: {good}") == [("monero", good)]
    changed = good[:50] + ("2" if good[50] != "2" else "3") + good[51:]
    assert not valid_monero(changed) and kinds(changed) == []
    assert kinds(monero_address(prefix=0x2A))[0][0] == "monero"
    assert kinds(monero_address(prefix=0x13)) == []  # not a main-net prefix


def test_email_addresses_are_found_and_lower_cased() -> None:
    assert kinds("write to Sales.Team+x@Example.org, or a@example.net.") == [
        ("email", "sales.team+x@example.org"),
        ("email", "a@example.net"),
    ]
    assert kinds("not an email: @example.org or user@ or user@localhost") == []


def test_onion_addresses_are_found_with_their_checksum_and_without_the_sub_domain() -> None:
    other = fresh_address()
    text = (
        f"see http://www.{TOR_PROJECT}.onion/page and {DUCKDUCKGO}.onion, not {other[:-2]}ab.onion"
    )
    assert kinds(text) == [("onion", TOR_PROJECT + ".onion"), ("onion", DUCKDUCKGO + ".onion")]


# --- what must not match -------------------------------------------------------------------------------


def test_hashes_tokens_and_words_are_not_entities() -> None:
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    text = f"{sha256} {'0x' + sha256} {'Aa1' * 30} word@"
    assert kinds(text) == []


def test_an_address_inside_a_longer_word_is_not_picked_out() -> None:
    assert kinds(f"x{GENESIS}") == []
    assert kinds(f"{GENESIS}x") == []
    assert kinds(f"({GENESIS})") == [("bitcoin", GENESIS)]


def test_each_entity_is_reported_once_in_order_and_within_limits() -> None:
    text = f"{SCRIPT} {GENESIS} {SCRIPT} {GENESIS}"
    assert kinds(text) == [("bitcoin", SCRIPT), ("bitcoin", GENESIS)]
    many = " ".join(f"user{n}@example.org" for n in range(500))
    found = extract_entities(many)
    assert len(found) == MAX_PER_KIND
    mixed = " ".join(f"u{n}@example.org {monero_address()}" for n in range(60))
    assert len(extract_entities(mixed)) <= MAX_ENTITIES
    assert Entity("email", "user0@example.org") in found


def test_a_huge_hostile_text_is_read_in_bounded_time() -> None:
    hostile = ("1" * 40 + "@" + "a" * 70 + "." + "0x" + "f" * 39 + " ") * 4000
    hostile += "a" * 300_000 + "." * 100_000
    started = time.perf_counter()
    extract_entities(hostile)
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize("text", ["", " ", "\n\n", "\x00\x01", "bc1", "0x", "@", "1"])
def test_odd_short_texts_find_nothing_and_do_not_fail(text: str) -> None:
    assert extract_entities(text) == []
