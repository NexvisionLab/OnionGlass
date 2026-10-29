# SPDX-License-Identifier: AGPL-3.0-only
"""Property P9: tickets cannot be forged, replayed after use, or used after expiry."""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

from onionglass.onion import InvalidOnionError
from onionglass.store import InMemoryStore
from onionglass.tickets import (
    MAX_LIFETIME_SECONDS,
    SIGNING_CONTEXT,
    KeyRing,
    TicketError,
    TicketIssuer,
    TicketVerifier,
    generate_key,
)

TOR_PROJECT = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"
AUDIENCE = "gateway-one"
NOW = 1_800_000_000


class FakeClock:
    def __init__(self, now: float = NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Setup:
    def __init__(self) -> None:
        self.clock = FakeClock()
        self.key = generate_key()
        self.ring = KeyRing()
        self.ring.add("k1", self.key.public_key())
        self.issuer = TicketIssuer(self.key, "k1", AUDIENCE, clock=self.clock)
        self.verifier = TicketVerifier(self.ring, AUDIENCE, clock=self.clock)

    def issue(self, **overrides: Any) -> str:
        args: dict[str, Any] = {"subject": "visitor-1", "group": "team-a", "profile": "analyst"}
        args.update(overrides)
        return self.issuer.issue(**args)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def forge(key: Ed25519PrivateKey, kid: str, payload: bytes) -> str:
    """Sign arbitrary payload bytes in the real wire format, to test claim validation."""
    signature = key.sign(SIGNING_CONTEXT + kid.encode("ascii") + b"\x00" + payload)
    return f"og1.{kid}.{b64(payload)}.{b64(signature)}"


def good_claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "sub": "visitor-1",
        "grp": "team-a",
        "prf": "analyst",
        "jti": "abcdefghijklmnopqrstuv",
        "iat": NOW,
        "exp": NOW + 60,
        "aud": AUDIENCE,
    }
    claims.update(overrides)
    return claims


def forge_claims(setup: Setup, claims: dict[str, Any]) -> str:
    payload = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    return forge(setup.key, "k1", payload)


def reason(setup: Setup, token: str) -> str:
    with pytest.raises(TicketError) as info:
        setup.verifier.verify(token)
    return info.value.reason


def test_a_valid_ticket_verifies() -> None:
    s = Setup()
    claims = s.verifier.verify(s.issue(onion=TOR_PROJECT.upper()))
    assert claims.subject == "visitor-1"
    assert claims.group == "team-a"
    assert claims.profile == "analyst"
    assert claims.audience == AUDIENCE
    assert claims.onion == TOR_PROJECT
    assert claims.expires_at - claims.issued_at == 60


def test_the_error_message_is_generic() -> None:
    s = Setup()
    with pytest.raises(TicketError) as info:
        s.verifier.verify("og1.k1.bad.bad")
    assert str(info.value) == "ticket rejected"


def test_a_changed_payload_or_signature_is_rejected() -> None:
    s = Setup()
    token = s.issue()
    prefix, kid, payload, signature = token.split(".")
    other = forge_claims(s, good_claims(sub="someone-else")).split(".")[2]
    assert reason(s, ".".join((prefix, kid, other, signature))) == "bad_signature"
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    assert reason(s, ".".join((prefix, kid, payload, flipped))) == "bad_signature"


def test_a_ticket_signed_by_another_key_is_rejected() -> None:
    s = Setup()
    assert reason(s, forge_claims_with(generate_key(), "k1")) == "bad_signature"


def forge_claims_with(key: Ed25519PrivateKey, kid: str) -> str:
    return forge(key, kid, json.dumps(good_claims(), separators=(",", ":")).encode("utf-8"))


def test_the_key_id_is_bound_into_the_signature() -> None:
    s = Setup()
    s.ring.add("k2", s.key.public_key())  # same key under another id
    token = s.issue()
    prefix, _, payload, signature = token.split(".")
    assert reason(s, ".".join((prefix, "k2", payload, signature))) == "bad_signature"


def test_an_unknown_key_id_is_rejected() -> None:
    s = Setup()
    prefix, _, payload, signature = s.issue().split(".")
    assert reason(s, ".".join((prefix, "nope", payload, signature))) == "unknown_key"


def test_key_rotation_accepts_both_keys_then_drops_the_old_one() -> None:
    s = Setup()
    new_key = generate_key()
    s.ring.add("k2", new_key.public_key())
    new_issuer = TicketIssuer(new_key, "k2", AUDIENCE, clock=s.clock)
    old_ticket = s.issue()
    new_ticket = new_issuer.issue(subject="visitor-2", group="g", profile="restricted")
    assert s.verifier.verify(old_ticket).subject == "visitor-1"
    assert s.verifier.verify(new_ticket).subject == "visitor-2"
    s.ring.remove("k1")
    assert reason(s, old_ticket) == "unknown_key"
    assert s.verifier.verify(new_ticket).subject == "visitor-2"


def test_time_window() -> None:
    s = Setup()
    token = s.issue(lifetime=60)
    s.clock.now = NOW + 60 + 29  # inside the skew allowance
    assert s.verifier.verify(token)
    s.clock.now = NOW + 60 + 30
    assert reason(s, token) == "expired"
    s.clock.now = NOW - 29
    assert s.verifier.verify(token)
    s.clock.now = NOW - 31
    assert reason(s, token) == "not_yet_valid"


def test_lifetime_limits() -> None:
    s = Setup()
    with pytest.raises(ValueError, match="lifetime"):
        s.issue(lifetime=MAX_LIFETIME_SECONDS + 1)
    with pytest.raises(ValueError, match="lifetime"):
        s.issue(lifetime=0)
    too_long = forge_claims(s, good_claims(exp=NOW + MAX_LIFETIME_SECONDS + 1))
    assert reason(s, too_long) == "bad_lifetime"
    backwards = forge_claims(s, good_claims(exp=NOW - 1))
    assert reason(s, backwards) == "bad_lifetime"


def test_wrong_audience_is_rejected() -> None:
    s = Setup()
    other = TicketIssuer(s.key, "k1", "gateway-two", clock=s.clock).issue(
        subject="v", group="g", profile="p"
    )
    assert reason(s, other) == "wrong_audience"


def test_a_ticket_can_only_be_redeemed_once() -> None:
    async def scenario() -> None:
        s = Setup()
        store = InMemoryStore(clock=s.clock)
        token = s.issue()
        claims = await s.verifier.redeem(token, store)
        assert claims.subject == "visitor-1"
        with pytest.raises(TicketError) as info:
            await s.verifier.redeem(token, store)
        assert info.value.reason == "replayed"
        # Two different tickets for the same visitor are independent.
        await s.verifier.redeem(s.issue(), store)

    asyncio.run(scenario())


def test_a_bad_ticket_does_not_consume_anything() -> None:
    async def scenario() -> None:
        s = Setup()
        store = InMemoryStore(clock=s.clock)
        with pytest.raises(TicketError):
            await s.verifier.redeem(forge_claims(s, good_claims(aud="other")), store)
        # The same ticket id with correct claims still redeems.
        await s.verifier.redeem(forge_claims(s, good_claims()), store)

    asyncio.run(scenario())


def test_the_issuer_rejects_a_bad_onion_claim() -> None:
    s = Setup()
    with pytest.raises(InvalidOnionError):
        s.issue(onion="not-an-onion")


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": ""},
        {"sub": "has space"},
        {"sub": "tab\there"},
        {"sub": "x" * 257},
        {"sub": 5},
        {"grp": None},
        {"prf": ""},
        {"jti": "short"},
        {"jti": "x" * 65},
        {"iat": True},
        {"iat": 1.5},
        {"iat": -1},
        {"iat": 10**12},
        {"iat": "1800000000"},
        {"exp": None},
        {"aud": ""},
        {"onion": "not-an-onion"},
        {"onion": 5},
        {"extra": "field"},
    ],
)
def test_bad_claim_values_are_rejected(claims: dict[str, Any]) -> None:
    s = Setup()
    assert reason(s, forge_claims(s, good_claims(**claims))) == "bad_claims"


def test_missing_required_claims_are_rejected() -> None:
    s = Setup()
    for key in ("sub", "grp", "prf", "jti", "iat", "exp", "aud"):
        claims = good_claims()
        del claims[key]
        assert reason(s, forge_claims(s, claims)) == "bad_claims"


def test_unusual_payload_shapes_are_rejected() -> None:
    s = Setup()
    duplicate = (
        b'{"aud":"gateway-one","exp":1800000060,"grp":"g","iat":1800000000,'
        b'"jti":"abcdefghijklmnopqrstuv","prf":"p","sub":"a","sub":"b"}'
    )
    for payload in (
        duplicate,
        b"[]",
        b'"text"',
        b"null",
        b"{",
        b"\xff\xfe",
        b"[" * 1500,
        b"{" + b'"a":{' * 400 + b"1" + b"}" * 400 + b"}",
    ):
        assert reason(s, forge(s.key, "k1", payload)) == "bad_claims"
    # An empty payload leaves an empty token segment, which is malformed before any parsing.
    assert reason(s, forge(s.key, "k1", b"")) == "malformed"


@pytest.mark.parametrize(
    "token",
    [
        "",
        "og1",
        "og1.k1",
        "og1.k1.a",
        "og1.k1.a.b.c",
        "og2.k1.aaaa.bbbb",
        "OG1.k1.aaaa.bbbb",
        "og1..aaaa.bbbb",
        "og1.k1..bbbb",
        "og1.k1.aaaa.",
        "og1.k1.aa==.bbbb",
        "og1.k1.a+aa.bbbb",
        "og1.k1.a/aa.bbbb",
        "og1.k1.aaaa.bbbb ",
        "og1.k1.aaaa.bbbb\n",
        "og1.k1." + chr(0xE9) + "aaa.bbbb",
        "og1." + "k" * 33 + ".aaaa.bbbb",
        "og1.k1." + "a" * 5000 + ".bbbb",
    ],
)
def test_malformed_tokens_are_rejected(token: str) -> None:
    s = Setup()
    with pytest.raises(TicketError):
        s.verifier.verify(token)


def test_non_canonical_base64_is_rejected() -> None:
    s = Setup()
    prefix, kid, payload, signature = s.issue().split(".")
    # The last character of an unpadded string can carry unused bits. Changing only those bits
    # decodes to the same bytes, so it must be refused rather than treated as the same ticket.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    variants = [c for c in alphabet if c != signature[-1]]
    results = []
    for char in variants:
        results.append(reason(s, ".".join((prefix, kid, payload, signature[:-1] + char))))
    assert set(results) <= {"malformed", "bad_signature"}
    assert "malformed" in results


@given(st.text(max_size=300))
def test_arbitrary_text_only_ever_raises_ticket_error(text: str) -> None:
    s = Setup()
    with pytest.raises(TicketError):
        s.verifier.verify(text)


FIXED = Setup()
FIXED_TOKEN = FIXED.issue(onion=TOR_PROJECT)


@given(
    index=st.integers(min_value=0, max_value=len(FIXED_TOKEN) - 1),
    char=st.characters(codec="ascii"),
)
def test_any_single_character_change_to_a_valid_ticket_is_rejected(index: int, char: str) -> None:
    if FIXED_TOKEN[index] == char:
        return
    mutated = FIXED_TOKEN[:index] + char + FIXED_TOKEN[index + 1 :]
    with pytest.raises(TicketError):
        FIXED.verifier.verify(mutated)
