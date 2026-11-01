# SPDX-License-Identifier: AGPL-3.0-only
"""The signature a relay puts on each request it sends to the gateway, and the check the gateway
makes. A request that was not signed by a relay the gateway knows is treated as a stranger's."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

from onionglass.relayauth import (
    HEADER,
    MAX_HEADER_CHARS,
    RelayAuthError,
    RelaySigner,
    RelayVerifier,
)
from onionglass.tickets import KeyRing, generate_key

NOW = 1_800_000_000.0
HOST = "k3f9.alpha.example.net"
TARGET = "/page?q=1"


class Clock:
    def __init__(self, now: float = NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def pair(
    key_id: str = "r1", clock: Clock | None = None, **options: int
) -> tuple[RelaySigner, RelayVerifier, Clock]:
    clock = clock or Clock()
    key = generate_key()
    ring = KeyRing()
    ring.add(key_id, key.public_key())
    return RelaySigner(key_id, key, clock), RelayVerifier(ring, clock=clock, **options), clock


def refused(
    verifier: RelayVerifier, value: str, method: str = "GET", host: str = HOST, target: str = TARGET
) -> str:
    with pytest.raises(RelayAuthError) as caught:
        verifier.verify(value, method, host, target)
    return caught.value.reason


def test_the_header_name_is_lower_case_and_plain() -> None:
    assert HEADER == "x-og-relay"


def test_a_signed_request_is_accepted_and_names_the_relay() -> None:
    signer, verifier, _ = pair("relay-one")
    assert verifier.verify(signer.sign("GET", HOST, TARGET), "GET", HOST, TARGET) == "relay-one"


@pytest.mark.parametrize(
    ("method", "host", "target"),
    [
        ("POST", HOST, TARGET),
        ("GET", "other.alpha.example.net", TARGET),
        ("GET", HOST, "/page?q=2"),
        ("GET", HOST, "/other"),
        ("GET", HOST.upper(), TARGET),
    ],
)
def test_a_signature_is_good_only_for_the_request_it_was_made_for(
    method: str, host: str, target: str
) -> None:
    signer, verifier, _ = pair()
    assert (
        refused(verifier, signer.sign("GET", HOST, TARGET), method, host, target) == "bad_signature"
    )


def test_a_signature_cannot_be_moved_between_fields() -> None:
    # "a" + "bc" and "ab" + "c" must not look the same to the check.
    signer, verifier, _ = pair()
    value = signer.sign("GET", "ab.example.net", "/c")
    assert refused(verifier, value, "GET", "a.example.net", "/bc") == "bad_signature"


def test_a_request_from_a_key_the_gateway_does_not_know_is_refused() -> None:
    signer, _, clock = pair("r1")
    _, other_verifier, _ = pair("r2", clock)
    assert refused(other_verifier, signer.sign("GET", HOST, TARGET)) == "unknown_key"


def test_a_key_taken_out_of_the_ring_stops_working_at_once() -> None:
    clock = Clock()
    key = generate_key()
    ring = KeyRing()
    ring.add("r1", key.public_key())
    signer, verifier = RelaySigner("r1", key, clock), RelayVerifier(ring, clock=clock)
    assert verifier.verify(signer.sign("GET", HOST, TARGET), "GET", HOST, TARGET) == "r1"
    ring.remove("r1")
    assert refused(verifier, signer.sign("GET", HOST, TARGET)) == "unknown_key"


def test_another_key_under_the_same_id_is_refused() -> None:
    clock = Clock()
    ring = KeyRing()
    ring.add("r1", generate_key().public_key())
    impostor = RelaySigner("r1", generate_key(), clock)
    assert (
        refused(RelayVerifier(ring, clock=clock), impostor.sign("GET", HOST, TARGET))
        == "bad_signature"
    )


def test_each_signature_is_new() -> None:
    signer, _, _ = pair()
    assert signer.sign("GET", HOST, TARGET) != signer.sign("GET", HOST, TARGET)


def test_the_same_signature_cannot_be_used_twice() -> None:
    signer, verifier, _ = pair()
    value = signer.sign("POST", HOST, TARGET)
    verifier.verify(value, "POST", HOST, TARGET)
    assert refused(verifier, value, "POST") == "replayed"


def test_a_refused_signature_is_not_remembered_as_used() -> None:
    signer, verifier, _ = pair()
    value = signer.sign("GET", HOST, TARGET)
    assert refused(verifier, value, "POST") == "bad_signature"  # wrong method, so not accepted
    assert verifier.verify(value, "GET", HOST, TARGET) == "r1"  # the right request still works


def test_a_signature_that_is_too_old_or_too_new_is_refused_and_the_edge_is_kept() -> None:
    clock = Clock()
    signer, verifier, _ = pair(clock=clock, skew=60)
    for offset, ok in ((-60, True), (-61, False), (60, True), (61, False)):
        clock.now = NOW + offset
        value = signer.sign("GET", HOST, TARGET)
        clock.now = NOW
        if ok:
            assert verifier.verify(value, "GET", HOST, TARGET) == "r1"
        else:
            assert refused(verifier, value) == "stale"


def test_a_used_signature_is_remembered_only_while_it_could_still_be_accepted() -> None:
    signer, verifier, clock = pair(skew=60)
    value = signer.sign("GET", HOST, TARGET)
    verifier.verify(value, "GET", HOST, TARGET)
    assert verifier.remembered() == 1
    clock.now = NOW + 500  # long after it could have been accepted
    assert refused(verifier, value) == "stale"
    verifier.verify(signer.sign("GET", HOST, TARGET), "GET", HOST, TARGET)
    assert verifier.remembered() == 1  # the old one was forgotten, the new one is kept


def test_the_memory_of_used_signatures_has_a_limit() -> None:
    signer, verifier, _ = pair(capacity=3)
    for _ in range(10):
        verifier.verify(signer.sign("GET", HOST, TARGET), "GET", HOST, TARGET)
    assert verifier.remembered() == 3


@pytest.mark.parametrize(
    "value",
    [
        "",
        "r1",
        "r1.1800000000",
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA",
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86 + ".extra",
        "r1.18000.00000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86,
        "r1.abc.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86,
        "r1.-1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86,
        "r1.01800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86,
        "r1.99999999999999999999999.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86,
        "r1.1800000000.AAAA." + "A" * 86,
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 85,
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 87,
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA.=" + "A" * 85,
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 85 + "B",  # not the canonical encoding
        ".1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86,
        "r 1.1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86,
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86 + " ",
        "r1.1800000000.AAAAAAAAAAAAAAAAAAAAAA." + chr(233) + "A" * 85,
        "x" * (MAX_HEADER_CHARS + 1),
    ],
)
def test_anything_that_is_not_a_well_formed_signature_is_refused_as_malformed(value: str) -> None:
    _, verifier, _ = pair()
    assert refused(verifier, value) == "malformed"


def test_the_signer_will_not_sign_what_could_not_be_checked() -> None:
    signer, _, _ = pair()
    for method, host, target in (
        ("GET", "a\x00b", "/"),
        ("GET", "a\r\nb", "/"),
        ("GET", HOST, "/a\nb"),
        ("GE T", HOST, "/"),
        ("", HOST, "/"),
        ("GET", "", "/"),
        ("GET", HOST, ""),
    ):
        with pytest.raises(ValueError, match=r"capital letters|printable"):
            signer.sign(method, host, target)


def test_a_key_id_that_could_break_the_format_is_refused_by_the_signer() -> None:
    for bad in ("", "a.b", "a b", "x" * 33):
        with pytest.raises(ValueError, match="relay key id"):
            RelaySigner(bad, Ed25519PrivateKey.generate())


def test_the_header_never_carries_the_key_and_stays_short() -> None:
    key = generate_key()
    ring = KeyRing()
    ring.add("r1", key.public_key())
    value = RelaySigner("r1", key, Clock()).sign("GET", HOST, TARGET)
    assert value.isascii() and len(value) <= MAX_HEADER_CHARS
    assert value.count(".") == 3


@given(st.text(max_size=400))
def test_whatever_text_arrives_the_check_only_ever_refuses_it(text: str) -> None:
    _, verifier, _ = pair()
    try:
        verifier.verify(text, "GET", HOST, TARGET)
    except RelayAuthError:
        pass
    else:  # a random string must not pass
        raise AssertionError("accepted")


@given(
    method=st.sampled_from(["GET", "POST", "HEAD"]),
    host=st.text(alphabet="abcdefgh0123.-", min_size=1, max_size=40),
    target=st.text(alphabet="/abc?=&%0123456789", min_size=1, max_size=60),
)
def test_whatever_is_signed_is_accepted_for_exactly_that_request(
    method: str, host: str, target: str
) -> None:
    signer, verifier, _ = pair()
    value = signer.sign(method, host, target)
    assert verifier.verify(value, method, host, target) == "r1"
