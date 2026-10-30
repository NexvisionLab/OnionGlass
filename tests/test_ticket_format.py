# SPDX-License-Identifier: AGPL-3.0-only
"""The ticket format as written in docs/integration-api.md.

The ticket maker below is written from that description alone and does not use the project's
own issuer. If the document and the gateway ever disagree, one of these tests fails, which is what
keeps a sign-in service built from the page working.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from helpers import DUCKDUCKGO
from onionglass.gateway import Gateway
from onionglass.settings import Settings
from onionglass.tickets import KeyRing, TicketError, TicketVerifier, generate_key
from test_gateway import FakeFetcher

DOCUMENT = (Path(__file__).resolve().parent.parent / "docs" / "integration-api.md").read_text(
    encoding="utf-8"
)
NOW = 1_700_000_000
KEY = generate_key()
OTHER_KEY = generate_key()
AUDIENCE = "onionglass"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def good_claims(**changes: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "sub": "account-1", "grp": "staff", "prf": "free", "jti": "j" * 16,
        "iat": NOW, "exp": NOW + 60, "aud": AUDIENCE,
    }  # fmt: skip
    claims.update(changes)
    return {k: v for k, v in claims.items() if v is not None}


def make(
    claims: dict[str, Any] | bytes | None = None,
    *,
    signer: Ed25519PrivateKey = KEY,
    key_id: str = "k1",
    signed_key_id: str | None = None,
    context: bytes = b"onionglass ticket v1",
    prefix: str = "og1",
) -> str:
    payload = (
        claims
        if isinstance(claims, bytes)
        else json.dumps(good_claims() if claims is None else claims, separators=(",", ":")).encode()
    )
    signed = context + b"\x00" + (signed_key_id or key_id).encode() + b"\x00" + payload
    return ".".join([prefix, key_id, b64(payload), b64(signer.sign(signed))])


def verifier(**kwargs: Any) -> TicketVerifier:
    ring = KeyRing()
    ring.add("k1", KEY.public_key())
    return TicketVerifier(ring, AUDIENCE, clock=lambda: float(NOW), **kwargs)


def reason(token: str) -> str:
    with pytest.raises(TicketError) as caught:
        verifier().verify(token)
    return caught.value.reason


# --- a ticket made from the document is accepted ---------------------------------------------------


def test_a_ticket_made_from_the_description_is_accepted() -> None:
    claims = verifier().verify(make())
    assert (claims.subject, claims.group, claims.profile, claims.audience) == (
        "account-1", "staff", "free", AUDIENCE,
    )  # fmt: skip
    assert claims.onion is None and claims.expires_at - claims.issued_at == 60


def test_the_onion_claim_is_the_address_without_the_suffix() -> None:
    claims = verifier().verify(make(good_claims(onion=DUCKDUCKGO)))
    assert claims.onion == DUCKDUCKGO
    assert reason(make(good_claims(onion=f"{DUCKDUCKGO}.onion"))) == "bad_claims"
    assert reason(make(good_claims(onion="tooshort"))) == "bad_claims"


# --- every rule in the document is enforced --------------------------------------------------------


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (make(prefix="og2"), "malformed"),
        (make(key_id=""), "malformed"),
        (make(key_id="k" * 33), "malformed"),
        (make(key_id="bad id"), "malformed"),
        (make(key_id="a.b"), "malformed"),
        (make(key_id="other"), "unknown_key"),
        (make(signer=OTHER_KEY), "bad_signature"),
        (make(context=b"onionglass ticket v2"), "bad_signature"),
        (make(signed_key_id="k2"), "bad_signature"),
        (make().rsplit(".", 1)[0] + "." + "=", "malformed"),
        ("og1.k1." + b64(b"{}") + "=." + b64(b"x"), "malformed"),
        ("x" * 4097, "malformed"),
    ],
)
def test_a_ticket_that_breaks_the_format_is_refused(token: str, expected: str) -> None:
    assert reason(token) == expected


def test_padding_and_a_non_canonical_encoding_are_refused() -> None:
    token = make()
    head, payload, signature = token.rsplit(".", 2)
    assert reason(f"{head}.{payload}=.{signature}") == "malformed"
    assert reason(f"{head}.{payload}.{signature}=") == "malformed"
    assert reason(f"{head}.{payload}+.{signature}") == "malformed"
    assert reason(token.replace("og1", "og1" + chr(0xE9))) == "malformed"


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        (good_claims(sub=None), "bad_claims"),
        (good_claims(grp=None), "bad_claims"),
        (good_claims(prf=None), "bad_claims"),
        (good_claims(jti=None), "bad_claims"),
        (good_claims(iat=None), "bad_claims"),
        (good_claims(exp=None), "bad_claims"),
        (good_claims(aud=None), "bad_claims"),
        (good_claims(extra="x"), "bad_claims"),
        (good_claims(jti="j" * 15), "bad_claims"),
        (good_claims(jti="j" * 65), "bad_claims"),
        (good_claims(sub="s" * 257), "bad_claims"),
        (good_claims(sub=""), "bad_claims"),
        (good_claims(sub="has space"), "bad_claims"),
        (good_claims(grp="g" * 129), "bad_claims"),
        (good_claims(prf="p" * 129), "bad_claims"),
        (good_claims(sub="caf" + chr(0xE9)), "bad_claims"),
        (good_claims(sub=7), "bad_claims"),
        (good_claims(iat=float(NOW)), "bad_claims"),
        (good_claims(iat=str(NOW)), "bad_claims"),
        (good_claims(exp=True), "bad_claims"),
        (good_claims(iat=-1), "bad_claims"),
        (good_claims(exp=4_102_444_801), "bad_claims"),
        (good_claims(aud="another-gateway"), "wrong_audience"),
        (good_claims(exp=NOW), "bad_lifetime"),
        (good_claims(exp=NOW - 5), "bad_lifetime"),
        (good_claims(exp=NOW + 301), "bad_lifetime"),
        (good_claims(iat=NOW + 31, exp=NOW + 91), "not_yet_valid"),
        (good_claims(iat=NOW - 200, exp=NOW - 31), "expired"),
    ],
)
def test_a_claim_that_breaks_a_rule_is_refused(claims: dict[str, Any], expected: str) -> None:
    assert reason(make(claims)) == expected


def test_a_repeated_claim_name_is_refused() -> None:
    body = (
        b'{"sub":"a","sub":"b","grp":"g","prf":"free","jti":"jjjjjjjjjjjjjjjj",'
        b'"iat":1700000000,"exp":1700000060,"aud":"onionglass"}'
    )
    assert reason(make(body)) == "bad_claims"
    assert reason(make(b"[1,2,3]")) == "bad_claims"
    assert reason(make(b"not json")) == "bad_claims"


def test_the_limits_in_the_document_are_the_limits_that_work() -> None:
    edge = good_claims(
        sub="s" * 256, grp="g" * 128, prf="p" * 128, jti="j" * 64, aud=AUDIENCE, exp=NOW + 300
    )
    assert verifier().verify(make(edge)).subject == "s" * 256
    assert verifier().verify(make(good_claims(jti="j" * 16))).ticket_id == "j" * 16
    assert verifier().verify(make(good_claims(iat=NOW + 30, exp=NOW + 90))).issued_at == NOW + 30
    # 30 seconds after expiry is already too late, and one second before is not.
    assert verifier().verify(make(good_claims(iat=NOW - 100, exp=NOW - 29))).expires_at == NOW - 29


# --- through the gateway -----------------------------------------------------------------------------


def team_gateway() -> TestClient:
    ring = KeyRing()
    ring.add("k1", KEY.public_key())
    settings = Settings(base_domain="gw.example", keys=ring, audience=AUDIENCE)
    gateway = Gateway(settings, fetcher=FakeFetcher())
    return TestClient(gateway.app, base_url="https://gw.example", follow_redirects=False)


def fresh(**changes: Any) -> str:
    now = int(time.time())
    return make(
        good_claims(
            iat=now, exp=now + 60, jti=f"{now}-{changes.pop('serial', 'a')}-unique-id", **changes
        )
    )


def test_the_gateway_signs_in_a_visitor_with_a_ticket_made_from_the_document() -> None:
    web = team_gateway()
    response = web.get("/enter", params={"t": fresh(serial="1", prf="personal")})
    assert response.status_code == 303 and "set-cookie" in response.headers
    assert response.headers["location"] == "https://gw.example/"


def test_a_ticket_with_an_onion_goes_straight_to_the_viewer_for_it() -> None:
    web = team_gateway()
    response = web.get("/enter", params={"t": fresh(serial="2", prf="personal", onion=DUCKDUCKGO)})
    assert response.status_code == 303 and "/view?l=" in response.headers["location"]
    assert DUCKDUCKGO not in response.headers["location"]


def test_a_ticket_works_once() -> None:
    web = team_gateway()
    ticket = fresh(serial="3", prf="personal")
    assert web.get("/enter", params={"t": ticket}).status_code == 303
    assert web.get("/enter", params={"t": ticket}).status_code == 403


def test_the_gateway_refuses_what_the_document_says_it_refuses() -> None:
    web = team_gateway()
    assert (
        web.get("/enter", params={"t": fresh(serial="4", prf="not-a-profile")}).status_code == 403
    )
    assert web.get("/enter", params={"t": make(signer=OTHER_KEY)}).status_code == 403
    assert web.get("/enter", params={"t": fresh(serial="5", aud="elsewhere")}).status_code == 403


# --- the document says what the code does -------------------------------------------------------------


@pytest.mark.parametrize(
    "phrase",
    [
        "og1.<key id>.<payload>.<signature>", "onionglass ticket v1", "4096 characters",
        "1 to 32 characters", "16 to 64 characters", "at most 300 seconds", "30 seconds",
        "1 to 256 characters", "4102444800", "56-character address without `.onion`",
    ],
)  # fmt: skip
def test_the_document_states_each_rule(phrase: str) -> None:
    assert phrase in DOCUMENT
