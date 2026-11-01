# SPDX-License-Identifier: AGPL-3.0-only
"""Generated requests and generated answers: whatever a visitor sends or the gateway says, the
relay ends with an answer, forwards only what it should, and passes on nothing about the visitor."""

from __future__ import annotations

import asyncio
import string
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from onionglass.relay import METHODS
from onionglass.relayauth import HEADER
from relay_origin import FakeOrigin, Reply
from test_relay import DOMAIN, VISITOR, Answer, ask, relay_for, signed_by_the_relay

FUZZ = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)

HOSTS = st.one_of(
    st.sampled_from(
        [
            DOMAIN,
            f"k3f9.{DOMAIN}",
            f"{DOMAIN}:8443",
            f"x{DOMAIN}",
            f"{DOMAIN}.evil.example",
            "other.example",
            "",
            f"{DOMAIN}@evil.example",
        ]
    ),
    st.text(alphabet=string.ascii_letters + string.digits + ".-:", max_size=40),
)
TARGETS = st.one_of(
    st.just("/"),
    st.text(alphabet=string.ascii_letters + string.digits + "/?&=%._-~", max_size=60).map(
        lambda tail: "/" + tail
    ),
    st.binary(max_size=40),
)
NAMES = st.one_of(
    st.sampled_from(
        [
            "x-forwarded-for",
            "forwarded",
            "via",
            "x-real-ip",
            "connection",
            "transfer-encoding",
            "content-length",
            "expect",
            "upgrade",
            "cookie",
            HEADER,
            "user-agent",
        ]
    ),
    st.text(alphabet=string.ascii_lowercase + "-", min_size=1, max_size=12),
)
VALUES = st.text(alphabet=string.ascii_letters + string.digits + " ,;=./-:", max_size=40)
METHOD_NAMES = st.one_of(
    st.sampled_from([*sorted(METHODS), "CONNECT", "TRACE", "get", ""]), st.text(max_size=8)
)


def served(host: str) -> bool:
    name, separator, port = host.rpartition(":")
    if not separator:
        name = host
    elif not port.isdigit():
        return False
    name = name.lower().removesuffix(".")
    return name == DOMAIN or name.endswith("." + DOMAIN)


@FUZZ
@given(
    method=METHOD_NAMES,
    host=HOSTS,
    target=TARGETS,
    headers=st.lists(st.tuples(NAMES, VALUES), max_size=12),
)
def test_whatever_a_visitor_sends_the_relay_answers_and_forwards_only_what_it_should(
    method: str, host: str, target: str | bytes, headers: list[tuple[str, str]]
) -> None:
    async def scenario() -> tuple[Answer, FakeOrigin]:
        async with FakeOrigin() as origin:
            relay = relay_for(origin.port)
            answer = await ask(relay, method, target, host=host, headers=list(headers), body=None)
            assert relay.busy() == (0, 0)
            return answer, origin

    answer, origin = asyncio.run(scenario())
    assert answer.status >= 100 and answer.finished
    for seen in origin.seen:
        host_header = seen.one("host")
        assert served(host_header), host_header
        assert seen.method in METHODS
        assert signed_by_the_relay(seen) == "r1"
        assert len(seen.all(HEADER)) == 1
        assert seen.all("x-forwarded-for") == [] and seen.all("forwarded") == []
        assert seen.all("via") == [] and seen.all("x-real-ip") == []
        assert VISITOR[0].encode() not in seen.raw_head
        assert seen.all("connection") == ["close"]


@FUZZ
@given(data=st.binary(max_size=3000))
def test_whatever_bytes_the_gateway_sends_back_the_relay_ends_with_an_answer(data: bytes) -> None:
    async def scenario() -> Answer:
        async with FakeOrigin(lambda _seen: Reply(raw=data)) as origin:
            relay = relay_for(origin.port, idle_timeout=0.3)
            answer = await ask(relay)
            assert relay.busy() == (0, 0)
            return answer

    answer = asyncio.run(scenario())
    assert answer.finished or answer.aborted
    assert answer.status >= 100


@FUZZ
@given(
    status=st.integers(min_value=200, max_value=599),
    headers=st.lists(st.tuples(NAMES, VALUES), max_size=8),
    body=st.binary(max_size=500),
)
def test_a_well_formed_answer_with_odd_headers_either_comes_back_whole_or_is_refused(
    status: int, headers: list[tuple[str, str]], body: bytes
) -> None:
    async def scenario() -> Answer:
        reply = Reply(status=status, headers=list(headers), body=body)
        async with FakeOrigin(lambda _seen: reply) as origin:
            relay = relay_for(origin.port, idle_timeout=0.3)
            return await ask(relay)

    answer = asyncio.run(scenario())
    if answer.aborted:  # cut off, which is allowed, but never ended as if it were whole
        assert not answer.finished
    elif answer.status == status:
        assert answer.finished
        expected = b"" if status in (204, 304) else body
        assert answer.body == expected  # whole, or not given as a success at all
        for name in ("connection", "keep-alive", "transfer-encoding", "server", "date"):
            assert answer.all(name) == []
    else:
        assert answer.status == 502 and answer.finished


def test_the_strategies_cover_what_they_are_meant_to() -> None:
    # A guard against a fuzz test that quietly tests nothing: the served hosts are common enough
    # to reach the gateway, and the others common enough to be refused.
    sample: list[Any] = [DOMAIN, f"a.{DOMAIN}", "other.example", f"x{DOMAIN}"]
    assert [served(host) for host in sample] == [True, True, False, False]
