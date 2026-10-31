# SPDX-License-Identifier: AGPL-3.0-only
"""Generated input through the reader view, the translation slots and the viewer's switches.

Three promises are tried with input nobody wrote by hand:

* Whatever a translation says, the page it is put into keeps exactly the structure it had.
* Whatever is posted to the switches, the gateway answers in a small fixed set of ways and never
  with an internal error.
* Whatever a translation service answers, the visitor still gets a page that is safe to show.
"""

from __future__ import annotations

import json
import os
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from starlette.testclient import TestClient

from helpers import FakeMapper, assert_safe_output, base_url
from onionglass.audit import MemoryAudit
from onionglass.rewrite.html import HtmlOptions, RewriteError, fill_slots, rewrite_html
from onionglass.settings import Profile
from test_entity_sink import MemorySink
from test_gateway import APEX, Env, reply
from test_gateway import PAGE as ONION
from test_grammar_fuzz import documents
from test_translate_page import PAGE

pytestmark = pytest.mark.timeout(600)
SCALE = max(1, int(os.environ.get("ONIONGLASS_FUZZ_SCALE", "1")))
HUNT = settings(
    max_examples=150 * SCALE,
    deadline=None,
    suppress_health_check=list(HealthCheck),
)
MAPPER = FakeMapper()
BASE = base_url()
EVERYTHING = Profile(name="personal", show_entities=True, send_entities=True, allow_translate=True)

HOSTILE = st.one_of(
    st.text(max_size=60),
    st.sampled_from(
        [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "</p><p>",
            "</a><a href='http://evil.example/'>x</a>",
            "&lt;b&gt;",
            "<!--",
            "ogt0123456789abcdefx0e",
            "{x}",
            "%s",
            chr(92) + "1",
            chr(92) + "g<0>",
            chr(0),
            "a" * 6000,
            "",
        ]
    ),
)


class Tags(HTMLParser):
    """The shape of a page: every start tag with the names of its attributes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.shape: list[tuple[str, tuple[str, ...]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.shape.append((tag, tuple(sorted(name for name, _ in attrs))))


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.found.extend(value or "" for name, value in attrs if name == "href")


def links(document: str) -> list[str]:
    parser = Links()
    parser.feed(document)
    parser.close()
    return parser.found


def host_of(link: str) -> str:
    return urlsplit(link).hostname or ""


def shape(document: str) -> list[tuple[str, tuple[str, ...]]]:
    parser = Tags()
    parser.feed(document)
    parser.close()
    return parser.shape


@HUNT
@given(documents(), st.data())
def test_a_translation_cannot_change_the_structure_of_the_page(
    document: str, data: st.DataObject
) -> None:
    options = HtmlOptions(reader=True, translate_slots=True)
    try:
        result = rewrite_html(document.encode("utf-8"), BASE, MAPPER, options=options)
    except RewriteError:
        return
    body = result.body.decode("utf-8")
    translations = [data.draw(HOSTILE) for _ in result.slots]
    original = fill_slots(body, result, None)
    filled = fill_slots(body, result, translations)
    assert shape(filled) == shape(original)
    assert result.slot_token not in filled
    assert_safe_output(filled.encode("utf-8"), MAPPER)


@HUNT
@given(documents())
def test_the_original_text_comes_back_exactly_when_nothing_is_translated(document: str) -> None:
    try:
        plain = rewrite_html(
            document.encode("utf-8"), BASE, MAPPER, options=HtmlOptions(reader=True)
        )
        slotted = rewrite_html(
            document.encode("utf-8"),
            BASE,
            MAPPER,
            options=HtmlOptions(reader=True, translate_slots=True),
        )
    except RewriteError:
        return
    restored = fill_slots(slotted.body.decode("utf-8"), slotted, None)
    assert shape(restored) == shape(plain.body.decode("utf-8"))
    assert restored == plain.body.decode("utf-8")
    assert slotted.text == plain.text


# --- the switches --------------------------------------------------------------------------------

PATHS = ["/_og/reader", "/_og/translate", "/_og/send-entities"]
ALLOWED_ANSWERS = {200, 400, 403, 413, 429, 502, 503}
BODIES = st.one_of(
    st.binary(max_size=80),
    st.text(alphabet="on=01&xyz%+", max_size=24).map(lambda text: text.encode("ascii")),
    st.just(b"on=1"),
    st.just(b"on=0"),
    st.just(b"on=1&on=0"),
    st.just(b"on=" + b"1" * 5000),
)
SITES = st.sampled_from(["same-origin", "cross-site", "same-site", "none", "", "bogus"])
ORIGINS = st.sampled_from(
    [f"http://{APEX}", "https://evil.example", "null", "", "http://localhost"]
)


@st.composite
def posts(draw: st.DrawFn) -> dict[str, Any]:
    return {
        "path": draw(st.sampled_from(PATHS)),
        "body": draw(BODIES),
        "site": draw(SITES),
        "origin": draw(ORIGINS),
        "signed_in": draw(st.booleans()),
    }


class Scripted:
    """A translator that answers whatever it was told to."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer

    async def translate(self, texts: list[str]) -> Any:
        return self.answer(texts) if callable(self.answer) else self.answer


def switchboard() -> tuple[Env, str]:
    env = Env(
        lambda _r: reply(PAGE),
        profile=EVERYTHING,
        translator=Scripted(lambda texts: [f"T:{t}" for t in texts]),
        entity_sink=MemorySink(),
        audit=MemoryAudit(),
    )
    label = env.open()
    return env, label


@HUNT
@given(st.lists(posts(), min_size=1, max_size=6))
def test_the_switches_answer_in_a_few_fixed_ways_and_never_with_an_internal_error(
    cases: list[dict[str, Any]],
) -> None:
    env, label = switchboard()
    env.get(label, headers={"sec-fetch-dest": "iframe"})
    stranger = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    for case in cases:
        headers = {"sec-fetch-site": case["site"], "origin": case["origin"]}
        headers = {name: value for name, value in headers.items() if value}
        client = env.client if case["signed_in"] else stranger
        response = client.post(case["path"], content=case["body"], headers=headers)
        assert response.status_code in ALLOWED_ANSWERS, response.text
        assert response.headers["content-type"] == "application/json"
        data = json.loads(response.text)
        assert isinstance(data, dict)
        if response.status_code == 200 and case["path"] != "/_og/send-entities":
            assert set(data) == {case["path"].rsplit("/", 1)[1]}
            assert isinstance(next(iter(data.values())), bool)
        if not case["signed_in"]:
            assert response.status_code == 403
    page = env.get(label, headers={"sec-fetch-dest": "iframe"})
    assert page.status_code == 200 and "<script" not in page.text.lower()


@HUNT
@given(st.lists(st.sampled_from(["reader", "translate"]), min_size=1, max_size=8), st.data())
def test_one_visitors_switches_never_reach_another_visitor(
    flips: list[str], data: st.DataObject
) -> None:
    env, _label = switchboard()
    other = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    assert other.post("/open", data={"address": ONION}).status_code == 303
    same = {"sec-fetch-site": "same-origin", "origin": f"http://{APEX}"}
    for name in flips:
        env.client.post(
            f"/_og/{name}", data={"on": data.draw(st.sampled_from(["0", "1"]))}, headers=same
        )
    state = json.loads(other.get("/_og/current").text or "{}")
    assert not state.get("reader") and not state.get("translate")


# --- a translation service that answers anything -------------------------------------------------


def right_length(pool: list[str]) -> Any:
    return lambda texts: [pool[i % len(pool)] for i in range(len(texts))] if pool else []


ANSWERS = st.one_of(
    st.none(),
    st.integers(),
    st.text(max_size=40),
    st.lists(
        st.one_of(HOSTILE, st.integers(), st.none(), st.lists(st.text(max_size=5))), max_size=10
    ),
    st.lists(HOSTILE, max_size=6).map(right_length),
)


@HUNT
@given(ANSWERS)
def test_a_translator_that_answers_anything_cannot_break_the_page(answer: Any) -> None:
    env = Env(
        lambda _r: reply(PAGE),
        profile=Profile(name="personal", allow_translate=True),
        translator=Scripted(answer),
        audit=MemoryAudit(),
    )
    label = env.open()
    same = {"sec-fetch-site": "same-origin", "origin": f"http://{APEX}"}
    assert env.client.post("/_og/translate", data={"on": "1"}, headers=same).status_code == 200
    response = env.get(label, headers={"sec-fetch-dest": "iframe"})
    assert response.status_code == 200
    text = response.text
    parsed = shape(text)
    unwanted = {"script", "img", "iframe", "object", "embed", "svg", "form", "input"}
    assert not unwanted & {tag for tag, _ in parsed}
    names = {name for _, attributes in parsed for name in attributes}
    assert not any(name.startswith("on") or name == "style" for name in names)
    assert all(host_of(link).endswith("localhost") for link in links(text))
    left = set(re.findall(r"ogt[0-9a-f]{16}x[0-9]+e", text))
    assert left <= {"ogt0123456789abcdefx0e"}  # a slot left behind; this one is test input
    assert "Machine translation" in text or "Translation was not available" in text
