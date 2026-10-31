# SPDX-License-Identifier: AGPL-3.0-only
"""Reader view: a page shown as plain, readable text, with nothing active or decorative left."""

from __future__ import annotations

import json
from html.parser import HTMLParser

from starlette.testclient import TestClient

from helpers import DUCKDUCKGO, FakeMapper, assert_safe_output, base_url
from onionglass.rewrite.html import HtmlOptions, RewriteResult, rewrite_html
from onionglass.settings import Profile
from test_entities import GENESIS
from test_gateway import APEX, PORT, Env, reply
from test_gateway import PAGE as PAGE_ADDRESS

MAPPER = FakeMapper()
BASE = base_url()
PREFIX = MAPPER.onion(BASE.origin)

PAGE = (
    "<title>News today</title><nav><a href='/menu'>Menu item</a></nav>"
    "<style>p{color:red}</style>"
    "<h1 id='top' class='big' style='color:red'>Headline</h1>"
    "<p onclick='x()'>First <b>bold</b> <a href='/next' target='_blank'>read more</a> "
    "<a href='http://example.com/x'>outside</a></p>"
    "<img src='/p.png' alt='A chart'>"
    "<ul><li>One</li><li>Two</li></ul>"
    "<form action='/s' method='post'><label>Search the archive</label>"
    "<input name='q'><button>Go</button></form>"
    "<table><tr><th>Name</th><td>Value</td></tr></table>"
    "<aside>Side bar</aside><footer>Foot note</footer><script>alert(1)</script>"
)


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend((tag, name) for name, _ in attrs)


def parsed(result: RewriteResult) -> _Tags:
    collector = _Tags()
    collector.feed(result.body.decode("utf-8"))
    return collector


def read(page: str, **options: object) -> RewriteResult:
    return rewrite_html(
        page.encode("utf-8"),
        BASE,
        MAPPER,
        options=HtmlOptions(reader=True, **options),  # type: ignore[arg-type]
    )


def test_the_text_and_its_structure_are_kept() -> None:
    result = read(PAGE)
    body = result.body.decode("utf-8")
    for expected in ("Headline", "First", "bold", "read more", "One", "Two", "Name", "Value"):
        assert expected in body
    tags = parsed(result).tags
    for kept in ("h1", "p", "ul", "li", "table", "tr", "th", "td", "b", "a"):
        assert kept in tags, kept
    assert result.title == "News today"
    assert result.headings == ("Headline",)


def test_nothing_that_is_not_reading_survives() -> None:
    result = read(PAGE)
    body = result.body.decode("utf-8")
    tags = set(parsed(result).tags) - {"html", "head", "meta", "title", "body", "style"}
    for gone in ("img", "form", "input", "button", "nav", "aside", "footer", "script", "link"):
        assert gone not in tags, gone
    for text in (
        "Menu item",
        "Side bar",
        "Foot note",
        "alert(1)",
        "color:red",
        "Search the archive",
    ):
        assert text not in body, text
    assert "/p.png" not in body and "action=" not in body


def test_only_links_keep_an_attribute_and_it_is_the_address() -> None:
    attributes = parsed(read(PAGE)).attributes
    allowed = {
        ("a", "href"),
        ("a", "rel"),
        ("meta", "charset"),
        ("meta", "name"),
        ("meta", "content"),
        ("html", "lang"),
        ("body", "class"),
    }
    extra = [pair for pair in attributes if pair not in allowed]
    assert extra == [], extra


def test_links_still_go_through_the_gateway() -> None:
    body = read(PAGE).body.decode("utf-8")
    assert f'href="{PREFIX}/next"' in body
    assert "/_og/external?u=" in body and 'href="http://example.com' not in body
    assert_safe_output(read(PAGE).body, MAPPER)


def test_a_withheld_picture_is_named_and_counted() -> None:
    result = read(PAGE)
    assert "A chart" in result.body.decode("utf-8")
    assert result.withheld_images == 1


def test_pictures_stay_out_even_when_the_profile_allows_images() -> None:
    result = read(PAGE, allow_images=True)
    assert "img" not in parsed(result).tags and "/p.png" not in result.body.decode("utf-8")
    assert result.withheld_images == 1 and "A chart" in result.body.decode("utf-8")


def test_the_page_says_it_is_the_reader_view() -> None:
    body = read(PAGE).body.decode("utf-8")
    assert '<meta name="og-view" content="reader">' in body
    assert "Reader view" in body


def test_a_page_with_no_reading_in_it_still_makes_a_valid_document() -> None:
    body = read("<script>1</script><form><input></form>").body.decode("utf-8")
    assert body.startswith("<!DOCTYPE html>") and "</html>" in body


def test_hostile_markup_is_gone_in_reader_form_too() -> None:
    hostile = (
        "<p style='background:url(http://evil.example/x)' onmouseover=alert(1)>hi</p>"
        "<a href='javascript:alert(1)' onclick=alert(2)>x</a>"
        "<svg onload=alert(1)></svg><iframe src='http://evil.example'></iframe>"
    )
    result = read(hostile)
    body = result.body.decode("utf-8").lower()
    assert "evil.example" not in body and "javascript:" not in body and "onclick" not in body
    assert_safe_output(result.body, MAPPER)


def test_the_normal_view_is_unchanged_by_the_option_existing() -> None:
    normal = rewrite_html(PAGE.encode("utf-8"), BASE, MAPPER)
    assert "<form" in normal.body.decode("utf-8") and "Menu item" in normal.body.decode("utf-8")
    assert 'name="og-view"' not in normal.body.decode("utf-8")


# --- through the gateway -------------------------------------------------------------------------

SAME = {"sec-fetch-site": "same-origin", "origin": f"http://{APEX}"}


def served(**extra: object) -> Env:
    return Env(lambda _r: reply(PAGE), **extra)  # type: ignore[arg-type]


def switch(env_client: TestClient, on: bool, headers: dict[str, str] | None = None) -> object:
    return env_client.post(
        "/_og/reader", data={"on": "1" if on else "0"}, headers=SAME if headers is None else headers
    )


def page(env: Env, label: str) -> str:
    response = env.get(label, headers={"sec-fetch-dest": "iframe"})
    assert response.status_code == 200
    return str(response.text)


def test_a_visitor_can_turn_the_reader_view_on_and_off() -> None:
    env = served()
    label = env.open()
    assert "<form" in page(env, label)
    on = switch(env.client, True)
    assert on.status_code == 200 and json.loads(on.text) == {"reader": True}  # type: ignore[attr-defined]
    text = page(env, label)
    assert 'name="og-view"' in text and "<form" not in text and "Menu item" not in text
    switch(env.client, False)
    assert "<form" in page(env, label)


def test_the_switch_is_remembered_for_every_site_in_the_session() -> None:
    env = served()
    first = env.open()
    switch(env.client, True)
    second = env.open(f"http://{DUCKDUCKGO}.onion/")
    assert first != second
    assert 'name="og-view"' in page(env, second)


def test_one_visitors_choice_does_not_reach_another() -> None:
    env = served()
    label = env.open()
    switch(env.client, True)
    other = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    opened = other.post("/open", data={"address": PAGE_ADDRESS})
    other_label = Env.viewer_label(opened.headers["location"])
    headers = {
        "host": f"{other_label}.localhost:{PORT}",
        "sec-fetch-site": "same-origin",
        "sec-fetch-dest": "iframe",
    }
    assert "<form" in other.get("/", headers=headers).text
    assert 'name="og-view"' in page(env, label)


def test_a_request_from_another_site_or_without_a_session_is_refused() -> None:
    env = served()
    env.open()
    for headers in ({"sec-fetch-site": "cross-site"}, {"origin": "https://evil.example"}):
        refused = switch(env.client, True, headers)
        assert refused.status_code == 403  # type: ignore[attr-defined]
    stranger = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    assert switch(stranger, True).status_code == 403  # type: ignore[attr-defined]
    label = env.open()
    assert "<form" in page(env, label)  # the refused requests changed nothing


def test_a_bad_value_is_refused_and_changes_nothing() -> None:
    env = served()
    label = env.open()
    switch(env.client, True)
    for body in ({"on": "maybe"}, {}, {"on": "1" * 5000}):
        response = env.client.post("/_og/reader", data=body, headers=SAME)
        assert response.status_code in (400, 413)
    assert 'name="og-view"' in page(env, label)


def test_the_page_the_viewer_polls_says_which_view_is_on() -> None:
    env = served()
    label = env.open()
    page(env, label)
    assert json.loads(env.client.get("/_og/current").text)["reader"] is False
    switch(env.client, True)
    assert json.loads(env.client.get("/_og/current").text)["reader"] is True


def test_the_viewer_has_the_reader_button() -> None:
    env = served()
    label = env.open()
    viewer = env.client.get("/view", params={"l": label, "p": "/"})
    assert 'id="reader-toggle"' in viewer.text


def test_the_reader_page_has_the_same_protective_headers() -> None:
    env = served()
    label = env.open()
    switch(env.client, True)
    response = env.get(label, headers={"sec-fetch-dest": "iframe"})
    policy = response.headers["content-security-policy"]
    assert "script-src 'none'" in policy and policy.startswith("sandbox")


def test_entities_are_still_found_on_a_page_shown_in_reader_form() -> None:
    env = Env(
        lambda _r: reply(f"<title>x</title><p>Pay {GENESIS}</p><nav>menu</nav>"),
        profile=Profile(name="personal", show_entities=True),
    )
    label = env.open()
    switch(env.client, True)
    page(env, label)
    shown = json.loads(env.client.get("/_og/current").text)["entities"]
    assert {"kind": "bitcoin", "value": GENESIS} in shown
