# SPDX-License-Identifier: AGPL-3.0-only
"""Settings, the placeholder mapper, the per-session label limit and the gateway's own pages."""

from __future__ import annotations

import asyncio
import html

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass import pages
from onionglass.headers import HeaderPolicy, apex_headers
from onionglass.labels import LabelBook, LabelError
from onionglass.mapper import MAX_ORIGINS_PER_PAGE, PlaceholderMapper
from onionglass.onion import OnionHost, OnionOrigin
from onionglass.settings import Settings
from onionglass.store import InMemoryStore
from onionglass.tickets import KeyRing

ORIGIN = OnionOrigin("http", OnionHost(TOR_PROJECT), 80)
OTHER = OnionOrigin("http", OnionHost(DUCKDUCKGO), 80)
LOCAL = Settings(base_domain="localhost", scheme="http", port=8080, open_mode=True)
SESSION = "session-aaaaaaaa"


def test_settings_describe_the_gateway_addresses() -> None:
    assert LOCAL.apex_host == "localhost:8080"
    assert LOCAL.apex_origin == "http://localhost:8080"
    assert LOCAL.require_cookie is False
    deployed = Settings(base_domain="gw.example", keys=KeyRing())
    assert deployed.apex_origin == "https://gw.example"
    assert deployed.require_cookie is True
    assert deployed.header_policy.viewer_origin == "https://gw.example"


@pytest.mark.parametrize(
    "bad",
    [
        {"scheme": "ftp"},
        {"port": 0},
        {"port": 70000},
        {"base_domain": "Gw.Example"},
        {"base_domain": "gw.example."},
        {"cookie_name": ""},
        {"cookie_name": "a b"},
        {"cookie_name": "a;b"},
    ],
)
def test_bad_settings_are_refused(bad: dict[str, object]) -> None:
    values: dict[str, object] = {"base_domain": "gw.example", "keys": KeyRing()}
    values.update(bad)
    with pytest.raises(ValueError, match=r"scheme|port|domain|cookie"):
        Settings(**values)  # type: ignore[arg-type]


# --- the placeholder mapper --------------------------------------------------------------------


def test_the_same_origin_always_gets_the_same_placeholder() -> None:
    mapper = PlaceholderMapper(LOCAL, nonce="n" * 32)
    first = mapper.onion(ORIGIN)
    assert mapper.onion(ORIGIN) == first
    assert mapper.onion(OTHER) != first
    assert first == f"http://p0.{'n' * 32}.invalid:8080"
    assert mapper.origins() == [ORIGIN, OTHER] or mapper.origins() == [ORIGIN]


def test_placeholders_and_warning_urls_are_recognised_and_nothing_else() -> None:
    mapper = PlaceholderMapper(LOCAL, nonce="a" * 32)
    placeholder = mapper.onion(ORIGIN) + "/x?y=1"
    assert mapper.owns(placeholder)
    assert mapper.owns(mapper.external("https://example.org/"))
    assert mapper.owns("") and mapper.owns("#frag")
    for url in (
        "http://p0.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.invalid:8080/x",  # another page's nonce
        f"http://p0.{'a' * 32}.invalid:9999/x",  # wrong port
        f"https://p0.{'a' * 32}.invalid:8080/x",  # wrong scheme
        f"http://q0.{'a' * 32}.invalid:8080/x",
        f"http://pX.{'a' * 32}.invalid:8080/x",
        "http://example.org/",
        "http://localhost:8080/other",
        "http://[::1",
        f"http://evil.example/?{'a' * 32}.invalid",
    ):
        assert not mapper.owns(url), url


def test_substitution_replaces_placeholders_with_labels_and_blocks_the_rest() -> None:
    mapper = PlaceholderMapper(LOCAL, nonce="c" * 32)
    text = f'<a href="{mapper.onion(ORIGIN)}/a">x</a><a href="{mapper.onion(OTHER)}/b">y</a>'
    result = mapper.substitute(text, {ORIGIN: "l" * 26})
    assert f"http://{'l' * 26}.localhost:8080/a" in result
    assert "http://localhost:8080/_og/blocked/b" in result
    assert ".invalid" not in result


def test_indexes_that_share_a_prefix_do_not_collide() -> None:
    mapper = PlaceholderMapper(LOCAL, nonce="d" * 32)
    origins = [OnionOrigin("http", OnionHost(TOR_PROJECT, (f"s{i}",)), 80) for i in range(12)]
    text = " ".join(mapper.onion(o) for o in origins)
    labels = {o: f"label{i:02d}".ljust(26, "x") for i, o in enumerate(origins)}
    result = mapper.substitute(text, labels)
    assert result.split()[1].startswith(f"http://{labels[origins[1]]}.")
    assert result.split()[10].startswith(f"http://{labels[origins[10]]}.")
    assert ".invalid" not in result


def test_a_page_cannot_forge_a_placeholder_without_the_random_value() -> None:
    mapper = PlaceholderMapper(LOCAL)
    mapper.onion(ORIGIN)
    forged = "http://p0.00000000000000000000000000000000.invalid:8080/x"
    assert mapper.substitute(forged, {ORIGIN: "l" * 26}) == forged
    assert not mapper.owns(forged)


def test_a_page_naming_too_many_sites_is_refused() -> None:
    mapper = PlaceholderMapper(LOCAL)
    for index in range(MAX_ORIGINS_PER_PAGE):
        mapper.onion(OnionOrigin("http", OnionHost(TOR_PROJECT, (f"s{index}",)), 80))
    with pytest.raises(ValueError, match="too many"):
        mapper.onion(OTHER)


# --- the per-session label limit ---------------------------------------------------------------------


def test_a_session_gets_a_fixed_number_of_labels() -> None:
    async def scenario() -> None:
        book = LabelBook(InMemoryStore(), ttl=60, max_per_session=2)
        origins = [OnionOrigin("http", OnionHost(TOR_PROJECT, (f"s{i}",)), 80) for i in range(3)]
        first = await book.label_for(SESSION, origins[0])
        await book.label_for(SESSION, origins[1])
        with pytest.raises(LabelError, match="too many"):
            await book.label_for(SESSION, origins[2])
        assert await book.label_for(SESSION, origins[0]) == first  # existing labels still work
        assert await book.label_for("session-bbbbbbbb", origins[2])  # other sessions are unaffected

    asyncio.run(scenario())


# --- pages and headers --------------------------------------------------------------------------------


def test_apex_headers_only_allow_a_form_when_asked() -> None:
    policy = HeaderPolicy("https", "gw.example")
    assert "form-action 'self'" in apex_headers(policy, form=True)["Content-Security-Policy"]
    assert "form-action 'none'" in apex_headers(policy)["Content-Security-Policy"]
    csp = apex_headers(policy, form=True)["Content-Security-Policy"]
    assert (
        "frame-ancestors 'none'" in csp
        and "script-src 'none'" in csp
        and "default-src 'none'" in csp
    )


def test_only_the_warning_page_may_be_framed_and_only_by_the_gateway_itself() -> None:
    policy = HeaderPolicy("https", "gw.example")
    assert "frame-ancestors 'self'" in apex_headers(policy, framed=True)["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in apex_headers(policy)["Content-Security-Policy"]


def test_every_error_kind_has_a_page_and_unknown_kinds_fall_back() -> None:
    for kind, (status, title, message) in pages.ERRORS.items():
        got_status, body = pages.error_page(kind)
        assert got_status == status
        assert html.escape(title).encode() in body
        assert html.escape(message).encode() in body
    assert pages.error_page("no-such-kind")[0] == 500


def test_pages_escape_everything_they_show() -> None:
    landing = pages.landing_page(notice="<script>alert(1)</script>").decode()
    assert "<script>" not in landing and "&lt;script&gt;" in landing
    warning = pages.external_page('https://example.org/"><script>alert(1)</script>').decode()
    assert "<script>" not in warning
    assert pages.landing_page(can_open=False).decode().count("<form") == 0
