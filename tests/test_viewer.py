# SPDX-License-Identifier: AGPL-3.0-only
"""The viewer page: a toolbar with the real address and a sandboxed frame for the site."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from helpers import TOR_PROJECT
from onionglass.pages import VIEWER_SCRIPT
from test_gateway import APEX, PAGE, PORT, Deployed, Env, reply


def viewer_path(env: Env, address: str = PAGE) -> str:
    """Open an address and return the path and query of the viewer page it leads to."""
    response = env.client.post("/open", data={"address": address})
    assert response.status_code == 303
    parts = urlsplit(response.headers["location"])
    return f"{parts.path}?{parts.query}"


def label_of(path: str) -> str:
    return parse_qs(urlsplit(path).query)["l"][0]


def test_the_viewer_frames_the_site_on_a_label_host_with_a_sandbox() -> None:
    env = Env()
    path = viewer_path(env, f"{TOR_PROJECT}.onion/some/page?x=1")
    response = env.client.get(path)
    assert response.status_code == 200
    label = label_of(path)
    assert f'src="http://{label}.localhost:{PORT}/some/page?x=1"' in response.text
    sandbox = "allow-forms allow-same-origin allow-popups allow-popups-to-escape-sandbox"
    assert f'sandbox="{sandbox}"' in response.text
    assert "allow-scripts" not in response.text
    assert "allow-top-navigation" not in response.text
    assert 'referrerpolicy="no-referrer"' in response.text
    assert '<script src="/_og/viewer.js"></script>' in response.text
    assert "can see every address you open" in response.text
    assert TOR_PROJECT not in response.text  # the page itself never carries the onion address
    assert env.fetcher.requests == []  # showing the viewer fetches nothing


def test_the_viewer_policy_allows_only_its_own_script_and_the_gateways_frames() -> None:
    env = Env()
    csp = env.client.get(viewer_path(env)).headers["content-security-policy"]
    rules = {
        part.strip().split(" ", 1)[0]: part.strip().partition(" ")[2] for part in csp.split(";")
    }
    assert rules["script-src"] == "'self'"
    assert rules["connect-src"] == "'self'"
    # The gateway's label hosts, and its own origin so the warning page can show in the frame.
    assert rules["frame-src"] == f"http://*.localhost:{PORT} 'self'"
    assert rules["frame-ancestors"] == "'none'"
    assert rules["default-src"] == "'none'"
    assert rules["form-action"] == "'none'"
    assert "unsafe" not in rules["script-src"]
    assert "allow-scripts" not in csp


def test_the_viewer_needs_a_session_and_the_label_must_belong_to_it() -> None:
    env = Env()
    path = viewer_path(env)
    assert TestClient(env.gateway.app, base_url=f"http://{APEX}").get(path).status_code == 403
    other = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    other.post("/open", data={"address": f"http://{TOR_PROJECT}.onion/other"})
    assert other.get(path).status_code == 403  # a different session cannot frame this label


@pytest.mark.parametrize(
    "query",
    [
        "",
        "l=short&p=/",
        "l=" + "a" * 26 + "&p=//evil.example/",
        "l=" + "a" * 26 + "&p=relative",
        "l=" + "a" * 26 + "&p=/has space",
        "l=" + "a" * 26 + "&p=/back%5Cslash",
        "l=" + "a" * 26 + "&p=/frag%23ment",
        "l=" + "a" * 26 + "&p=/ctrl%00",
        "l=" + "a" * 26 + "&p=/" + "x" * 3000,
        "l=" + "A" * 26 + "&p=/",
    ],
)
def test_viewer_parameters_are_checked(query: str) -> None:
    env = Env()
    viewer_path(env)
    assert env.client.get(f"/view?{query}").status_code == 400


def test_an_unknown_label_is_refused() -> None:
    env = Env()
    viewer_path(env)
    assert env.client.get("/view?l=" + "a" * 26 + "&p=/").status_code == 403


# --- the current address -----------------------------------------------------------------------


def test_the_current_address_follows_page_loads_in_the_frame() -> None:
    env = Env(lambda _r: reply("<title>My site</title><p>hello</p>"))
    path = viewer_path(env)
    label = label_of(path)
    assert env.client.get("/_og/current").json() == {}
    env.get(label, "/dir/page?x=1", headers={"sec-fetch-dest": "iframe"})
    record = env.client.get("/_og/current").json()
    assert record["url"] == f"http://{TOR_PROJECT}.onion/dir/page?x=1"
    assert record["frame"] == f"http://{label}.localhost:{PORT}/dir/page?x=1"
    assert record["title"] == "My site"


def test_only_page_navigations_update_the_current_address() -> None:
    def handler(request):  # type: ignore[no-untyped-def]
        if request.target == "/missing":
            return reply("<p>no</p>", status=404)
        if request.target == "/style.css":
            return reply("a{color:red}", content_type="text/css")
        return reply("<title>Home</title>")

    env = Env(handler)
    label = label_of(viewer_path(env))
    env.get(label, "/", headers={"sec-fetch-dest": "iframe"})
    env.get(label, "/missing", headers={"sec-fetch-dest": "iframe"})  # an error page
    env.get(label, "/style.css", headers={"sec-fetch-dest": "iframe"})  # not a page
    env.get(label, "/other", headers={"sec-fetch-dest": "image"})  # a subresource
    env.get(label, "/other2")  # no destination given
    assert env.client.get("/_og/current").json()["url"] == f"http://{TOR_PROJECT}.onion/"


def test_the_current_address_is_private_to_the_session() -> None:
    env = Env()
    label = label_of(viewer_path(env))
    env.get(label, "/", headers={"sec-fetch-dest": "iframe"})
    anonymous = TestClient(env.gateway.app, base_url=f"http://{APEX}")
    response = anonymous.get("/_og/current")
    assert response.status_code == 403 and response.json() == {}
    assert response.headers["cache-control"] == "no-store"


def test_a_hostile_title_is_only_ever_data() -> None:
    # The title is escaped markup, so it reads as the text "<script>alert(1)</script>".
    markup = "&lt;script&gt;alert(1)&lt;/script&gt;"
    env = Env(lambda _r: reply(f"<title>{markup}</title><p>x</p>"))
    path = viewer_path(env)
    env.get(label_of(path), "/", headers={"sec-fetch-dest": "iframe"})
    response = env.client.get("/_og/current")
    assert json.loads(response.text)["title"] == "<script>alert(1)</script>"  # data, not markup
    assert response.headers["content-type"] == "application/json"
    assert response.headers["x-content-type-options"] == "nosniff"
    # The viewer page is built without the title, and the script shows it as plain text.
    assert "alert(1)" not in env.client.get(path).text


# --- the toolbar script -------------------------------------------------------------------------


def test_the_script_is_served_with_safe_headers() -> None:
    env = Env()
    response = env.client.get("/_og/viewer.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.text == VIEWER_SCRIPT


def test_the_script_only_displays_text_and_only_talks_to_the_gateway() -> None:
    assert VIEWER_SCRIPT.isascii()
    for dangerous in (
        "eval(",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "new Function",
        'setTimeout("',
        "postMessage",
        "XMLHttpRequest",
        "importScripts",
        "WebSocket",
        "localStorage",
        "document.cookie",
    ):
        assert dangerous not in VIEWER_SCRIPT, dangerous
    assert "textContent" in VIEWER_SCRIPT
    assert VIEWER_SCRIPT.count("fetch(") == 1 and 'fetch("/_og/current"' in VIEWER_SCRIPT
    assert "http://" not in VIEWER_SCRIPT and "https://" not in VIEWER_SCRIPT


# --- tickets lead to the viewer too -----------------------------------------------------------------


def test_a_ticket_for_one_onion_leads_to_a_working_viewer() -> None:
    env = Deployed()
    response = env.client.get("/enter", params={"t": env.ticket(onion=TOR_PROJECT)})
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("https://gw.example/view?l=")
    page = env.client.get(location)
    assert page.status_code == 200
    label = parse_qs(urlsplit(location).query)["l"][0]
    assert f'src="https://{label}.gw.example/"' in page.text
    assert "frame-src https://*.gw.example" in page.headers["content-security-policy"]
