# SPDX-License-Identifier: AGPL-3.0-only
"""Profiles: what each signed-in visitor may do, enforced per session (milestone 2, slice 2).

A ticket names a profile. The gateway must give that session exactly that profile, refuse a
profile it does not have, and enforce the profile on the request as well as on the page it sends
back, since a visitor can send a request no page of ours would have produced.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from onionglass.audit import MemoryAudit
from onionglass.gateway import Gateway
from onionglass.killswitch import KillSwitch
from onionglass.settings import Profile, Settings
from onionglass.store import InMemoryStore
from onionglass.tickets import KeyRing, TicketIssuer, generate_key
from test_gateway import PAGE, Env, FakeFetcher, reply

PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 20
FORMS = Profile(name="forms", allow_post_forms=True, allow_uploads=False)
ANALYST = Profile(name="analyst", allow_images=True, allow_fonts=True, allow_uploads=True)
LIMITED = Profile(name="limited", max_requests_per_minute=3)

PAGE_HTML = (
    '<h1>Page</h1><img src="/a.png" alt="picture">'
    '<form method="post" action="/x"><input name="user"><input type="password" name="pw">'
    '<input type="file" name="f"><button>Go</button></form>'
)


def site(request: Any) -> Any:
    if request.target.startswith("/a.png"):
        return reply(PNG, content_type="image/png")
    if request.target.startswith("/font"):
        return reply(b"fontdata", content_type="font/woff2")
    if request.target.startswith("/big"):
        return reply("<p>" + "x" * 500 + "</p>")
    return reply(PAGE_HTML)


class Team:
    """A team-mode gateway with several profiles, and visitors who sign in with tickets."""

    def __init__(self, *, store: InMemoryStore | None = None, **settings: Any) -> None:
        self.key = generate_key()
        keys = KeyRing()
        keys.add("k1", self.key.public_key())
        self.issuer = TicketIssuer(self.key, "k1", "onionglass")
        profiles = settings.pop("profiles", {})
        self.settings = Settings(
            base_domain="gw.example",
            keys=keys,
            profiles={
                "restricted": Profile.restricted(),
                "analyst": ANALYST,
                "forms": FORMS,
                "limited": LIMITED,
                **profiles,
            },
            **settings,
        )
        self.fetcher = FakeFetcher(site)
        self.clock = [1000.0]
        self.gateway = Gateway(
            self.settings, fetcher=self.fetcher, store=store, clock=lambda: self.clock[0]
        )

    def visitor(self, profile: str, *, subject: str = "v1") -> Visitor:
        client = TestClient(self.gateway.app, base_url="https://gw.example", follow_redirects=False)
        ticket = self.issuer.issue(subject=subject, group="team", profile=profile)
        entered = client.get("/enter", params={"t": ticket})
        return Visitor(self, client, entered.status_code)


class Visitor:
    def __init__(self, team: Team, client: TestClient, entered: int) -> None:
        self.team = team
        self.client = client
        self.entered = entered
        self.label_host = ""

    def open(self, address: str = PAGE) -> int:
        opened = self.client.post(
            "/open", data={"address": address}, headers={"origin": "https://gw.example"}
        )
        if opened.status_code == 303:
            self.label_host = f"{Env.viewer_label(opened.headers['location'])}.gw.example"
        return int(opened.status_code)

    def get(self, path: str = "/") -> Any:
        return self.client.get(path, headers={"host": self.label_host})

    def post(self, path: str = "/x", **kwargs: Any) -> Any:
        headers = {"host": self.label_host, **kwargs.pop("headers", {})}
        return self.client.post(path, headers=headers, **kwargs)


# --- the settings --------------------------------------------------------------------------------


def test_profiles_are_found_by_name_and_the_default_stays_available() -> None:
    settings = Settings(
        base_domain="localhost", open_mode=True, profiles={"restricted": Profile.restricted()}
    )
    assert settings.profile_named("personal") is settings.profile
    assert settings.profile_named("restricted") == Profile.restricted()
    assert settings.profile_named("nobody") is None


def test_profile_settings_are_checked_when_the_gateway_is_set_up() -> None:
    with pytest.raises(ValueError, match="named by their own name"):
        Settings(base_domain="localhost", open_mode=True, profiles={"a": Profile(name="b")})
    with pytest.raises(ValueError, match="unique"):
        Settings(base_domain="localhost", open_mode=True, profiles={"personal": Profile()})
    with pytest.raises(ValueError, match="needs a name"):
        Profile(name="")
    with pytest.raises(ValueError, match="at least 1"):
        Profile(max_requests_per_minute=0)


def test_the_restricted_profile_turns_everything_risky_off() -> None:
    p = Profile.restricted()
    assert not (p.allow_images or p.allow_fonts or p.allow_post_forms)
    assert not (p.allow_uploads or p.allow_password_fields)
    assert p.max_requests_per_minute == 60


# --- tickets and unknown profiles ----------------------------------------------------------------


def test_a_ticket_for_a_profile_this_gateway_does_not_have_is_refused() -> None:
    team = Team()
    visitor = team.visitor("invented")
    assert visitor.entered == 403
    assert visitor.client.cookies.get("og_session") is None
    assert visitor.open() == 403  # no session was made


def test_a_session_whose_profile_disappears_is_refused_not_given_the_default() -> None:
    store = InMemoryStore()
    team = Team(store=store)
    visitor = team.visitor("analyst")
    assert visitor.open() == 303 and visitor.get().status_code == 200
    # The same sessions, served by a gateway that no longer has that profile.
    later = Gateway(
        Settings(base_domain="gw.example", keys=team.settings.keys),
        fetcher=team.fetcher,
        store=store,
    )
    client = TestClient(later.app, base_url="https://gw.example", follow_redirects=False)
    client.cookies.update(visitor.client.cookies)
    before = len(team.fetcher.requests)
    response = client.get("/", headers={"host": visitor.label_host})
    assert response.status_code == 403 and "not available" in response.text
    assert len(team.fetcher.requests) == before


# --- each profile does what it says, and only for its own sessions -------------------------------


def test_the_restricted_profile_gets_text_only_and_the_analyst_gets_images() -> None:
    team = Team()
    restricted, analyst = team.visitor("restricted"), team.visitor("analyst", subject="v2")
    assert restricted.open() == 303 and analyst.open() == 303
    plain = restricted.get().text
    rich = analyst.get().text
    assert 'src="' not in plain and "password" not in plain.lower() and "<form" not in plain
    assert 'src="' in rich and 'type="password"' in rich
    assert restricted.get("/a.png").status_code != 200  # the image itself is withheld
    assert analyst.get("/a.png").status_code == 200


def test_fonts_follow_the_profile() -> None:
    team = Team()
    restricted, analyst = team.visitor("restricted"), team.visitor("analyst", subject="v2")
    restricted.open()
    analyst.open()
    assert restricted.get("/font.woff2").status_code == 403  # blocked type
    assert analyst.get("/font.woff2").status_code == 200


def test_page_size_limits_follow_the_profile() -> None:
    tiny = Profile(name="tiny", max_page_bytes=100)
    team = Team(profiles={"tiny": tiny})
    small, normal = team.visitor("tiny"), team.visitor("analyst", subject="v2")
    small.open()
    normal.open()
    assert small.get("/big").status_code == 502
    assert normal.get("/big").status_code == 200


def test_a_profile_without_forms_cannot_send_a_post_even_by_hand() -> None:
    team = Team()
    restricted = team.visitor("restricted")
    restricted.open()
    before = len(team.fetcher.requests)
    response = restricted.post("/x", data={"user": "a"})
    assert response.status_code == 403 and "does not allow" in response.text
    assert len(team.fetcher.requests) == before


def test_a_profile_without_uploads_cannot_send_a_file_even_by_hand() -> None:
    team = Team()
    forms, analyst = team.visitor("forms"), team.visitor("analyst", subject="v2")
    forms.open()
    analyst.open()
    boundary = "----b0undary123456"
    with_file = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\nhello\r\n--{boundary}--\r\n"
    ).encode()
    plain_field = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="user"\r\n\r\nbob\r\n'
        f"--{boundary}--\r\n"
    ).encode()
    headers = {"content-type": f"multipart/form-data; boundary={boundary}"}
    before = len(team.fetcher.requests)
    assert forms.post("/x", content=with_file, headers={**headers}).status_code == 403
    assert len(team.fetcher.requests) == before
    assert forms.post("/x", content=plain_field, headers={**headers}).status_code == 200
    assert analyst.post("/x", content=with_file, headers={**headers}).status_code == 200


def test_the_audit_log_names_each_sessions_own_profile() -> None:
    audit = MemoryAudit()
    team = Team(audit=audit)
    team.visitor("restricted").open()
    team.visitor("analyst", subject="v2").open()
    assert {(e.profile, e.subject) for e in audit.events} == {
        ("restricted", "v1"),
        ("analyst", "v2"),
    }


def test_a_kill_file_can_stop_one_profile_and_leave_the_others(tmp_path: Path) -> None:
    path = tmp_path / "kill"
    path.write_text("profile restricted\n", encoding="utf-8")
    clock = [100.0]
    team = Team(kill=KillSwitch(path, clock=lambda: clock[0]))
    restricted, analyst = team.visitor("restricted"), team.visitor("analyst", subject="v2")
    assert restricted.open() == 503
    assert analyst.open() == 303 and analyst.get().status_code == 200


# --- the request limit ---------------------------------------------------------------------------


def test_the_request_limit_is_per_session_and_clears_after_a_minute() -> None:
    team = Team()
    one, two = team.visitor("limited"), team.visitor("limited", subject="v2")
    one.open()
    two.open()
    assert [one.get().status_code for _ in range(3)] == [200, 200, 200]
    slow = one.get()
    assert slow.status_code == 429 and "too quickly" in slow.text
    assert two.get().status_code == 200  # another session has its own allowance
    team.clock[0] += 61
    assert one.get().status_code == 200


def test_a_profile_without_a_limit_is_not_limited() -> None:
    team = Team()
    analyst = team.visitor("analyst")
    analyst.open()
    assert all(analyst.get().status_code == 200 for _ in range(40))


def test_requests_that_are_refused_do_not_use_up_the_allowance() -> None:
    team = Team(
        profiles={"two": Profile(name="two", allow_post_forms=False, max_requests_per_minute=2)}
    )
    visitor = team.visitor("two")
    visitor.open()
    for _ in range(5):
        assert visitor.post("/x", data={"a": "b"}).status_code == 403
    assert visitor.get().status_code == 200 and visitor.get().status_code == 200
