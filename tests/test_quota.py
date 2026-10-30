# SPDX-License-Identifier: AGPL-3.0-only
"""Daily allowances (milestone 2, slice 3).

The operator chooses the unit through two costs on each profile: one for opening an address and
one for every web page that comes back. These tests cover the meter, the profile settings, and
the gateway's behaviour when the allowance runs out or the meter cannot be trusted.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from onionglass.audit import MemoryAudit
from onionglass.policy import StaticPolicy
from onionglass.quota import SECONDS_PER_DAY, LocalQuota, QuotaError
from onionglass.settings import Profile, Settings
from test_gateway import PAGE
from test_profiles import Team

DAY = float(SECONDS_PER_DAY)


class Wall:
    """A wall clock the tests can move."""

    def __init__(self) -> None:
        self.now = 10 * DAY + 100

    def __call__(self) -> float:
        return self.now


# --- the meter -----------------------------------------------------------------------------------


def test_the_meter_counts_per_account_and_per_profile() -> None:
    meter = LocalQuota(clock=Wall())
    assert asyncio.run(meter.used("a", "p")) == 0
    assert asyncio.run(meter.charge("a", "p", 2)) == 2
    assert asyncio.run(meter.charge("a", "p", 1)) == 3
    assert asyncio.run(meter.used("b", "p")) == 0
    assert asyncio.run(meter.used("a", "other")) == 0


def test_the_count_starts_again_at_midnight_utc() -> None:
    wall = Wall()
    wall.now = 10 * DAY + DAY - 1
    meter = LocalQuota(clock=wall)
    asyncio.run(meter.charge("a", "p", 5))
    wall.now += 2
    assert asyncio.run(meter.used("a", "p")) == 0


def test_negative_charges_are_refused() -> None:
    with pytest.raises(ValueError, match="negative"):
        asyncio.run(LocalQuota(clock=Wall()).charge("a", "p", -1))


def test_a_journal_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "quota.log"
    wall = Wall()
    first = LocalQuota(path, clock=wall)
    asyncio.run(first.charge("a", "p", 2))
    asyncio.run(first.charge("a", "p", 1))
    second = LocalQuota(path, clock=wall)
    assert asyncio.run(second.used("a", "p")) == 3


def test_old_days_are_dropped_from_the_journal_on_start(tmp_path: Path) -> None:
    path = tmp_path / "quota.log"
    wall = Wall()
    asyncio.run(LocalQuota(path, clock=wall).charge("a", "p", 4))
    wall.now += DAY
    fresh = LocalQuota(path, clock=wall)
    assert asyncio.run(fresh.used("a", "p")) == 0
    assert path.read_text(encoding="utf-8") == ""


def test_a_journal_that_cannot_be_read_stops_start_up(tmp_path: Path) -> None:
    bad = tmp_path / "bad.log"
    bad.write_text("not json\n", encoding="utf-8")
    with pytest.raises(QuotaError, match="line 1"):
        LocalQuota(bad, clock=Wall())
    with pytest.raises(QuotaError, match="cannot read"):
        LocalQuota(tmp_path, clock=Wall())  # a folder


def test_a_charge_that_cannot_be_written_is_not_counted(tmp_path: Path) -> None:
    path = tmp_path / "quota.log"
    meter = LocalQuota(path, clock=Wall())
    asyncio.run(meter.charge("a", "p", 1))
    path.unlink()
    path.mkdir()  # now the journal cannot be appended to
    with pytest.raises(QuotaError):
        asyncio.run(meter.charge("a", "p", 1))
    assert asyncio.run(meter.used("a", "p")) == 1


def test_concurrent_charges_are_all_counted_and_all_written(tmp_path: Path) -> None:
    path = tmp_path / "quota.log"
    meter = LocalQuota(path, clock=Wall())

    async def burst() -> None:
        await asyncio.gather(*(meter.charge("a", "p", 1) for _ in range(50)))

    asyncio.run(burst())
    assert asyncio.run(meter.used("a", "p")) == 50
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 50 and all(json.loads(line)["n"] == 1 for line in lines)


# --- the settings --------------------------------------------------------------------------------


def test_quota_settings_are_checked_when_the_gateway_is_set_up() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        Profile(daily_quota=0)
    with pytest.raises(ValueError, match="cannot be negative"):
        Profile(page_cost=-1)
    with pytest.raises(ValueError, match="needs a cost"):
        Profile(daily_quota=5, open_cost=0, page_cost=0)
    daily = Profile(name="daily", daily_quota=5)
    with pytest.raises(ValueError, match="no quota meter"):
        Settings(base_domain="localhost", open_mode=True, profiles={"daily": daily})
    Settings(
        base_domain="localhost",
        open_mode=True,
        profiles={"daily": daily},
        quota=LocalQuota(clock=Wall()),
    )


# --- in the gateway ------------------------------------------------------------------------------


def make(wall: Wall | None = None, **settings: Any) -> tuple[Team, Wall]:
    wall = wall or Wall()
    profiles = {
        "opens": Profile(name="opens", daily_quota=2, open_cost=1, page_cost=0),
        "pages": Profile(name="pages", daily_quota=2, open_cost=0, page_cost=1, allow_images=True),
        "mixed": Profile(name="mixed", daily_quota=5, open_cost=2, page_cost=1),
    }
    settings.setdefault("quota", LocalQuota(clock=wall))
    return Team(profiles=profiles, **settings), wall


def test_opens_per_day_is_counted_and_starts_again_tomorrow() -> None:
    team, wall = make()
    visitor = team.visitor("opens")
    assert visitor.open() == 303 and visitor.open() == 303
    refused = visitor.open()
    assert refused == 429
    assert [visitor.get().status_code for _ in range(5)] == [200] * 5  # pages cost nothing here
    wall.now += DAY
    assert visitor.open() == 303


def test_pages_per_day_is_counted_and_a_spent_allowance_blocks_the_fetch() -> None:
    team, wall = make()
    visitor = team.visitor("pages")
    assert visitor.open() == 303  # opening is free in this profile
    assert visitor.get().status_code == 200 and visitor.get().status_code == 200
    before = len(team.fetcher.requests)
    spent = visitor.get()
    assert spent.status_code == 429 and "allowance" in spent.text
    assert visitor.get("/a.png").status_code == 429  # everything stops, not just pages
    assert len(team.fetcher.requests) == before
    wall.now += DAY
    assert visitor.get().status_code == 200


def test_the_page_cost_follows_what_comes_back_not_what_the_browser_says() -> None:
    team, _ = make()
    visitor = team.visitor("pages")
    visitor.open()
    claim = {"sec-fetch-dest": "image"}
    for _ in range(2):
        assert (
            visitor.client.get("/", headers={"host": visitor.label_host, **claim}).status_code
            == 200
        )
    assert visitor.get().status_code == 429  # both pages were charged despite the claim


def test_images_do_not_use_up_a_pages_allowance() -> None:
    team, _ = make()
    visitor = team.visitor("pages")
    visitor.open()
    assert all(visitor.get("/a.png").status_code == 200 for _ in range(6))
    assert visitor.get().status_code == 200 and visitor.get().status_code == 200


def test_costs_add_up_in_a_mixed_profile() -> None:
    team, _ = make()
    visitor = team.visitor("mixed")
    assert visitor.open() == 303  # 2
    assert visitor.get().status_code == 200  # 3
    assert visitor.get().status_code == 200  # 4
    assert visitor.get().status_code == 200  # 5
    assert visitor.get().status_code == 429
    assert visitor.open() == 429


def test_the_allowance_belongs_to_the_account_not_the_session() -> None:
    team, _ = make()
    first = team.visitor("opens", subject="alice")
    again = team.visitor("opens", subject="alice")
    other = team.visitor("opens", subject="bob")
    assert first.open() == 303 and again.open() == 303
    assert first.open() == 429 and again.open() == 429  # two sessions, one allowance
    assert other.open() == 303  # another account has its own


def test_each_profile_counts_separately() -> None:
    team, _ = make()
    opens = team.visitor("opens", subject="alice")
    pages = team.visitor("pages", subject="alice")
    assert opens.open() == 303 and opens.open() == 303 and opens.open() == 429
    assert pages.open() == 303 and pages.get().status_code == 200


def test_profiles_without_a_quota_are_not_limited() -> None:
    team, _ = make()
    visitor = team.visitor("analyst")
    assert all(visitor.open() == 303 for _ in range(10))


def test_a_refused_request_does_not_use_the_allowance() -> None:
    team, _ = make(
        policy=StaticPolicy(blocked=["2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"])
    )
    visitor = team.visitor("opens")
    for _ in range(5):
        assert visitor.open(PAGE) == 403  # blocked by the policy, not charged
    other = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
    assert visitor.open(other) == 303 and visitor.open(other) == 303


def test_the_audit_log_shows_why_a_request_was_refused() -> None:
    audit = MemoryAudit()
    team, _ = make(audit=audit)
    visitor = team.visitor("opens")
    visitor.open()
    visitor.open()
    visitor.open()
    assert [(e.kind, e.rule) for e in audit.events][-1] == ("refused", "quota")


def test_a_restart_does_not_hand_out_a_fresh_allowance(tmp_path: Path) -> None:
    wall = Wall()
    path = tmp_path / "quota.log"
    team, _ = make(wall, quota=LocalQuota(path, clock=wall))
    visitor = team.visitor("opens", subject="alice")
    visitor.open()
    visitor.open()
    later, _ = make(wall, quota=LocalQuota(path, clock=wall))
    assert later.visitor("opens", subject="alice").open() == 429


# --- break the meter -----------------------------------------------------------------------------


class Broken:
    def __init__(self, *, used: bool = False, charge: bool = False) -> None:
        self.fail_used, self.fail_charge = used, charge

    async def used(self, subject: str, profile: str) -> int:
        if self.fail_used:
            raise QuotaError("down")
        return 0

    async def charge(self, subject: str, profile: str, units: int) -> int:
        if self.fail_charge:
            raise QuotaError("down")
        return units


class Hanging:
    async def used(self, subject: str, profile: str) -> int:
        await asyncio.sleep(30)
        return 0

    async def charge(self, subject: str, profile: str, units: int) -> int:
        await asyncio.sleep(30)
        return units


@pytest.mark.parametrize(
    "meter",
    [Broken(used=True), Broken(charge=True), Hanging()],
    ids=["unreadable", "unwritable", "hangs"],
)
def test_when_the_meter_cannot_be_trusted_an_open_is_refused(meter: Any) -> None:
    team, _ = make(quota=meter, hook_timeout=0.05)
    visitor = team.visitor("opens")
    assert visitor.open() == 503
    assert team.fetcher.requests == []


def test_when_the_meter_cannot_be_read_a_fetch_is_refused_in_a_limited_profile() -> None:
    meter = Broken()
    team, _ = make(quota=meter)
    visitor = team.visitor("pages")
    assert visitor.open() == 303 and visitor.get().status_code == 200
    meter.fail_used = True
    before = len(team.fetcher.requests)
    assert visitor.get().status_code == 503
    assert len(team.fetcher.requests) == before


def test_when_a_page_cannot_be_charged_the_reply_is_withheld() -> None:
    meter = Broken()
    team, _ = make(quota=meter)
    visitor = team.visitor("pages")
    visitor.open()
    meter.fail_charge = True
    reply = visitor.get()
    assert reply.status_code == 503 and "Page" not in reply.text


def test_a_profile_without_a_quota_keeps_working_when_the_meter_is_down() -> None:
    team, _ = make(quota=Broken(used=True, charge=True))
    visitor = team.visitor("analyst")
    assert visitor.open() == 303 and visitor.get().status_code == 200
