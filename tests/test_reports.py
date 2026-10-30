# SPDX-License-Identifier: AGPL-3.0-only
"""The report queue: a visitor reports the site they are looking at (milestone 2, slice 5)."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.audit import MemoryAudit
from onionglass.cli import build_gateway
from onionglass.held import HeldList
from onionglass.policy import PolicyConfigError
from onionglass.reports import CATEGORIES, ReportError, ReportQueue
from test_gateway import PAGE, Env, reply
from test_profiles import Team

OTHER = f"http://{DUCKDUCKGO}.onion/"


# --- the queue -----------------------------------------------------------------------------------


def lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_a_report_is_one_line_with_the_time_site_reason_and_reporter(tmp_path: Path) -> None:
    path = tmp_path / "reports.log"
    queue = ReportQueue(path)
    assert asyncio.run(queue.submit(TOR_PROJECT, "scam", "alice")) == "received"
    [record] = lines(path)
    assert set(record) == {"time", "address", "category", "subject"}
    assert record["address"] == TOR_PROJECT and record["category"] == "scam"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", record["time"])


def test_a_visitor_can_report_a_site_once_and_a_restart_does_not_forget(tmp_path: Path) -> None:
    path = tmp_path / "reports.log"
    queue = ReportQueue(path)
    assert asyncio.run(queue.submit(TOR_PROJECT, "scam", "alice")) == "received"
    assert asyncio.run(queue.submit(TOR_PROJECT, "harmful", "alice")) == "duplicate"
    assert asyncio.run(queue.submit(DUCKDUCKGO, "scam", "alice")) == "received"
    assert asyncio.run(queue.submit(TOR_PROJECT, "scam", "bob")) == "received"
    assert len(lines(path)) == 3 and queue.reporters_of(TOR_PROJECT) == 2
    again = ReportQueue(path)
    assert asyncio.run(again.submit(TOR_PROJECT, "scam", "alice")) == "duplicate"
    assert again.reporters_of(TOR_PROJECT) == 2


def test_only_the_listed_reasons_are_accepted(tmp_path: Path) -> None:
    queue = ReportQueue(tmp_path / "reports.log")
    for reason in ("", "free text from a visitor", "ILLEGAL", "illegal; drop"):
        with pytest.raises(ValueError, match="unknown reason"):
            asyncio.run(queue.submit(TOR_PROJECT, reason, "alice"))
    assert set(CATEGORIES) == {"illegal", "harmful", "scam", "other"}


def test_a_hostile_reporter_name_stays_on_one_short_line(tmp_path: Path) -> None:
    path = tmp_path / "reports.log"
    asyncio.run(ReportQueue(path).submit(TOR_PROJECT, "other", 'x"}\n{"a":1}\r\n' + "y" * 1000))
    [record] = lines(path)
    assert len(record["subject"]) <= 200


def test_a_report_file_that_cannot_be_read_stops_start_up(tmp_path: Path) -> None:
    bad = tmp_path / "bad.log"
    bad.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ReportError, match="line 1"):
        ReportQueue(bad)
    with pytest.raises(ReportError, match="cannot read"):
        ReportQueue(tmp_path)  # a folder


def test_a_report_that_cannot_be_written_is_not_counted(tmp_path: Path) -> None:
    path = tmp_path / "reports.log"
    queue = ReportQueue(path)
    asyncio.run(queue.submit(TOR_PROJECT, "scam", "alice"))
    path.unlink()
    path.mkdir()  # now it cannot be appended to
    with pytest.raises(ReportError):
        asyncio.run(queue.submit(DUCKDUCKGO, "scam", "alice"))
    assert queue.reporters_of(DUCKDUCKGO) == 0


# --- holding a site that enough people report ----------------------------------------------------


def test_enough_different_reporters_put_a_site_on_the_held_list(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    queue = ReportQueue(tmp_path / "reports.log", held=held, hold_after=3)
    asyncio.run(queue.submit(TOR_PROJECT, "scam", "a"))
    asyncio.run(queue.submit(TOR_PROJECT, "scam", "a"))  # the same person again
    asyncio.run(queue.submit(TOR_PROJECT, "scam", "b"))
    assert held.reason_for(TOR_PROJECT) is None
    asyncio.run(queue.submit(TOR_PROJECT, "harmful", "c"))
    assert held.reason_for(TOR_PROJECT) == "held"
    assert "reports:3" in (tmp_path / "held.txt").read_text(encoding="utf-8")
    assert held.reason_for(DUCKDUCKGO) is None


def test_a_site_is_only_held_once(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    queue = ReportQueue(tmp_path / "reports.log", held=held, hold_after=1)
    for who in ("a", "b", "c"):
        asyncio.run(queue.submit(TOR_PROJECT, "scam", who))
    assert len((tmp_path / "held.txt").read_text(encoding="utf-8").splitlines()) == 1


def test_a_held_list_that_cannot_be_written_does_not_lose_the_report(tmp_path: Path) -> None:
    held = HeldList(tmp_path)  # a folder cannot be appended to
    queue = ReportQueue(tmp_path / "reports.log", held=held, hold_after=1)
    assert asyncio.run(queue.submit(TOR_PROJECT, "scam", "a")) == "received"
    assert queue.reporters_of(TOR_PROJECT) == 1


def test_the_threshold_needs_a_held_list_and_a_sensible_number(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="held list"):
        ReportQueue(tmp_path / "r.log", hold_after=2)
    with pytest.raises(ValueError, match="at least 1"):
        ReportQueue(tmp_path / "r.log", held=HeldList(tmp_path / "h"), hold_after=0)


# --- in the gateway ------------------------------------------------------------------------------

IFRAME = {"sec-fetch-dest": "iframe", "sec-fetch-mode": "navigate"}
SAME = {"sec-fetch-site": "same-origin"}


def shown(env: Env, address: str = PAGE) -> str:
    """Open an address and load its page in the viewer's frame, as a browser would."""
    label = env.open(address)
    assert env.get(label, headers=IFRAME).status_code == 200
    return label


def report(env: Env, category: str = "scam", **extra: str) -> Any:
    return env.client.post("/_og/report", data={"category": category, **extra}, headers=SAME)


def test_a_visitor_reports_the_site_the_server_says_they_are_looking_at(tmp_path: Path) -> None:
    queue = ReportQueue(tmp_path / "reports.log")
    env = Env(lambda _r: reply("<p>page</p>"), reports=queue)
    shown(env)
    response = report(env, "illegal", address=OTHER, url=OTHER)  # extra fields are ignored
    assert response.status_code == 200 and "Thank you" in response.json()["message"]
    [record] = lines(tmp_path / "reports.log")
    assert record["address"] == TOR_PROJECT and record["category"] == "illegal"
    assert "page" not in json.dumps(record)  # no content is ever stored
    again = report(env, "scam")
    assert again.status_code == 200 and "already reported" in again.json()["message"]
    assert len(lines(tmp_path / "reports.log")) == 1


def test_a_report_follows_the_page_that_is_shown_now(tmp_path: Path) -> None:
    env = Env(lambda _r: reply("<p>page</p>"), reports=ReportQueue(tmp_path / "reports.log"))
    shown(env, PAGE)
    shown(env, OTHER)  # the viewer now shows the second site
    report(env)
    assert [r["address"] for r in lines(tmp_path / "reports.log")] == [DUCKDUCKGO]


@pytest.mark.parametrize("category", ["", "nonsense", "ILLEGAL", "illegal&category=other"])
def test_only_a_listed_reason_is_accepted(tmp_path: Path, category: str) -> None:
    env = Env(lambda _r: reply("<p>page</p>"), reports=ReportQueue(tmp_path / "reports.log"))
    shown(env)
    assert report(env, category).status_code == 400
    assert not (tmp_path / "reports.log").exists()


def test_there_must_be_a_page_and_a_session_and_it_must_come_from_the_viewer(
    tmp_path: Path,
) -> None:
    queue = ReportQueue(tmp_path / "reports.log")
    env = Env(lambda _r: reply("<p>page</p>"), reports=queue)
    assert report(env).status_code == 403  # no session yet
    env.open()
    assert report(env).status_code == 400  # a session, but nothing shown yet
    env.get(
        env.viewer_label(env.client.post("/open", data={"address": PAGE}).headers["location"]),
        headers=IFRAME,
    )
    cross = env.client.post(
        "/_og/report", data={"category": "scam"}, headers={"sec-fetch-site": "cross-site"}
    )
    assert cross.status_code == 403
    assert not (tmp_path / "reports.log").exists()


def test_a_session_can_only_send_so_many_reports(tmp_path: Path) -> None:
    env = Env(
        lambda _r: reply("<p>page</p>"),
        reports=ReportQueue(tmp_path / "reports.log"),
        max_reports_per_session=1,
    )
    shown(env, PAGE)
    assert report(env).status_code == 200
    shown(env, OTHER)
    limited = report(env)
    assert limited.status_code == 429 and len(lines(tmp_path / "reports.log")) == 1


def test_a_repeated_report_does_not_use_up_the_limit(tmp_path: Path) -> None:
    env = Env(
        lambda _r: reply("<p>page</p>"),
        reports=ReportQueue(tmp_path / "reports.log"),
        max_reports_per_session=2,
    )
    shown(env, PAGE)
    assert report(env).status_code == 200
    assert "already reported" in report(env).json()["message"]  # not counted
    shown(env, OTHER)
    assert report(env).status_code == 200  # the second real report is still within the limit
    assert len(lines(tmp_path / "reports.log")) == 2


def test_a_report_that_cannot_be_recorded_says_so(tmp_path: Path) -> None:
    path = tmp_path / "reports.log"
    env = Env(lambda _r: reply("<p>page</p>"), reports=ReportQueue(path))
    shown(env)
    path.mkdir()
    failed = report(env)
    assert failed.status_code == 503 and "could not be recorded" in failed.json()["message"]


def test_without_a_report_file_there_is_no_route_and_no_button() -> None:
    env = Env(lambda _r: reply("<p>page</p>"))
    label = env.open()
    assert (
        env.client.post("/_og/report", data={"category": "scam"}, headers=SAME).status_code == 404
    )
    viewer = env.client.get(f"/view?l={label}&p=%2F").text
    assert 'id="report"' not in viewer


def test_the_viewer_shows_the_report_controls_when_reports_are_on(tmp_path: Path) -> None:
    env = Env(lambda _r: reply("<p>page</p>"), reports=ReportQueue(tmp_path / "reports.log"))
    label = env.open()
    viewer = env.client.get(f"/view?l={label}&p=%2F").text
    assert 'id="report"' in viewer and 'id="report-category"' in viewer
    for name in CATEGORIES:
        assert f'value="{name}"' in viewer


def test_a_report_is_written_to_the_audit_log_without_content(tmp_path: Path) -> None:
    audit = MemoryAudit()
    env = Env(
        lambda _r: reply("<p>secret page text</p>"),
        reports=ReportQueue(tmp_path / "reports.log"),
        audit=audit,
    )
    shown(env)
    report(env, "harmful")
    [event] = [e for e in audit.events if e.kind == "report"]
    assert event.rule == "harmful" and "secret" not in repr(audit.events)


def test_reports_from_enough_different_accounts_hold_the_site_for_everyone(tmp_path: Path) -> None:
    held = HeldList(tmp_path / "held.txt")
    queue = ReportQueue(tmp_path / "reports.log", held=held, hold_after=2)
    team = Team(reports=queue, held=held)
    first, second = team.visitor("analyst", subject="a"), team.visitor("analyst", subject="b")
    for visitor in (first, second):
        visitor.open()
        visitor.client.get("/", headers={"host": visitor.label_host, **IFRAME})
    one = first.client.post("/_og/report", data={"category": "scam"}, headers=SAME)
    assert one.status_code == 200 and first.get().status_code == 200
    two = second.client.post("/_og/report", data={"category": "scam"}, headers=SAME)
    assert two.status_code == 200
    before = len(team.fetcher.requests)
    assert first.get().status_code == 403  # held now, for the first visitor too
    assert len(team.fetcher.requests) == before


# --- the command line ----------------------------------------------------------------------------


def test_the_options_are_wired_in_and_checked(tmp_path: Path) -> None:
    held = tmp_path / "held.txt"
    gateway = build_gateway(
        port=9000, report_file=tmp_path / "reports.log", held_file=held, hold_after=3
    )
    assert gateway.settings.reports is not None and gateway.settings.held is not None
    with pytest.raises(PolicyConfigError, match="report-file"):
        build_gateway(port=9000, hold_after=3, held_file=held)
    with pytest.raises(PolicyConfigError, match="held list"):
        build_gateway(port=9000, report_file=tmp_path / "r2.log", hold_after=3)
    bad = tmp_path / "bad.log"
    bad.write_text("nope\n", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="line 1"):
        build_gateway(port=9000, report_file=bad)
