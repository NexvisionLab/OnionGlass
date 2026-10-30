# SPDX-License-Identifier: AGPL-3.0-only
"""Operator commands on the files the gateway watches.

The tests that matter most start a gateway on the same files and show that what a command writes
is what the gateway then does.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass import cli
from onionglass.admin import (
    AdminError,
    AdminPaths,
    held_add,
    held_list,
    held_release,
    kill_off,
    kill_on,
    kill_status,
    paths_from_config,
    reports_summary,
)
from onionglass.held import HeldList
from onionglass.killswitch import KillSwitch, parse_kill_file
from onionglass.reports import ReportQueue
from test_gateway import PAGE, Env, reply

OTHER = f"http://{DUCKDUCKGO}.onion/"
CONFIG = """
[server]
domain = "gateway.example.org"

[kill]
file = "state/kill"

[held]
file = "state/held.txt"

[reports]
file = "state/reports.log"
"""


@pytest.fixture
def home(tmp_path: Path) -> Path:
    (tmp_path / "state").mkdir()
    (tmp_path / "team.toml").write_text(CONFIG, encoding="utf-8")
    return tmp_path


@pytest.fixture
def paths(home: Path) -> AdminPaths:
    return paths_from_config(home / "team.toml")


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


# --- finding the files ---------------------------------------------------------------------------


def test_the_files_come_from_the_config_relative_to_it(home: Path, paths: AdminPaths) -> None:
    assert paths.kill == home / "state" / "kill"
    assert paths.held == home / "state" / "held.txt"
    assert paths.reports == home / "state" / "reports.log"


def test_absolute_paths_are_kept_and_missing_sections_are_none(tmp_path: Path) -> None:
    absolute = (tmp_path / "elsewhere" / "kill").as_posix()
    config = tmp_path / "c.toml"
    config.write_text(f'[kill]\nfile = "{absolute}"\n', encoding="utf-8")
    found = paths_from_config(config)
    assert found.kill == Path(absolute) and found.held is None and found.reports is None


def test_the_commands_do_not_need_the_rest_of_the_config_to_be_valid(home: Path) -> None:
    (home / "team.toml").write_text(
        CONFIG + "\n[tickets]\nkeys = 5\n[nonsense]\na = 1\n", encoding="utf-8"
    )
    assert paths_from_config(home / "team.toml").kill is not None


def test_a_missing_or_broken_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(AdminError, match="cannot read"):
        paths_from_config(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("this = is = not toml", encoding="utf-8")
    with pytest.raises(AdminError, match="not valid TOML"):
        paths_from_config(bad)


def test_a_section_the_config_does_not_have_is_named(tmp_path: Path) -> None:
    config = tmp_path / "c.toml"
    config.write_text("[server]\ndomain = 'x.example.org'\n", encoding="utf-8")
    none = paths_from_config(config)
    calls: list[Callable[[], list[str]]] = [
        lambda: kill_status(none),
        lambda: held_list(none),
        lambda: reports_summary(none),
    ]
    for call in calls:
        with pytest.raises(AdminError, match=r"no \[(kill|held|reports)\] section"):
            call()


# --- the kill file -------------------------------------------------------------------------------


def test_kill_status_describes_every_state(paths: AdminPaths) -> None:
    assert kill_status(paths) == ["not stopped: there is no kill file"]
    assert paths.kill is not None
    paths.kill.write_text("# nothing yet\n", encoding="utf-8")
    assert kill_status(paths) == ["not stopped: the kill file is empty"]
    paths.kill.write_text("all\nprofile free\n", encoding="utf-8")
    assert kill_status(paths) == ["stopped:", "  all", "  profile free"]
    paths.kill.write_text("this is a typo\n", encoding="utf-8")
    assert "stops the whole gateway" in kill_status(paths)[0]


def test_stopping_adds_scopes_once_and_keeps_what_was_there(paths: AdminPaths) -> None:
    assert paths.kill is not None
    paths.kill.write_text("# why: maintenance\nprofile free\n", encoding="utf-8")
    assert kill_on(paths, "all") == "stopped: all"
    assert kill_on(paths, "all") == "already stopped: all"
    assert kill_on(paths, "onion", f"{DUCKDUCKGO}.onion").startswith("stopped: onion ")
    text = paths.kill.read_text(encoding="utf-8")
    assert text.startswith("# why: maintenance\nprofile free\nall\n")
    assert not parse_kill_file(text).broken


def test_resuming_takes_out_one_scope_or_all_of_them(paths: AdminPaths) -> None:
    assert paths.kill is not None
    kill_on(paths, "all")
    kill_on(paths, "profile", "free")
    assert kill_off(paths, "all") == "resumed: all"
    assert kill_off(paths, "all") == "was not stopped: all"
    assert paths.kill.read_text(encoding="utf-8") == "profile free\n"
    assert kill_off(paths) == "resumed: the kill file is removed"
    assert not paths.kill.exists()
    assert kill_off(paths) == "nothing to resume: there is no kill file"


@pytest.mark.parametrize(
    ("scope", "value"),
    [
        ("profile", None),
        ("profile", ""),
        ("profile", "two words"),
        ("profile", "a#b"),
        ("onion", "nonsense"),
        ("onion", None),
        ("everything", None),
    ],
)
def test_a_bad_scope_is_refused_before_anything_is_written(
    paths: AdminPaths, scope: str, value: str | None
) -> None:
    assert paths.kill is not None
    with pytest.raises(AdminError):
        kill_on(paths, scope, value)
    assert not paths.kill.exists()


# --- the held list -------------------------------------------------------------------------------


def test_holding_listing_and_releasing_a_site(paths: AdminPaths) -> None:
    assert held_list(paths) == ["no sites are held"]
    assert held_add(paths, f"{TOR_PROJECT}.onion", "checked by hand") == f"held: {TOR_PROJECT}"
    assert held_add(paths, TOR_PROJECT) == f"already held: {TOR_PROJECT}"
    held_add(paths, DUCKDUCKGO)
    listing = held_list(paths)
    assert (
        len(listing) == 2 and listing[0].startswith(TOR_PROJECT) and "checked by hand" in listing[0]
    )
    assert held_release(paths, TOR_PROJECT) == f"released: {TOR_PROJECT}"
    assert held_release(paths, TOR_PROJECT) == f"was not held: {TOR_PROJECT}"
    assert [line.split()[0] for line in held_list(paths)] == [DUCKDUCKGO]


def test_releasing_keeps_comments_and_other_sites_and_finds_every_form_of_the_address(
    paths: AdminPaths,
) -> None:
    assert paths.held is not None
    paths.held.write_text(
        f"# queue, newest last\n{TOR_PROJECT} 2026-10-30T00:00:00Z name-gate\n"
        f"www.{TOR_PROJECT}.onion 2026-10-30T00:01:00Z reports:3\n"
        f"{DUCKDUCKGO} 2026-10-30T00:02:00Z by hand\n",
        encoding="utf-8",
    )
    held_release(paths, f"{TOR_PROJECT.upper()}.ONION")
    assert paths.held.read_text(encoding="utf-8") == (
        f"# queue, newest last\n{DUCKDUCKGO} 2026-10-30T00:02:00Z by hand\n"
    )


def test_a_reason_cannot_break_the_line_format_and_bad_addresses_are_refused(
    paths: AdminPaths,
) -> None:
    assert paths.held is not None
    held_add(paths, TOR_PROJECT, "line one\nline two " + "x" * 500)
    assert len(paths.held.read_text(encoding="utf-8").splitlines()) == 1
    for bad in ("nonsense", "", f"{TOR_PROJECT}x"):
        with pytest.raises(AdminError, match="valid onion address"):
            held_add(paths, bad)
        with pytest.raises(AdminError, match="valid onion address"):
            held_release(paths, bad)


def test_a_held_file_the_gateway_wrote_can_be_read_back(paths: AdminPaths) -> None:
    assert paths.held is not None
    asyncio.run(HeldList(paths.held).hold(TOR_PROJECT, "name-gate"))
    assert held_list(paths)[0].startswith(TOR_PROJECT)
    held_release(paths, TOR_PROJECT)
    assert HeldList(paths.held).reason_for(TOR_PROJECT) is None


# --- reports -------------------------------------------------------------------------------------


def test_the_report_summary_ranks_sites_and_never_shows_who_reported(paths: AdminPaths) -> None:
    assert paths.reports is not None
    queue = ReportQueue(paths.reports)
    for who, address, why in (
        ("alice-the-reporter", TOR_PROJECT, "scam"),
        ("bob-the-reporter", TOR_PROJECT, "scam"),
        ("carol-the-reporter", TOR_PROJECT, "harmful"),
        ("alice-the-reporter", DUCKDUCKGO, "other"),
    ):
        asyncio.run(queue.submit(address, why, who))
    summary = reports_summary(paths)
    assert summary[0] == f"{TOR_PROJECT}  3 visitors  (harmful 1, scam 2)"
    assert summary[1] == f"{DUCKDUCKGO}  1 visitor  (other 1)"
    assert not any("reporter" in line for line in summary)
    assert reports_summary(paths, at_least=2) == [summary[0]]
    assert reports_summary(paths, at_least=9) == ["no reports"]


def test_one_visitor_is_counted_once_even_if_a_hand_edited_file_lists_them_twice(
    paths: AdminPaths,
) -> None:
    assert paths.reports is not None
    line = f'{{"time":"2026-10-30T00:00:00Z","address":"{TOR_PROJECT}","category":"scam","subject":"same"}}'
    paths.reports.write_text((line + chr(10)) * 2, encoding="utf-8")
    assert reports_summary(paths)[0].startswith(f"{TOR_PROJECT}  1 visitor ")


def test_a_report_file_that_is_not_one_is_an_error(paths: AdminPaths) -> None:
    assert paths.reports is not None
    paths.reports.write_text('{"address": "x"}\nnot json\n', encoding="utf-8")
    with pytest.raises(AdminError, match="line 1"):
        reports_summary(paths)
    assert reports_summary(AdminPaths(None, None, paths.reports.with_name("none.log"))) == [
        "no reports"
    ]


def test_files_are_replaced_in_one_step_so_the_gateway_never_reads_half_a_file(
    paths: AdminPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    replaced: list[tuple[str, str]] = []
    real = os.replace

    def spy(source: Any, destination: Any) -> None:
        replaced.append((Path(source).name, Path(destination).name))
        real(source, destination)

    monkeypatch.setattr("onionglass.admin.os.replace", spy)
    kill_on(paths, "all")
    held_add(paths, TOR_PROJECT)
    held_release(paths, TOR_PROJECT)
    assert replaced == [
        ("kill.tmp", "kill"),
        ("held.txt.tmp", "held.txt"),
        ("held.txt.tmp", "held.txt"),
    ]
    assert not list((paths.kill or Path()).parent.glob("*.tmp"))  # nothing is left behind


# --- the gateway does what the commands write ----------------------------------------------------


def served(paths: AdminPaths, clock: Clock, **extra: Any) -> Env:
    assert paths.kill is not None and paths.held is not None
    return Env(
        lambda _r: reply("<p>hello</p>"),
        kill=KillSwitch(paths.kill, clock=clock, refresh=1.0),
        held=HeldList(paths.held, clock=clock, refresh=1.0),
        **extra,
    )


def test_stopping_and_resuming_with_the_commands_stops_and_resumes_the_gateway(
    paths: AdminPaths,
) -> None:
    clock = Clock()
    env = served(paths, clock)
    label = env.open()
    assert env.get(label).status_code == 200
    kill_on(paths, "all")
    clock.now += 2
    before = len(env.fetcher.requests)
    assert env.get(label).status_code == 503 and len(env.fetcher.requests) == before
    assert env.client.post("/open", data={"address": OTHER}).status_code == 503
    kill_off(paths)
    clock.now += 2
    assert env.get(label).status_code == 200


def test_stopping_one_site_leaves_the_others(paths: AdminPaths) -> None:
    clock = Clock()
    env = served(paths, clock)
    first, second = env.open(PAGE), env.open(OTHER)
    kill_on(paths, "onion", TOR_PROJECT)
    clock.now += 2
    assert env.get(first).status_code == 503 and env.get(second).status_code == 200


def test_holding_and_releasing_with_the_commands_changes_what_the_gateway_serves(
    paths: AdminPaths,
) -> None:
    clock = Clock()
    env = served(paths, clock)
    label = env.open()
    assert env.get(label).status_code == 200
    held_add(paths, TOR_PROJECT, "after a report")
    clock.now += 3
    assert env.get(label).status_code == 403
    assert env.client.post("/open", data={"address": PAGE}).status_code == 403
    held_release(paths, TOR_PROJECT)
    clock.now += 3
    assert env.get(label).status_code == 200


# --- the command line ----------------------------------------------------------------------------


def run(home: Path, *words: str) -> int:
    return cli.main(["admin", "--config", str(home / "team.toml"), *words])


def test_the_whole_thing_works_from_the_command_line(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(home, "kill", "status") == 0
    assert "not stopped" in capsys.readouterr().out
    assert run(home, "kill", "on", "--profile", "free") == 0
    assert run(home, "kill", "on", "--onion", DUCKDUCKGO) == 0
    assert run(home, "kill", "status") == 0
    status = capsys.readouterr().out
    assert "profile free" in status and f"onion {DUCKDUCKGO}" in status
    assert run(home, "kill", "off", "--profile", "free") == 0
    assert run(home, "kill", "off") == 0
    assert not (home / "state" / "kill").exists()
    capsys.readouterr()
    assert run(home, "held", "add", TOR_PROJECT, "--reason", "from the command line") == 0
    assert run(home, "held", "list") == 0
    assert "from the command line" in capsys.readouterr().out
    assert run(home, "held", "release", TOR_PROJECT) == 0


def test_a_missing_report_file_means_no_reports_not_an_error(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(home, "reports", "summary") == 0
    assert capsys.readouterr().out.strip() == "no reports"


def test_mistakes_are_one_line_and_exit_code_two(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(home, "kill", "on", "--onion", "nonsense") == 2
    assert run(home, "held", "release", "nonsense") == 2
    assert cli.main(["admin", "--config", str(home / "missing.toml"), "kill", "status"]) == 2
    errors = capsys.readouterr().err.strip().splitlines()
    assert len(errors) == 3 and all(line.startswith("onionglass: ") for line in errors)


def test_stopping_needs_a_scope_and_only_one(home: Path) -> None:
    for words in (("kill", "on"), ("kill", "on", "--all", "--profile", "free")):
        with pytest.raises(SystemExit) as caught:
            run(home, *words)
        assert caught.value.code == 2
