# SPDX-License-Identifier: AGPL-3.0-only
"""Availability problems found by the third independent review, each with its reproduction.

Every test here failed on the code as reviewed. They are about one visitor, or one request,
being able to slow down or take over the whole gateway.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import zlib
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from helpers import DUCKDUCKGO, TOR_PROJECT, fresh_address
from onionglass.config import ConfigError, load_config
from onionglass.decode import DecodeError, decode_body
from onionglass.gateway import _has_file_part
from onionglass.held import HeldList
from onionglass.quota import LocalQuota, QuotaError
from onionglass.reports import ReportError, ReportQueue
from onionglass.settings import Profile
from onionglass.store import InMemoryStore
from test_config import Layout
from test_gateway import APEX, Env, reply

# --- one visitor filling the shared store ----------------------------------------------------------


def typed() -> str:
    """An address as a visitor would type it into the entry form."""
    return f"{fresh_address()}.onion"


def test_a_full_store_refuses_politely_and_never_becomes_an_internal_error() -> None:
    env = Env(lambda _r: reply("<p>x</p>"), store=InMemoryStore(max_entries=60))
    codes = {env.client.post("/open", data={"address": typed()}).status_code for _ in range(60)}
    assert 500 not in codes
    assert codes <= {303, 429, 503}


def test_one_visitor_cannot_fill_the_store_by_typing_endless_addresses() -> None:
    env = Env(
        lambda _r: reply("<p>x</p>"),
        store=InMemoryStore(max_entries=4000),
        max_opens_per_session=20,
    )
    codes = [env.client.post("/open", data={"address": typed()}).status_code for _ in range(80)]
    assert codes.count(303) == 20 and set(codes) <= {303, 429}
    assert env.store._bytes < 100_000
    # Somebody else can still come in, and the store has room.
    other = TestClient(env.gateway.app, base_url=f"http://{APEX}", follow_redirects=False)
    assert other.post("/open", data={"address": typed()}).status_code == 303


def test_typing_addresses_is_covered_by_the_profile_request_limit() -> None:
    env = Env(
        lambda _r: reply("<p>x</p>"),
        profile=Profile(name="personal", max_requests_per_minute=3),
        max_opens_per_session=1000,
    )
    codes = [env.client.post("/open", data={"address": typed()}).status_code for _ in range(8)]
    assert codes.count(303) == 3 and codes.count(429) == 5
    env.clock[0] += 61
    assert env.client.post("/open", data={"address": typed()}).status_code == 303


def test_opening_the_same_address_again_does_not_use_up_the_allowance() -> None:
    env = Env(lambda _r: reply("<p>x</p>"), max_opens_per_session=3)
    for address in (typed(), typed(), typed()):
        assert env.client.post("/open", data={"address": address}).status_code == 303
        assert env.client.post("/open", data={"address": address}).status_code == 303
    assert env.client.post("/open", data={"address": typed()}).status_code == 429


# --- one request freezing the event loop ---------------------------------------------------------------

BOUNDARY = "multipart/form-data; boundary=XyZ123"


def part(name: str, extra: str = "", data: bytes = b"value") -> bytes:
    return (
        f'--XyZ123\r\nContent-Disposition: form-data; name="{name}"{extra}\r\n\r\n'.encode()
        + data
        + b"\r\n"
    )


def test_a_hostile_body_is_checked_in_linear_time() -> None:
    body = b"content-disposition:" * 20_000  # 400 KB with no line break and no semicolon
    started = time.perf_counter()
    _has_file_part(body, BOUNDARY)
    assert time.perf_counter() - started < 0.5
    started = time.perf_counter()
    _has_file_part(b"--XyZ123\r\n" + b"content-disposition: " * 20_000, BOUNDARY)
    assert time.perf_counter() - started < 0.5


def test_a_file_in_a_multipart_body_is_found_wherever_it_is() -> None:
    plain = part("a") + part("b")
    with_file = part("a") + part("f", '; filename="x.txt"') + b"--XyZ123--\r\n"
    assert _has_file_part(plain + b"--XyZ123--\r\n", BOUNDARY) is False
    assert _has_file_part(with_file, BOUNDARY) is True
    assert _has_file_part(part("f", "; FILENAME=x") + b"--XyZ123--", BOUNDARY) is True
    assert _has_file_part(part("f", "; filename*=UTF-8''x.txt") + b"--XyZ123--", BOUNDARY) is True
    assert _has_file_part(part("f", '; filename = "x"') + b"--XyZ123--", BOUNDARY) is True
    quoted = f'"{BOUNDARY.split("=")[1]}"'
    assert _has_file_part(with_file, f"multipart/form-data; boundary={quoted}") is True


def test_the_word_filename_in_a_value_is_not_a_file() -> None:
    body = part("note", data=b'content-disposition: form-data; name="x"; filename="not a header"')
    assert _has_file_part(body + b"--XyZ123--", BOUNDARY) is False


def test_a_body_that_cannot_be_read_as_multipart_counts_as_having_a_file() -> None:
    assert _has_file_part(b"anything", "multipart/form-data") is True  # no boundary at all
    assert _has_file_part(b"anything", "multipart/form-data; boundary=") is True
    assert _has_file_part(b"anything", "application/x-www-form-urlencoded") is False
    assert _has_file_part(b"anything", None) is False


def test_a_big_hostile_post_does_not_hold_up_everyone_else() -> None:
    env = Env(lambda _r: reply("<p>x</p>"))
    label = env.open()
    headers = {
        "host": f"{label}.localhost:8765",
        "content-type": BOUNDARY,
        "sec-fetch-site": "same-origin",
    }
    started = time.perf_counter()
    env.client.post("/x", content=b"content-disposition:" * 20_000, headers=headers)
    assert time.perf_counter() - started < 2


# --- limits that fail open ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [0, -1])
def test_a_size_limit_below_one_is_refused_by_profiles(bad: int) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        Profile(max_page_bytes=bad)
    with pytest.raises(ValueError, match="at least 1"):
        Profile(max_asset_bytes=bad)
    with pytest.raises(ValueError, match="above zero"):
        Profile(rewrite_timeout=float(bad))


def test_absurd_profile_limits_are_refused() -> None:
    with pytest.raises(ValueError, match="too large"):
        Profile(max_page_bytes=2_000_000_000)
    with pytest.raises(ValueError, match="too large"):
        Profile(rewrite_timeout=10_000)
    with pytest.raises(ValueError, match="too large"):
        Profile(max_requests_per_minute=10**12)


def test_a_negative_output_limit_cannot_turn_the_decompression_cap_off() -> None:
    bomb = zlib.compress(b"\0" * 5_000_000)
    for bad in (-1, 0):
        with pytest.raises(DecodeError):
            decode_body(bomb, "deflate", max_output=bad)


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("session_hours", "0"),
        ("session_hours", "-1"),
        ("max_labels_per_session", "0"),
        ("max_labels_per_session", "-5"),
        ("max_opens_per_session", "0"),
        ("max_new_sessions_per_minute", "0"),
        ("max_concurrent_fetches", "0"),
        ("max_concurrent_fetches", "1000000000"),
        ("max_fetches_per_session", "0"),
        ("max_request_body", "-1"),
        ("max_reports_per_session", "0"),
        ("hook_timeout", "0"),
    ],
)
def test_the_config_refuses_limits_that_would_fail_open_or_stop_everything(
    tmp_path: Path, setting: str, value: str
) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    if setting in text:
        text = re.sub(rf"^{setting} = .*$", f"{setting} = {value}", text, flags=re.MULTILINE)
    else:
        text = text.replace("[limits]\n", f"[limits]\n{setting} = {value}\n", 1)
    layout.config.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(layout.config)


def test_the_config_refuses_profile_numbers_that_fail_open(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    for old, new in (
        ("max_page_bytes = 5000000", "max_page_bytes = -1"),
        ("max_asset_bytes = 10000000", "max_asset_bytes = 0"),
        ("rewrite_timeout = 15", "rewrite_timeout = 0"),
        ("rewrite_timeout = 15", "rewrite_timeout = 1000000000000"),
    ):
        text = layout.text().replace(old, new, 1)
        layout.config.write_text(text, encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(layout.config)
        layout.config.write_text(text.replace(new, old, 1), encoding="utf-8")


# --- a held list that is read again and again -----------------------------------------------------------


def test_an_unchanged_held_list_is_not_read_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    path = tmp_path / "held.txt"
    path.write_text(f"{TOR_PROJECT} 2026-10-30T00:00:00Z name-gate\n", encoding="utf-8")
    held = HeldList(path, clock=lambda: clock[0], refresh=1.0)
    loads: list[int] = []
    original = held._load

    def counting() -> Any:
        loads.append(1)
        return original()

    monkeypatch.setattr(held, "_load", counting)
    for _ in range(10):
        clock[0] += 2
        assert held.reason_for(TOR_PROJECT) == "held"
    assert len(loads) == 1  # the file did not change, so it was parsed once
    path.write_text(
        path.read_text(encoding="utf-8") + f"{DUCKDUCKGO} 2026-10-30T00:01:00Z by hand\n",
        encoding="utf-8",
    )
    clock[0] += 2
    assert held.reason_for(DUCKDUCKGO) == "held" and len(loads) == 2


def test_a_very_long_held_list_is_read_quickly(tmp_path: Path) -> None:
    path = tmp_path / "held.txt"
    path.write_text(
        "".join(f"{fresh_address()} 2026-10-30T00:00:00Z reports:3\n" for _ in range(3000)),
        encoding="utf-8",
    )
    started = time.perf_counter()
    HeldList(path).reason_for(TOR_PROJECT)
    per_line = (time.perf_counter() - started) / 3000
    assert (
        per_line < 0.0002
    )  # 40,000 lines in under 8 seconds was the problem; this is 40 times better


# --- a torn last line ---------------------------------------------------------------------------------


def test_a_last_line_cut_off_by_a_crash_is_ignored_not_fatal(tmp_path: Path) -> None:
    journal = tmp_path / "quota.log"
    good = json.dumps({"d": int(time.time() // 86_400), "s": "a", "p": "free", "n": 2})
    journal.write_text(good + "\n" + '{"d": 1, "s": "b", "p"', encoding="utf-8")  # no final newline
    meter = LocalQuota(journal)
    assert asyncio.run(meter.used("a", "free")) == 2
    reports = tmp_path / "reports.log"
    line = json.dumps(
        {"time": "2026-10-30T00:00:00Z", "address": TOR_PROJECT, "category": "scam", "subject": "a"}
    )
    reports.write_text(line + "\n" + '{"address": "x", "subj', encoding="utf-8")
    assert ReportQueue(reports).reporters_of(TOR_PROJECT) == 1
    held = tmp_path / "held.txt"
    cut = DUCKDUCKGO[:30]  # the crash came part way through writing the address
    held.write_text(f"{TOR_PROJECT} 2026-10-30T00:00:00Z name-gate\n{cut}", encoding="utf-8")
    assert HeldList(held).reason_for(TOR_PROJECT) == "held"
    assert HeldList(held).reason_for(DUCKDUCKGO) is None  # half an address says nothing
    # A cut-off line that still holds a whole address does hold it, the safe way to read it.
    held.write_text(f"{DUCKDUCKGO} 2026-10", encoding="utf-8")
    assert HeldList(held).reason_for(DUCKDUCKGO) == "held"


def test_a_bad_line_in_the_middle_is_still_an_error(tmp_path: Path) -> None:
    good = json.dumps({"d": int(time.time() // 86_400), "s": "a", "p": "free", "n": 2})
    journal = tmp_path / "quota.log"
    journal.write_text("not json\n" + good + "\n", encoding="utf-8")
    with pytest.raises(QuotaError, match="line 1"):
        LocalQuota(journal)
    reports = tmp_path / "reports.log"
    reports.write_text("not json\n" + "{}\n", encoding="utf-8")
    with pytest.raises(ReportError, match="line 1"):
        ReportQueue(reports)
    held = tmp_path / "held.txt"
    held.write_text(
        "not an address\n" + f"{TOR_PROJECT} 2026-10-30T00:00:00Z x\n", encoding="utf-8"
    )
    assert HeldList(held).reason_for(TOR_PROJECT) == "held-list-unreadable"


def _unused(_: Any) -> None:  # keeps the Any import honest for type checkers
    return None
