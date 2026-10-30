# SPDX-License-Identifier: AGPL-3.0-only
"""Metrics: useful to an operator, and unable to say what a visitor looked at."""

from __future__ import annotations

import random
import re
from pathlib import Path
from typing import Any

import pytest

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass import __version__
from onionglass.audit import MemoryAudit
from onionglass.cli import build_gateway
from onionglass.held import HeldList
from onionglass.killswitch import KillSwitch
from onionglass.metrics import REFUSAL_REASONS, Metrics, reason_for, token_matches
from onionglass.namegate import NameGate
from onionglass.policy import Decision, PolicyConfigError, PolicyRequest, StaticPolicy
from onionglass.reports import ReportQueue
from onionglass.settings import Profile, Settings
from onionglass.upstream import UpstreamError
from test_gateway import PAGE, Env, reply

TOKEN = "t" * 24
AUTH = {"authorization": f"Bearer {TOKEN}"}
OTHER = f"http://{DUCKDUCKGO}.onion/"


def read(env: Env) -> dict[str, float]:
    """The metrics as {'name{labels}': value}."""
    response = env.client.get("/_og/metrics", headers=AUTH)
    assert response.status_code == 200, response.text
    found: dict[str, float] = {}
    for line in response.text.splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.rpartition(" ")
            found[key] = float(value)
    return found


def served(**settings: Any) -> Env:
    return Env(lambda _r: reply("<p>hello</p>"), metrics_token=TOKEN, **settings)


# --- the pieces ----------------------------------------------------------------------------------


def test_rules_become_a_small_fixed_set_of_reasons() -> None:
    assert reason_for("kill:all") == "kill" and reason_for("kill:profile:secret-name") == "kill"
    assert reason_for("held") == "held" and reason_for("held-list-unreadable") == "held"
    assert reason_for("blocklist") == "policy" and reason_for("not-on-allowlist") == "policy"
    assert reason_for("name-gate") == "name-gate" and reason_for("quota") == "quota"
    assert reason_for("profile:post") == "profile" and reason_for("unrated:post") == "unrated"
    assert reason_for("policy-unavailable") == "policy-unavailable"
    assert reason_for("an operator wrote this rule name") == "other" and reason_for("") == "other"
    assert all(reason_for(r) in REFUSAL_REASONS for r in ("x", "kill:x", "profile:y", "z:z:z"))


def test_the_token_comparison() -> None:
    assert token_matches(TOKEN, TOKEN)
    assert not token_matches(None, TOKEN) and not token_matches("", TOKEN)
    assert not token_matches(TOKEN + "x", TOKEN) and not token_matches(TOKEN[:-1], TOKEN)
    assert not token_matches("u" * 24, TOKEN)


def test_an_unknown_label_value_can_never_start_a_new_series() -> None:
    metrics = Metrics(["known_error"])
    before = len(metrics.render({}, "1").splitlines())
    rng = random.Random(1)  # noqa: S311 - test input, not a secret
    for _ in range(2000):
        junk = "".join(rng.choice('abcdefghij{}"\n=, ') for _ in range(30))
        metrics.inc("refusals_total", reason=junk)
        metrics.inc("upstream_errors_total", kind=junk)
        metrics.inc("reports_total", category=junk)
        metrics.inc("requests_total", action=junk, outcome=junk)
        metrics.inc("upstream_responses_total", **{"class": junk})
    text = metrics.render({}, "1")
    assert len(text.splitlines()) == before
    assert 'reason="other"} 2000' in text and 'kind="other"} 2000' in text
    assert junk not in text


def test_the_output_is_valid_prometheus_text() -> None:
    metrics = Metrics(["known_error"])
    metrics.inc("requests_total", action="fetch", outcome="allowed")
    metrics.observe_upstream(0.7)
    metrics.observe_upstream(100.0)
    text = metrics.render({"up": ("Running.", 1.0)}, "1.2.3")
    sample = re.compile(r'^[a-z_]+(\{[a-z_]+="[^"\n]*"(,[a-z_]+="[^"\n]*")*\})? -?[0-9.e+]+$')
    for line in text.splitlines():
        assert line.startswith(("# HELP ", "# TYPE ")) or sample.match(line), line
    assert 'onionglass_requests_total{action="fetch",outcome="allowed"} 1' in text
    assert 'onionglass_requests_total{action="open",outcome="refused"} 0' in text  # zeros are shown
    assert 'onionglass_upstream_seconds_bucket{le="1.0"} 1' in text
    assert 'onionglass_upstream_seconds_bucket{le="60.0"} 1' in text
    assert 'onionglass_upstream_seconds_bucket{le="+Inf"} 2' in text
    assert "onionglass_upstream_seconds_count 2" in text
    assert 'onionglass_build_info{version="1.2.3"} 1' in text


# --- the endpoint --------------------------------------------------------------------------------


def test_the_endpoint_is_off_unless_a_token_is_set() -> None:
    env = Env(lambda _r: reply("<p>x</p>"))
    assert env.client.get("/_og/metrics", headers=AUTH).status_code == 404


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"authorization": "Bearer wrong-token-wrong-token"},
        {"authorization": TOKEN},
        {"authorization": f"Basic {TOKEN}"},
        {"authorization": "Bearer "},
    ],
)
def test_the_endpoint_needs_the_token(headers: dict[str, str]) -> None:
    response = served().client.get("/_og/metrics", headers=headers)
    assert response.status_code == 401 and response.headers["www-authenticate"] == "Bearer"
    assert response.text == ""


def test_the_endpoint_answers_a_scraper_with_the_token() -> None:
    response = served().client.get("/_og/metrics", headers=AUTH)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert f'onionglass_build_info{{version="{__version__}"}} 1' in response.text
    assert "onionglass_up 1" in response.text


def test_a_site_cannot_reach_the_endpoint_through_its_own_address() -> None:
    env = served()
    label = env.open()
    page = env.get(label, "/_og/metrics", headers=AUTH)
    assert "onionglass_up" not in page.text  # it went to the onion site, which has no such page


def test_the_token_must_be_long_enough() -> None:
    for bad in ("short", "has a space in it 12345", "x" * 15, "caf" + chr(0xE9) * 20):
        with pytest.raises(ValueError, match="metrics token"):
            Settings(base_domain="localhost", open_mode=True, metrics_token=bad)


# --- what is counted -----------------------------------------------------------------------------


def test_requests_sessions_and_replies_are_counted() -> None:
    env = served()
    label = env.open()
    env.get(label)
    env.get(label)
    m = read(env)
    assert m['onionglass_requests_total{action="open",outcome="allowed"}'] == 1
    assert m['onionglass_requests_total{action="fetch",outcome="allowed"}'] == 2
    assert m['onionglass_upstream_responses_total{class="2xx"}'] == 2
    assert m["onionglass_sessions_created_total"] == 1
    assert m["onionglass_upstream_seconds_count"] == 2
    assert m["onionglass_active_fetches"] == 0 and m["onionglass_fetch_capacity"] == 32


def test_failures_are_counted_by_kind() -> None:
    env = Env(lambda _r: UpstreamError("descriptor_not_found"), metrics_token=TOKEN)
    env.get(env.open())
    env.get(env.open())
    m = read(env)
    assert m['onionglass_upstream_errors_total{kind="descriptor_not_found"}'] == 2


def test_refusals_are_counted_by_reason(tmp_path: Path) -> None:
    kill = tmp_path / "kill"
    env = served(
        policy=StaticPolicy(blocked=[TOR_PROJECT]),
        kill=KillSwitch(kill, refresh=0.0),
    )
    assert env.client.post("/open", data={"address": PAGE}).status_code == 403
    kill.write_text("all\n", encoding="utf-8")
    assert env.client.post("/open", data={"address": OTHER}).status_code == 503
    m = read(env)
    assert m['onionglass_refusals_total{reason="policy"}'] == 1
    assert m['onionglass_refusals_total{reason="kill"}'] == 1
    assert m['onionglass_requests_total{action="open",outcome="refused"}'] == 2
    assert m["onionglass_kill_all"] == 1


def test_the_kill_gauge_follows_the_kill_file(tmp_path: Path) -> None:
    kill = tmp_path / "kill"
    env = served(kill=KillSwitch(kill, refresh=0.0))
    assert read(env)["onionglass_kill_all"] == 0
    kill.write_text("profile restricted\n", encoding="utf-8")
    assert read(env)["onionglass_kill_all"] == 0  # a narrower stop is not a full stop
    kill.write_text("this is a typo\n", encoding="utf-8")
    assert read(env)["onionglass_kill_all"] == 1  # an unreadable file stops everything


def test_rate_limits_quotas_unknown_profiles_and_the_name_gate_are_counted(tmp_path: Path) -> None:
    profile = Profile(name="personal", max_requests_per_minute=2)  # opening counts as one
    env = Env(
        lambda _r: reply("<title>Grape</title><p>x</p>"),
        profile=profile,
        metrics_token=TOKEN,
        name_gate=NameGate(["grape"]),
        held=HeldList(tmp_path / "held.txt"),
    )
    label = env.open()
    env.get(label)  # the name gate refuses the page
    env.get(label)  # the rate limit
    m = read(env)
    assert m['onionglass_refusals_total{reason="name-gate"}'] == 1
    assert m['onionglass_refusals_total{reason="rate-limit"}'] == 1


def test_reports_and_rewrite_failures_are_counted(tmp_path: Path) -> None:
    env = Env(
        lambda _r: reply("<p>" + "<b>" * 40000 + "</p>"),
        metrics_token=TOKEN,
        reports=ReportQueue(tmp_path / "reports.log"),
    )
    label = env.open()
    assert env.get(label, headers={"sec-fetch-dest": "iframe"}).status_code == 502
    m = read(env)
    assert m["onionglass_rewrite_failures_total"] == 1
    assert m['onionglass_reports_total{category="scam"}'] == 0


def test_an_audit_failure_is_counted_even_though_it_cannot_be_logged() -> None:
    class Broken:
        async def write(self, event: Any) -> None:
            raise RuntimeError("down")

    env = served(audit=Broken(), hook_timeout=0.05)
    assert env.client.post("/open", data={"address": PAGE}).status_code == 503
    assert read(env)['onionglass_refusals_total{reason="audit-unavailable"}'] == 1


# --- privacy -------------------------------------------------------------------------------------


def test_the_metrics_never_say_what_anyone_opened_or_who_they_are() -> None:
    class Secretive:
        async def decide(self, request: PolicyRequest) -> Decision:
            if request.origin.host.address == DUCKDUCKGO:
                return Decision.deny("my-private-operator-rule")
            return Decision.allow("another-private-rule")

    audit = MemoryAudit()
    env = served(policy=Secretive(), audit=audit)
    label = env.open(PAGE)
    env.get(label, "/a/very/private/path?token=hunter2")
    env.client.post("/open", data={"address": OTHER})
    text = env.client.get("/_og/metrics", headers=AUTH).text
    for secret in (
        TOR_PROJECT, TOR_PROJECT[:12], DUCKDUCKGO, DUCKDUCKGO[:12], "private", "hunter2",
        "my-private-operator-rule", "another-private-rule", "local", ".onion", label,
    ):  # fmt: skip
        assert secret not in text, secret
    assert 'onionglass_refusals_total{reason="other"} 1' in text  # the operator's own rule name


# --- the command line ----------------------------------------------------------------------------


def test_the_metrics_token_comes_from_a_file(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    assert build_gateway(port=9000, metrics_token_file=token_file).settings.metrics_token == TOKEN
    assert build_gateway(port=9000).settings.metrics_token is None
    with pytest.raises(PolicyConfigError, match="cannot read"):
        build_gateway(port=9000, metrics_token_file=tmp_path / "missing")
    token_file.write_text("short\n", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="metrics token"):
        build_gateway(port=9000, metrics_token_file=token_file)
