# SPDX-License-Identifier: AGPL-3.0-only
"""Metrics in the Prometheus text format, built so they cannot say what a visitor looked at.

Every label has a small fixed set of allowed values, and anything outside the set is counted as
``other``. No metric is labelled with an onion address, an account, a session, a path or the name
of a rule an operator wrote, so scraping the endpoint, or losing the scrape, reveals nothing about
what anyone opened (properties P8 and P10). What it does show is how healthy the gateway is: how
many requests were allowed and why others were refused, how Tor fetches are going, and how close
the gateway is to its limits.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable, Mapping
from itertools import product

PREFIX = "onionglass_"
BUCKETS = (0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
REFUSAL_REASONS = (
    "kill", "held", "policy", "policy-unavailable", "quota", "quota-unavailable", "name-gate",
    "profile", "unrated", "rate-limit", "audit-unavailable", "unknown-profile", "other",
)  # fmt: skip
STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx")
CATEGORIES = ("illegal", "harmful", "scam", "other")
_POLICY_RULES = frozenset({"blocklist", "not-on-allowlist"})
_RULE_TO_REASON = {"held-list-unreadable": "held"}


def reason_for(rule: str) -> str:
    """The metric label for the rule that refused a request. Unknown rules become ``other``."""
    first = _RULE_TO_REASON.get(rule) or rule.split(":", 1)[0]
    if first in _POLICY_RULES:
        return "policy"
    return first if first in REFUSAL_REASONS else "other"


def token_matches(supplied: str | None, expected: str) -> bool:
    """Compare a bearer token without leaking how much of it was right."""
    if not supplied:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


class Metrics:
    """Counters with fixed label sets, one histogram, and a few gauges supplied when rendered."""

    def __init__(self, known_errors: Iterable[str]) -> None:
        errors = tuple(sorted({*known_errors, "other"}))
        self._spec: dict[str, tuple[str, dict[str, tuple[str, ...]]]] = {
            "requests_total": (
                "Requests that reached the admission check.",
                {"action": ("open", "fetch"), "outcome": ("allowed", "refused")},
            ),
            "refusals_total": (
                "Requests that were refused, by reason.",
                {"reason": REFUSAL_REASONS},
            ),
            "upstream_responses_total": (
                "Replies from onion sites, by status class.",
                {"class": STATUS_CLASSES},
            ),
            "upstream_errors_total": (
                "Fetches that failed before a reply, by error kind.",
                {"kind": errors},
            ),
            "reports_total": ("Visitor reports accepted, by reason.", {"category": CATEGORIES}),
            "sessions_created_total": ("Sessions created.", {}),
            "rewrite_failures_total": ("Pages that could not be rewritten safely.", {}),
        }
        self._counts: dict[tuple[str, tuple[str, ...]], int] = {}
        self._buckets = [0] * len(BUCKETS)
        self._seconds_sum = 0.0
        self._seconds_count = 0

    def inc(self, name: str, **labels: str) -> None:
        _help, allowed = self._spec[name]
        # A value outside the allowed set is counted as "other", or as the set's last value if it
        # has no "other". It can never start a new series.
        values = tuple(
            labels[label]
            if labels.get(label) in options
            else ("other" if "other" in options else options[-1])
            for label, options in allowed.items()
        )
        self._counts[(name, values)] = self._counts.get((name, values), 0) + 1

    def observe_upstream(self, seconds: float) -> None:
        self._seconds_sum += seconds
        self._seconds_count += 1
        for index, bound in enumerate(BUCKETS):
            if seconds <= bound:
                self._buckets[index] += 1

    def render(self, gauges: Mapping[str, tuple[str, float]], version: str) -> str:
        lines: list[str] = []
        for name, (help_text, allowed) in self._spec.items():
            full = PREFIX + name
            lines += [f"# HELP {full} {help_text}", f"# TYPE {full} counter"]
            combos = list(product(*allowed.values())) if allowed else [()]
            for values in combos:
                labels = ",".join(
                    f'{key}="{value}"' for key, value in zip(allowed, values, strict=True)
                )
                count = self._counts.get((name, tuple(values)), 0)
                lines.append(f"{full}{{{labels}}} {count}" if labels else f"{full} {count}")
        full = PREFIX + "upstream_seconds"
        lines += [f"# HELP {full} Time to fetch from an onion site.", f"# TYPE {full} histogram"]
        for bound, count in zip(BUCKETS, self._buckets, strict=True):
            lines.append(f'{full}_bucket{{le="{bound}"}} {count}')
        lines += [
            f'{full}_bucket{{le="+Inf"}} {self._seconds_count}',
            f"{full}_sum {self._seconds_sum:.3f}",
            f"{full}_count {self._seconds_count}",
        ]
        for name, (help_text, value) in gauges.items():
            full = PREFIX + name
            lines += [f"# HELP {full} {help_text}", f"# TYPE {full} gauge", f"{full} {value:g}"]
        info = PREFIX + "build_info"
        lines += [
            f"# HELP {info} The version of this gateway.",
            f"# TYPE {info} gauge",
            f'{info}{{version="{version}"}} 1',
        ]
        return "\n".join(lines) + "\n"
