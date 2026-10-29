# SPDX-License-Identifier: AGPL-3.0-only
"""Mapping between labels and the gateway's host names."""

from __future__ import annotations

import pytest

from onionglass.hosts import GatewayHosts
from onionglass.labels import new_label


def test_round_trip_with_port_case_and_trailing_dot() -> None:
    hosts = GatewayHosts("gateway.example")
    label = new_label()
    host = hosts.host_for(label)
    assert hosts.label_from_host(host) == label
    assert hosts.label_from_host(host.upper()) == label
    assert hosts.label_from_host(host + ".") == label
    assert hosts.label_from_host(host + ":8443") == label


def test_personal_mode_uses_localhost() -> None:
    hosts = GatewayHosts("localhost")
    label = new_label()
    assert hosts.host_for(label) == f"{label}.localhost"
    assert hosts.label_from_host(f"{label}.localhost:8080") == label


def test_other_hosts_do_not_match() -> None:
    hosts = GatewayHosts("gateway.example")
    label = new_label()
    for host in (
        "gateway.example",
        "example",
        f"{label}.gateway.example.evil.test",
        f"{label}.evilgateway.example",
        f"{label}gateway.example",
        f"x.{label}.gateway.example",
        f"{label[:-1]}.gateway.example",
        f"{label}x.gateway.example",
        f"[{label}.gateway.example]",
        f"{label}.gateway.example:notaport",
        f"{label}.gateway.example\n",
        "",
    ):
        assert hosts.label_from_host(host) is None, host


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "Gateway.Example",
        "gateway.example.",
        "-a.example",
        "a..example",
        "a b.example",
        "a_b.example",
        chr(0xE9) + ".example",
    ],
)
def test_bad_base_domains_are_rejected(domain: str) -> None:
    with pytest.raises(ValueError, match="base_domain"):
        GatewayHosts(domain)


def test_host_for_rejects_invalid_labels() -> None:
    with pytest.raises(ValueError, match="label"):
        GatewayHosts("gateway.example").host_for("not-a-label")
