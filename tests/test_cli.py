# SPDX-License-Identifier: AGPL-3.0-only
"""The command line entry point."""

from __future__ import annotations

import pytest

from onionglass.cli import build_gateway, main, parse_arguments


def test_defaults() -> None:
    args = parse_arguments([])
    assert args.host == "127.0.0.1" and args.port == 8080
    assert args.tor_host == "127.0.0.1" and args.tor_port is None
    assert args.allow_images is False


def test_a_personal_gateway_is_local_only_and_needs_no_sign_in() -> None:
    gateway = build_gateway(port=9000)
    assert gateway.settings.open_mode is True
    assert gateway.settings.base_domain == "localhost"
    assert gateway.settings.port == 9000
    assert gateway.settings.profile.allow_images is False


def test_images_are_only_on_when_asked_for() -> None:
    assert build_gateway(port=9000, allow_images=True).settings.profile.allow_images is True


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.10", "example.org", "::", ""])  # noqa: S104
def test_personal_mode_refuses_to_listen_beyond_this_machine(
    host: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--host", host]) == 2
    assert "only listens on this machine" in capsys.readouterr().err


def test_a_bad_port_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--port", "0"]) == 2
    assert main(["--port", "70000"]) == 2
    assert "port" in capsys.readouterr().err


def test_several_tor_ports_can_be_given() -> None:
    args = parse_arguments(["--tor-port", "9050", "--tor-port", "9052"])
    assert args.tor_port == [9050, 9052]
    gateway = build_gateway(port=8080, tor_ports=args.tor_port)
    assert gateway.fetcher is not None
