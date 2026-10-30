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


def test_listening_on_all_addresses_is_only_allowed_inside_the_container_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ONIONGLASS_IN_CONTAINER", raising=False)
    assert main(["--host", "0.0.0.0"]) == 2  # noqa: S104
    monkeypatch.setenv("ONIONGLASS_IN_CONTAINER", "0")
    assert main(["--host", "0.0.0.0"]) == 2  # noqa: S104
    monkeypatch.setenv("ONIONGLASS_IN_CONTAINER", "1")
    started: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        started.update(kwargs)

    monkeypatch.setattr("onionglass.cli.uvicorn.run", fake_run)
    assert main(["--host", "0.0.0.0", "--port", "8080", "--public-port", "9090"]) == 0  # noqa: S104
    assert started["host"] == "0.0.0.0"  # noqa: S104
    assert started["access_log"] is False
    # Even in a container, only that one wildcard address is accepted.
    assert main(["--host", "192.0.2.10"]) == 2


def test_the_address_the_browser_uses_decides_the_gateways_own_port() -> None:
    assert build_gateway(port=9090).settings.port == 9090


def test_a_bad_port_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--port", "0"]) == 2
    assert main(["--port", "70000"]) == 2
    assert "port" in capsys.readouterr().err


def test_several_tor_ports_can_be_given() -> None:
    args = parse_arguments(["--tor-port", "9050", "--tor-port", "9052"])
    assert args.tor_port == [9050, 9052]
    gateway = build_gateway(port=8080, tor_ports=args.tor_port)
    assert gateway.fetcher is not None
