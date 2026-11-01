# SPDX-License-Identifier: AGPL-3.0-only
"""The commands for relays: adding one, listing, revoking, and checking that a gateway knows it."""

from __future__ import annotations

import asyncio
import os
import tomllib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from onionglass import cli
from onionglass.config import load_config
from onionglass.relayauth import RelayVerifier
from onionglass.relayconfig import load_relay_config
from onionglass.tickets import generate_key
from test_config import Layout, pem_private, pem_public, secret
from test_relay_end_to_end import Chain

PIN = "cd" * 32
DOMAIN = "gateway.example.org"


def add(layout: Layout, out: Path, *extra: str, name: str = "r1") -> int:
    return cli.main(
        ["relays", "add", "--config", str(layout.config), "--name", name, "--out", str(out), *extra]
    )


def tables(layout: Layout, name: str) -> int:
    """How many times a table of that name is opened in the file, not counting comments."""
    return sum(1 for line in layout.text().splitlines() if line.strip() == f"[{name}]")


def with_origin(*extra: str) -> list[str]:
    return ["--origin-url", "https://203.0.113.10:8443", "--pin-sha256", PIN, *extra]


# --- adding a relay ------------------------------------------------------------------------------


def test_adding_a_relay_makes_its_key_its_file_and_the_gateways_entry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    assert add(layout, out, *with_origin()) == 0
    shown = capsys.readouterr().out
    assert (out / "relay-r1.key").is_file() and (out / "relay-r1.toml").is_file()
    assert (tmp_path / "keys" / "relay-r1.public.pem").is_file()
    assert "relay-r1.key" in shown and "restart the gateway" in shown.lower()
    settings = load_config(layout.config).settings
    assert settings.relay_keys is not None and settings.relay_keys.ids() == ["r1"]
    assert settings.relay_required is False  # nothing is cut off until the operator says so


def test_the_key_the_gateway_trusts_is_the_one_the_relay_signs_with(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    assert add(layout, out, *with_origin()) == 0
    relay = load_relay_config(out / "relay-r1.toml")
    ring = load_config(layout.config).settings.relay_keys
    assert ring is not None
    signed = relay.settings.signer.sign("GET", DOMAIN, "/")
    assert RelayVerifier(ring).verify(signed, "GET", DOMAIN, "/") == "r1"


def test_the_private_key_is_kept_private_and_the_public_one_holds_no_secret(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    private = (out / "relay-r1.key").read_bytes()
    public = (tmp_path / "keys" / "relay-r1.public.pem").read_bytes()
    assert b"PRIVATE" in private and b"PRIVATE" not in public
    assert serialization.load_pem_public_key(public) is not None
    if os.name != "nt":
        assert (out / "relay-r1.key").stat().st_mode & 0o077 == 0
    assert private not in layout.config.read_bytes()


def test_without_the_gateways_address_the_file_says_what_to_fill_in_and_will_not_start(
    tmp_path: Path,
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    assert add(layout, out) == 0
    text = (out / "relay-r1.toml").read_text(encoding="utf-8")
    assert "EDIT" in text
    with pytest.raises(Exception, match=r"pin_sha256|url"):
        load_relay_config(out / "relay-r1.toml")


def test_the_relay_file_names_the_domain_and_the_key_it_goes_with(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    data = tomllib.loads((out / "relay-r1.toml").read_text(encoding="utf-8"))
    assert data["relay"]["domains"] == [DOMAIN]
    assert data["sign"] == {"key_id": "r1", "key_file": "relay-r1.key"}


def test_a_second_relay_is_added_beside_the_first(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    assert add(layout, out, *with_origin(), name="r1") == 0
    assert add(layout, out, *with_origin(), name="r2") == 0
    ring = load_config(layout.config).settings.relay_keys
    assert ring is not None and ring.ids() == ["r1", "r2"]
    assert tables(layout, "relays") == 1


def test_a_relay_for_a_group_domain_is_made_by_naming_the_domain(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    layout.config.write_text(
        layout.text() + '\n[entries.alpha]\ndomain = "alpha.example.net"\nport = 8090\n',
        encoding="utf-8",
    )
    assert add(layout, out, *with_origin("--domain", "alpha.example.net")) == 0
    data = tomllib.loads((out / "relay-r1.toml").read_text(encoding="utf-8"))
    assert data["relay"]["domains"] == ["alpha.example.net"]


@pytest.mark.parametrize(
    "extra",
    [["--domain", "other.example.com"], ["--domain", "Gateway.Example.Org"]],
)
def test_a_relay_for_a_domain_the_gateway_does_not_serve_is_refused(
    tmp_path: Path, extra: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    before = layout.text()
    assert add(layout, out, *with_origin(*extra)) == 2
    assert "domain" in capsys.readouterr().err
    assert layout.text() == before and not out.exists()


def test_with_several_domains_the_relay_must_be_told_which_it_serves(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    layout.config.write_text(
        layout.text() + '\n[entries.alpha]\ndomain = "alpha.example.net"\nport = 8090\n',
        encoding="utf-8",
    )
    assert add(layout, out, *with_origin()) == 2
    assert "--domain" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["", "a.b", "a b", "x" * 33, "../x"])
def test_a_relay_name_that_could_not_be_a_key_id_is_refused(
    tmp_path: Path, name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    before = layout.text()
    assert add(layout, out, *with_origin(), name=name) == 2
    assert capsys.readouterr().err
    assert layout.text() == before and not out.exists()


def test_a_name_in_use_or_files_that_exist_are_never_overwritten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    assert add(layout, out, *with_origin()) == 0
    key = (out / "relay-r1.key").read_bytes()
    after_first = layout.text()
    assert add(layout, out, *with_origin()) == 2  # same name
    assert (out / "relay-r1.key").read_bytes() == key and layout.text() == after_first
    secret(out / "relay-r2.key", b"someone else's file")
    assert add(layout, out, *with_origin(), name="r2") == 2  # the file is there already
    assert (out / "relay-r2.key").read_bytes() == b"someone else's file"
    assert layout.text() == after_first
    assert "already" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flags",
    [
        ["--origin-url", "ftp://x"],
        ["--origin-url", "https://203.0.113.10:8443", "--pin-sha256", "xyz"],
        ["--pin-sha256", "xyz"],
    ],
)
def test_a_bad_address_or_fingerprint_is_refused_before_anything_is_written(
    tmp_path: Path, flags: list[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    before = layout.text()
    assert add(layout, out, *flags) == 2
    assert layout.text() == before and not (tmp_path / "keys" / "relay-r1.public.pem").exists()


# --- listing and revoking ------------------------------------------------------------------------


def test_the_list_names_each_relay_and_says_whether_they_are_required(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin(), name="r1")
    add(layout, out, *with_origin(), name="r2")
    capsys.readouterr()
    assert cli.main(["relays", "list", "--config", str(layout.config)]) == 0
    shown = capsys.readouterr().out
    assert "r1" in shown and "r2" in shown and "not required" in shown


def test_the_list_says_when_there_are_no_relays(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["relays", "list", "--config", str(Layout(tmp_path).config)]) == 0
    assert "no relays" in capsys.readouterr().out


def test_revoking_one_relay_leaves_the_others_and_the_rest_of_the_file(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    for name in ("r1", "r2", "r3"):
        add(layout, out, *with_origin(), name=name)
    before = layout.text()
    assert cli.main(["relays", "revoke", "--config", str(layout.config), "--name", "r2"]) == 0
    ring = load_config(layout.config).settings.relay_keys
    assert ring is not None and ring.ids() == ["r1", "r3"]
    after = layout.text()
    assert after.startswith(before.split("[[relays.keys]]")[0].rstrip())
    assert "relay-r2" not in after and "relay-r1" in after and "relay-r3" in after


def test_revoking_says_what_the_operator_must_still_do(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin(), name="r1")
    add(layout, out, *with_origin(), name="r2")
    capsys.readouterr()
    cli.main(["relays", "revoke", "--config", str(layout.config), "--name", "r1"])
    shown = capsys.readouterr().out.lower()
    assert "restart" in shown and "relay-r1.public.pem" in shown


def test_revoking_a_relay_that_is_not_there_changes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    before = layout.text()
    assert cli.main(["relays", "revoke", "--config", str(layout.config), "--name", "nope"]) == 2
    assert "nope" in capsys.readouterr().err and layout.text() == before


def test_the_last_relay_cannot_be_revoked_while_relays_are_required(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    layout.config.write_text(layout.text() + "\n[cover]\nenabled = true\n", encoding="utf-8")
    add(layout, out, *with_origin())
    layout.config.write_text(
        layout.text().replace("require = false", "require = true"), encoding="utf-8"
    )
    before = layout.text()
    assert cli.main(["relays", "revoke", "--config", str(layout.config), "--name", "r1"]) == 2
    assert "required" in capsys.readouterr().err and layout.text() == before


def test_the_last_relay_can_be_revoked_when_they_are_not_required_and_that_ends_relay_mode(
    tmp_path: Path,
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    assert cli.main(["relays", "revoke", "--config", str(layout.config), "--name", "r1"]) == 0
    assert tables(layout, "relays") == 0 and tables(layout, "[relays.keys]") == 0
    assert load_config(layout.config).settings.relay_keys is None


# --- running and checking a relay ----------------------------------------------------------------


def relay_file(tmp_path: Path, port: int, key: object, *, key_id: str = "r1") -> Path:
    secret(tmp_path / "k.key", pem_private(key))  # type: ignore[arg-type]
    file = tmp_path / "relay.toml"
    file.write_text(
        f'[relay]\ndomains = ["gw.example"]\n[origin]\nurl = "http://127.0.0.1:{port}"\n'
        f'[sign]\nkey_id = "{key_id}"\nkey_file = "k.key"\n',
        encoding="utf-8",
    )
    return file


def test_check_config_describes_the_relay_without_any_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from onionglass.tickets import generate_key  # noqa: PLC0415

    file = relay_file(tmp_path, 8080, generate_key())
    assert cli.main(["relay", "run", "--config", str(file), "--check-config"]) == 0
    shown = capsys.readouterr().out
    assert "gw.example" in shown and "127.0.0.1:8081" in shown and "r1" in shown
    assert "PRIVATE" not in shown


def test_a_relay_file_with_a_mistake_is_refused_with_a_plain_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "relay.toml").write_text("[relay]\n", encoding="utf-8")
    for action in (["run", "--check-config"], ["check"]):
        assert cli.main(["relay", *action, "--config", str(tmp_path / "relay.toml")]) == 2
        assert "config error" in capsys.readouterr().err


def test_the_check_says_ok_when_the_gateway_knows_the_relay(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with Chain() as chain:
        file = relay_file(tmp_path, chain.port, chain.env.relay_key)
        code = asyncio.run(asyncio.to_thread(cli.main, ["relay", "check", "--config", str(file)]))
    shown = capsys.readouterr().out
    assert code == 0 and "ok" in shown and "r1" in shown


def test_the_check_says_when_the_gateway_does_not_know_the_relay(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from onionglass.tickets import generate_key  # noqa: PLC0415

    with Chain() as chain:
        file = relay_file(
            tmp_path, chain.port, generate_key()
        )  # a key the gateway has not heard of
        code = asyncio.run(asyncio.to_thread(cli.main, ["relay", "check", "--config", str(file)]))
    shown = capsys.readouterr().out
    assert code == 1 and "FAIL" in shown and "does not know" in shown


def test_the_check_says_when_the_gateway_cannot_be_reached(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from onionglass.tickets import generate_key  # noqa: PLC0415

    file = relay_file(tmp_path, 1, generate_key())
    assert cli.main(["relay", "check", "--config", str(file)]) == 1
    shown = capsys.readouterr().out
    assert "FAIL" in shown and "reach" in shown


def test_the_relay_is_started_with_logging_and_forwarded_headers_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from onionglass.relay import Relay  # noqa: PLC0415
    from onionglass.tickets import generate_key  # noqa: PLC0415

    started: dict[str, object] = {}
    monkeypatch.setattr(
        "onionglass.relaycli.uvicorn.run", lambda app, **kwargs: started.update(kwargs, app=app)
    )
    file = relay_file(tmp_path, 8080, generate_key())
    assert cli.main(["relay", "run", "--config", str(file)]) == 0
    assert isinstance(started["app"], Relay)
    assert (started["host"], started["port"]) == ("127.0.0.1", 8081)
    assert started["access_log"] is False and started["proxy_headers"] is False
    assert started["server_header"] is False
    assert started["ssl_certfile"] is None and started["ssl_keyfile"] is None
    assert started["limit_concurrency"] == 400  # twice what the relay will serve
    assert started["timeout_keep_alive"] == 5


def test_a_relay_that_ends_tls_hands_the_certificate_to_the_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from onionglass.tickets import generate_key  # noqa: PLC0415

    started: dict[str, object] = {}
    monkeypatch.setattr(
        "onionglass.relaycli.uvicorn.run", lambda app, **kwargs: started.update(kwargs, app=app)
    )
    file = relay_file(tmp_path, 8080, generate_key())
    (tmp_path / "tls.crt").write_text("x", encoding="utf-8")
    secret(tmp_path / "tls.key", b"x")
    text = file.read_text(encoding="utf-8").replace(
        "[relay]\n",
        '[relay]\nlisten = "0.0.0.0"\nport = 443\ntls_cert_file = "tls.crt"\ntls_key_file = "tls.key"\n',
    )
    file.write_text(text, encoding="utf-8")
    assert cli.main(["relay", "run", "--config", str(file)]) == 0
    assert started["ssl_certfile"] == str(tmp_path / "tls.crt")
    assert started["ssl_keyfile"] == str(tmp_path / "tls.key")
    assert (started["host"], started["port"]) == ("0.0.0.0", 443)  # noqa: S104


# --- a config file written by hand ---------------------------------------------------------------


def revoke(layout: Layout, name: str) -> int:
    return cli.main(["relays", "revoke", "--config", str(layout.config), "--name", name])


def three_relays(tmp_path: Path) -> tuple[Layout, Path]:
    layout, out = Layout(tmp_path), tmp_path / "out"
    for name in ("r1", "r2", "r3"):
        assert add(layout, out, *with_origin(), name=name) == 0
    return layout, out


def test_a_comment_after_a_table_header_does_not_hide_the_relay_from_revoke(tmp_path: Path) -> None:
    layout, _ = three_relays(tmp_path)
    layout.config.write_text(
        layout.text().replace("\n[[relays.keys]]\n", "\n[[relays.keys]]  # kept by hand\n"),
        encoding="utf-8",
    )
    assert revoke(layout, "r2") == 0
    ring = load_config(layout.config).settings.relay_keys
    assert ring is not None and ring.ids() == ["r1", "r3"]


def test_a_comment_after_the_relays_header_does_not_leave_it_behind_when_the_last_relay_goes(
    tmp_path: Path,
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    layout.config.write_text(
        layout.text().replace("\n[relays]\n", "\n[relays]   # mine\n"), encoding="utf-8"
    )
    assert revoke(layout, "r1") == 0
    assert tables(layout, "relays") == 0
    assert "[relays]" not in [line.split("#")[0].strip() for line in layout.text().splitlines()]
    assert load_config(layout.config).settings.relay_keys is None


def test_revoking_the_last_relay_says_that_relay_mode_is_over_and_what_went_with_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    capsys.readouterr()
    assert revoke(layout, "r1") == 0
    shown = capsys.readouterr().out
    assert "relay mode is off" in shown and "max_skew_seconds" in shown


def test_what_comes_after_a_relay_block_is_not_taken_with_it(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin(), name="r1")
    add(layout, out, *with_origin(), name="r2")
    layout.config.write_text(
        layout.text()
        + "\n# Keep this note: it belongs to the cover page.\n[cover]\nenabled = true\n",
        encoding="utf-8",
    )
    assert revoke(layout, "r2") == 0
    text = layout.text()
    assert "# Keep this note: it belongs to the cover page.\n[cover]" in text
    assert load_config(layout.config).settings.cover is not None


def test_line_endings_are_kept_when_a_file_uses_windows_ones(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    layout.config.write_bytes(layout.config.read_bytes().replace(b"\n", b"\r\n"))
    assert add(layout, out, *with_origin(), name="r1") == 0
    assert add(layout, out, *with_origin(), name="r2") == 0
    data = layout.config.read_bytes()
    assert data.count(b"\n") == data.count(b"\r\n"), "a bare line feed crept in"
    assert revoke(layout, "r1") == 0
    data = layout.config.read_bytes()
    assert data.count(b"\n") == data.count(b"\r\n")
    ring = load_config(layout.config).settings.relay_keys
    assert ring is not None and ring.ids() == ["r2"]


def test_keys_written_as_an_inline_list_are_listed_and_the_commands_say_what_to_do(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    (tmp_path / "keys" / "relay-r1.public.pem").write_bytes(pem_public(generate_key()))
    layout.config.write_text(
        layout.text()
        + '\n[relays]\nkeys = [{ id = "r1", public_key_file = "keys/relay-r1.public.pem" }]\n',
        encoding="utf-8",
    )
    before = layout.text()
    capsys.readouterr()
    assert cli.main(["relays", "list", "--config", str(layout.config)]) == 0
    assert "r1" in capsys.readouterr().out
    assert add(layout, out, *with_origin(), name="r2") == 2
    assert "inline" in capsys.readouterr().err and not out.exists()
    assert revoke(layout, "r1") == 2
    assert "inline" in capsys.readouterr().err
    assert layout.text() == before


def test_revoking_a_name_that_two_blocks_share_removes_both(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin(), name="r1")
    add(layout, out, *with_origin(), name="r2")
    layout.config.write_text(layout.text().replace('id = "r2"', 'id = "r1"'), encoding="utf-8")
    assert revoke(layout, "r1") == 0
    assert load_config(layout.config).settings.relay_keys is None


# --- what an operator types ends up in a file, so it must not be able to add to it ----------------


@pytest.mark.parametrize(
    "url",
    [
        'https://a"' + chr(10) + "allow_plain = true" + chr(10) + ":8443",
        "https://a" + chr(13) + chr(10) + "x.example",
        "https://a" + chr(9) + ".example",
        'https://a".example',
        "https://a" + chr(92) + ".example",
        "https://a b.example",
    ],
)
def test_an_origin_address_with_quotes_spaces_or_line_breaks_is_refused_and_nothing_is_written(
    tmp_path: Path, url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    before = layout.text()
    assert add(layout, out, "--origin-url", url, "--pin-sha256", PIN) == 2
    assert capsys.readouterr().err
    assert layout.text() == before and not out.exists()


@pytest.mark.parametrize(
    "pin",
    [
        "x" + chr(34) + chr(10) + "allow_plain = true" + chr(10) + "[limits]" + chr(10) + "#",
        "ab" * 31,
        ("ab" * 32).upper(),
        "",
    ],
)
def test_a_fingerprint_that_is_not_64_lower_case_hex_digits_is_refused_even_for_a_plain_hop(
    tmp_path: Path, pin: str
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    before = layout.text()
    assert add(layout, out, "--origin-url", "http://127.0.0.1:8081", "--pin-sha256", pin) == 2
    assert layout.text() == before and not out.exists()


def test_the_relay_file_holds_exactly_what_was_asked_and_nothing_else(tmp_path: Path) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    assert add(layout, out, *with_origin()) == 0
    data = tomllib.loads((out / "relay-r1.toml").read_text(encoding="utf-8"))
    assert set(data) == {"relay", "origin", "sign"}
    assert data["origin"] == {"url": "https://203.0.113.10:8443", "pin_sha256": PIN}


def test_the_relay_file_and_the_key_are_private_to_their_owner(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("file modes mean nothing on Windows")
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    for name in ("relay-r1.key", "relay-r1.toml"):
        assert (out / name).stat().st_mode & 0o077 == 0, name


def test_adding_a_relay_says_to_delete_the_gateways_copy_of_the_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout, out = Layout(tmp_path), tmp_path / "out"
    add(layout, out, *with_origin())
    assert "delete the copy of the key here" in capsys.readouterr().out
