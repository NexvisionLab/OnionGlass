# SPDX-License-Identifier: AGPL-3.0-only
"""The file a relay is started from: what it may say, and every mistake that is caught at start."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from onionglass.config import ConfigError
from onionglass.relayconfig import RelayConfig, load_relay_config
from onionglass.tickets import generate_key
from test_config import pem_private, secret

PIN = "ab" * 32

BASE = f"""
[relay]
domains = ["alpha.example.net"]

[origin]
url = "https://203.0.113.10:8443"
pin_sha256 = "{PIN}"

[sign]
key_id = "r1"
key_file = "relay-r1.key"
"""


def folder(tmp_path: Path) -> Path:
    secret(tmp_path / "relay-r1.key", pem_private(generate_key()))
    return tmp_path


def load(tmp_path: Path, text: str = BASE) -> RelayConfig:
    root = folder(tmp_path)
    (root / "relay.toml").write_text(text, encoding="utf-8")
    return load_relay_config(root / "relay.toml")


def changed(old: str, new: str) -> str:
    assert old in BASE, old
    return BASE.replace(old, new, 1)


def test_a_small_file_is_enough_and_the_rest_has_safe_defaults(tmp_path: Path) -> None:
    config = load(tmp_path)
    settings = config.settings
    assert settings.domains == ("alpha.example.net",)
    assert (settings.origin.host, settings.origin.port, settings.origin.tls) == (
        "203.0.113.10",
        8443,
        True,
    )
    assert settings.origin.pin_sha256 == PIN and settings.origin.allow_plain is False
    assert (config.listen, config.port) == ("127.0.0.1", 8081)
    assert config.tls_cert is None and config.tls_key is None and settings.trust_forwarded is False
    assert settings.max_concurrent == 200 and settings.max_per_client == 20


def test_every_setting_can_be_given(tmp_path: Path) -> None:
    text = BASE.replace(
        '[relay]\ndomains = ["alpha.example.net"]',
        '[relay]\ndomains = ["alpha.example.net", "beta.example.org"]\nlisten = "127.0.0.2"\nport = 9000\n'
        "trust_forwarded = true",
    ) + (
        "\n[limits]\nmax_concurrent = 50\nmax_per_client = 5\nmax_request_body = 2000\n"
        "max_response_body = 3000\n"
    )
    text = text.replace(
        f'pin_sha256 = "{PIN}"', f'pin_sha256 = "{PIN}"\nconnect_timeout = 3\nidle_timeout = 7'
    )
    config = load(tmp_path, text)
    s = config.settings
    assert s.domains == ("alpha.example.net", "beta.example.org") and config.port == 9000
    assert config.listen == "127.0.0.2" and s.trust_forwarded is True
    assert (s.max_concurrent, s.max_per_client, s.max_request_body, s.max_response_body) == (
        50,
        5,
        2000,
        3000,
    )
    assert (s.connect_timeout, s.idle_timeout) == (3, 7)


@pytest.mark.parametrize(
    ("url", "host", "port", "tls"),
    [
        ("https://gateway.example:9443", "gateway.example", 9443, True),
        ("https://203.0.113.10", "203.0.113.10", 443, True),
        ("https://[2001:db8::1]:8443", "2001:db8::1", 8443, True),
    ],
)
def test_the_origin_address_is_read_from_its_url(
    tmp_path: Path, url: str, host: str, port: int, tls: bool
) -> None:
    origin = load(tmp_path, changed("https://203.0.113.10:8443", url)).settings.origin
    assert (origin.host, origin.port, origin.tls) == (host, port, tls)


def test_a_plain_origin_is_read_on_this_machine_and_on_a_network_only_when_allowed(
    tmp_path: Path,
) -> None:
    plain = BASE.replace(
        'url = "https://203.0.113.10:8443"\npin_sha256 = ' + f'"{PIN}"',
        'url = "http://127.0.0.1:8080"',
    )
    origin = load(tmp_path, plain).settings.origin
    assert (origin.tls, origin.port, origin.pin_sha256) == (False, 8080, None)
    network = plain.replace("http://127.0.0.1:8080", "http://198.51.100.8").replace(
        'url = "http://198.51.100.8"', 'url = "http://198.51.100.8"\nallow_plain = true'
    )
    assert load(tmp_path, network).settings.origin.port == 80


def test_the_key_comes_from_the_file_and_signs_for_the_named_relay(tmp_path: Path) -> None:
    signed = load(tmp_path).settings.signer.sign("GET", "alpha.example.net", "/")
    assert signed.startswith("r1.")


def test_a_relay_can_end_tls_itself_when_given_a_certificate_and_a_key(tmp_path: Path) -> None:
    root = folder(tmp_path)
    (root / "tls.crt").write_text("x", encoding="utf-8")
    secret(root / "tls.key", b"x")
    text = BASE.replace(
        'domains = ["alpha.example.net"]',
        'domains = ["alpha.example.net"]\nlisten = "0.0.0.0"\ntls_cert_file = "tls.crt"\ntls_key_file = "tls.key"',
    )
    config = load(tmp_path, text)
    assert config.tls_cert == root / "tls.crt" and config.tls_key == root / "tls.key"


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('domains = ["alpha.example.net"]', "", "domains"),
        ('domains = ["alpha.example.net"]', "domains = []", "domains"),
        ('domains = ["alpha.example.net"]', 'domains = "alpha.example.net"', "list"),
        ('domains = ["alpha.example.net"]', "domains = [1]", "domains"),
        ('domains = ["alpha.example.net"]', 'domains = ["Alpha.Example.Net"]', "lower-case"),
        ('domains = ["alpha.example.net"]', 'domains = ["alpha.example.net"]\nport = 0', "port"),
        (
            'domains = ["alpha.example.net"]',
            'domains = ["alpha.example.net"]\nport = 70000',
            "port",
        ),
        (
            'domains = ["alpha.example.net"]',
            'domains = ["alpha.example.net"]\nlisten = "not-an-address"',
            "listen",
        ),
        (
            'domains = ["alpha.example.net"]',
            'domains = ["alpha.example.net"]\nunknown = 1',
            "unknown",
        ),
        ('url = "https://203.0.113.10:8443"', "", "url"),
        ('url = "https://203.0.113.10:8443"', 'url = "ftp://203.0.113.10"', "url"),
        ('url = "https://203.0.113.10:8443"', 'url = "https://"', "url"),
        ('url = "https://203.0.113.10:8443"', 'url = "https://203.0.113.10:8443/path"', "path"),
        ('url = "https://203.0.113.10:8443"', 'url = "https://u:p@203.0.113.10:8443"', "url"),
        ('url = "https://203.0.113.10:8443"', 'url = "https://203.0.113.10:8443?x=1"', "url"),
        ('url = "https://203.0.113.10:8443"', 'url = "http://203.0.113.10:8443"', "unencrypted"),
        (f'pin_sha256 = "{PIN}"', "", "pin_sha256"),
        (f'pin_sha256 = "{PIN}"', 'pin_sha256 = "abc"', "pin_sha256"),
        (f'pin_sha256 = "{PIN}"', f'pin_sha256 = "{PIN}"\nallow_plain = "yes"', "true or false"),
        (f'pin_sha256 = "{PIN}"', f'pin_sha256 = "{PIN}"\nidle_timeout = 0', "timeout"),
        ('key_id = "r1"', "", "key_id"),
        ('key_id = "r1"', 'key_id = "a.b"', "key id"),
        ('key_file = "relay-r1.key"', "", "key_file"),
        ('key_file = "relay-r1.key"', 'key_file = "missing.key"', "missing.key"),
        ("[sign]", "[sign]\nunknown = 1", "unknown"),
        ("[origin]", "[origin]\nunknown = 1", "unknown"),
    ],
)
def test_every_mistake_is_caught_with_a_message_that_names_it(
    tmp_path: Path, old: str, new: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=re.escape(message)):
        load(tmp_path, changed(old, new))


@pytest.mark.parametrize("section", ["[relay]", "[origin]", "[sign]"])
def test_a_missing_section_is_caught(tmp_path: Path, section: str) -> None:
    text = re.sub(rf"\n\{section[:-1]}\]\n(?:[^\[]*)", "\n", BASE, count=1)
    with pytest.raises(ConfigError):
        load(tmp_path, text)


def test_an_unknown_section_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown section"):
        load(tmp_path, BASE + "\n[surprise]\nx = 1\n")


def test_a_relay_open_to_the_internet_must_end_tls_or_sit_behind_a_proxy_on_this_machine(
    tmp_path: Path,
) -> None:
    text = BASE.replace(
        'domains = ["alpha.example.net"]', 'domains = ["alpha.example.net"]\nlisten = "0.0.0.0"'
    )
    with pytest.raises(ConfigError, match="TLS"):
        load(tmp_path, text)


def test_a_certificate_needs_its_key_and_the_other_way_round(tmp_path: Path) -> None:
    root = folder(tmp_path)
    (root / "tls.crt").write_text("x", encoding="utf-8")
    secret(root / "tls.key", b"x")
    for only in ('tls_cert_file = "tls.crt"', 'tls_key_file = "tls.key"'):
        text = BASE.replace(
            'domains = ["alpha.example.net"]', f'domains = ["alpha.example.net"]\n{only}'
        )
        with pytest.raises(ConfigError, match="certificate and"):
            load(tmp_path, text)
    text = BASE.replace(
        'domains = ["alpha.example.net"]',
        'domains = ["alpha.example.net"]\ntls_cert_file = "gone.crt"\ntls_key_file = "tls.key"',
    )
    with pytest.raises(ConfigError, match=r"gone\.crt"):
        load(tmp_path, text)


def test_a_file_that_is_missing_or_not_toml_is_caught(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_relay_config(tmp_path / "nope.toml")
    (tmp_path / "bad.toml").write_text("this is [not toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_relay_config(tmp_path / "bad.toml")


def test_the_key_must_be_a_private_ed25519_key(tmp_path: Path) -> None:
    root = folder(tmp_path)
    secret(root / "relay-r1.key", b"not a key at all")
    (root / "relay.toml").write_text(BASE, encoding="utf-8")
    with pytest.raises(ConfigError, match="PEM private key"):
        load_relay_config(root / "relay.toml")


# --- the total time, a list of fingerprints, and an address that could not be trusted -------------


def test_the_total_time_and_a_list_of_fingerprints_can_be_given(tmp_path: Path) -> None:
    other = "ef" * 32
    text = changed(f'pin_sha256 = "{PIN}"', f'pin_sha256 = ["{PIN}", "{other}"]')
    text += "\n[limits]\nmax_request_seconds = 90\n"
    settings = load(tmp_path, text).settings
    assert settings.max_request_seconds == 90
    assert settings.origin.pins == (PIN, other)


def test_the_total_time_has_a_default_and_limits(tmp_path: Path) -> None:
    assert load(tmp_path).settings.max_request_seconds == 300


@pytest.mark.parametrize("seconds", ["0", "-5", "3601", '"soon"'])
def test_a_total_time_that_could_not_work_is_refused(tmp_path: Path, seconds: str) -> None:
    with pytest.raises(ConfigError, match="max_request_seconds"):
        load(tmp_path, BASE + f"\n[limits]\nmax_request_seconds = {seconds}\n")


@pytest.mark.parametrize(
    "pins",
    ["[]", '["abc"]', f'["{PIN}", "xyz"]', "[1]", f'"{PIN.upper()}"', "5"],
)
def test_a_fingerprint_list_that_is_wrong_is_refused(tmp_path: Path, pins: str) -> None:
    with pytest.raises(ConfigError, match="pin_sha256"):
        load(tmp_path, changed(f'pin_sha256 = "{PIN}"', f"pin_sha256 = {pins}"))


@pytest.mark.parametrize(
    "url",
    [
        "https://gateway.example:0",
        "https://ho st.example",
        "https://gateway.example/x y",
        "https://a..b.example",
        "https://.example",
        "https://" + "a" * 64 + ".example",
        "https://a_b.example",
    ],
)
def test_an_origin_address_that_could_not_be_trusted_is_refused(tmp_path: Path, url: str) -> None:
    with pytest.raises(ConfigError):
        load(tmp_path, changed("https://203.0.113.10:8443", url))
