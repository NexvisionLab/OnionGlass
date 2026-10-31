# SPDX-License-Identifier: AGPL-3.0-only
"""The team configuration file and the commands that use it (milestone 2, slice 8).

The example file shipped in ``docs/examples`` is loaded exactly as written, so it cannot go stale.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import tomllib
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass import cli, teamcli
from onionglass.audit import JsonLinesAudit
from onionglass.config import (
    ConfigError,
    load_config,
    load_private_key,
    mode_too_open,
    parse_config,
)
from onionglass.gateway import Gateway
from onionglass.hooks import HttpAudit, HttpPolicy, HttpQuota
from onionglass.killswitch import KillSwitch
from onionglass.policy import StaticPolicy
from onionglass.quota import LocalQuota
from onionglass.tickets import TicketIssuer, generate_key
from test_gateway import FakeFetcher, reply

EXAMPLE = Path(__file__).resolve().parent.parent / "docs" / "examples" / "team.toml"
KEY_ID = "signin-2026-10"
# Made fresh for every run, so no value that looks like a credential is ever written down here.
SALT = secrets.token_urlsafe(32)
TOKEN = secrets.token_urlsafe(24)


def pem_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def pem_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)


class Layout:
    """Everything the example file refers to, in the places it expects."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.signer = generate_key()
        for folder in ("keys", "lists", "state", "secrets"):
            (root / folder).mkdir()
        (root / "keys" / f"{KEY_ID}.public.pem").write_bytes(pem_public(self.signer))
        (root / "lists" / "blocked.txt").write_text(f"{TOR_PROJECT}\n", encoding="utf-8")
        (root / "lists" / "rated.txt").write_text(f"{DUCKDUCKGO}\n", encoding="utf-8")
        (root / "lists" / "names.txt").write_text("grape\n", encoding="utf-8")
        (root / "lists" / "known-sites.txt").write_text(
            f"{TOR_PROJECT} The Tor Project\n", encoding="utf-8"
        )
        secret(root / "secrets" / "audit.salt", SALT.encode())
        secret(root / "secrets" / "metrics.token", TOKEN.encode())
        shutil.copy(EXAMPLE, root / "team.toml")

    @property
    def config(self) -> Path:
        return self.root / "team.toml"

    def edit(self, old: str, new: str) -> Path:
        text = self.config.read_text(encoding="utf-8")
        assert old in text, old
        self.config.write_text(text.replace(old, new, 1), encoding="utf-8")
        return self.config

    def text(self) -> str:
        return self.config.read_text(encoding="utf-8")

    def issuer(self) -> TicketIssuer:
        return TicketIssuer(self.signer, KEY_ID, "onionglass")


@pytest.fixture
def layout(tmp_path: Path) -> Layout:
    return Layout(tmp_path)


def enter(client: TestClient, token: str) -> Any:
    """Sign in through a link the way a visitor does: look at the page, then press the button."""
    page = client.get("/enter", params={"t": token})
    assert page.status_code == 200 and "set-cookie" not in page.headers
    origin = str(client.base_url).rstrip("/")
    return client.post(
        "/enter", data={"t": token}, headers={"origin": origin, "sec-fetch-site": "same-origin"}
    )


def loads(text: str, base: Path) -> Any:
    return parse_config(tomllib.loads(text), base)


def without_sections(text: str, *names: str) -> str:
    """The config with whole sections taken out."""
    pattern = r"^\[(" + "|".join(names) + r")\]\n(?:[^\[\n].*\n|\n)*"
    return re.sub(pattern, "", text, flags=re.MULTILINE)


# --- the example file ----------------------------------------------------------------------------


def test_the_example_file_loads_as_written_and_says_what_it_means(layout: Layout) -> None:
    config = load_config(layout.config)
    s = config.settings
    assert (s.base_domain, s.scheme, s.port) == ("gateway.example.org", "https", None)
    assert s.audience == "onionglass"
    assert (config.listen, config.port) == ("127.0.0.1", 8080)
    assert config.tor.socks_ports == (9050, 9052) and config.tor.socks_host == "127.0.0.1"
    assert s.keys is not None and s.keys.ids() == [KEY_ID]
    assert s.session_ttl == 8 * 3600 and s.max_concurrent_fetches == 32 and s.hook_timeout == 2.0
    assert s.profile.name == "standard" and not s.profile.allow_images
    assert set(s.profiles) == {"restricted", "analyst"}
    restricted = s.profiles["restricted"]
    assert not restricted.allow_post_forms and restricted.daily_quota == 20
    assert restricted.max_requests_per_minute == 60 and restricted.name == "restricted"
    analyst = s.profiles["analyst"]
    assert analyst.allow_images and analyst.max_requests_per_minute == 300
    assert isinstance(s.policy, StaticPolicy) and isinstance(s.audit, JsonLinesAudit)
    assert isinstance(s.quota, LocalQuota) and isinstance(s.kill, KillSwitch)
    assert s.held and s.name_gate and s.reports and s.metrics_token == TOKEN
    assert not s.open_mode


def test_a_typo_in_any_section_of_the_example_is_refused(layout: Layout) -> None:
    text = layout.text()
    for header in ("[server]", "[tor]", "[limits]", "[profile]", "[audit]", "[reports]"):
        layout.config.write_text(
            text.replace(header, header + "\ntypo_setting = 1", 1), encoding="utf-8"
        )
        with pytest.raises(ConfigError, match="typo_setting"):
            load_config(layout.config)


def test_the_gateway_built_from_the_example_signs_people_in_and_enforces_it(
    layout: Layout,
) -> None:
    config = load_config(layout.config)
    fetcher = FakeFetcher(lambda _r: reply("<p>hello</p>"))
    gateway = Gateway(config.settings, fetcher=fetcher)
    client = TestClient(gateway.app, base_url="https://gateway.example.org", follow_redirects=False)
    assert client.post("/open", data={"address": f"{DUCKDUCKGO}.onion"}).status_code == 403
    ghost = layout.issuer().issue(subject="a", group="g", profile="ghost")
    assert client.get("/enter", params={"t": ghost}).status_code == 403  # no such profile
    ticket = layout.issuer().issue(subject="alice", group="team", profile="restricted")
    assert enter(client, ticket).status_code == 303
    same = {"origin": "https://gateway.example.org"}
    blocked = client.post("/open", data={"address": f"{TOR_PROJECT}.onion"}, headers=same)
    assert blocked.status_code == 403
    allowed = client.post("/open", data={"address": f"{DUCKDUCKGO}.onion"}, headers=same)
    assert allowed.status_code == 303
    log = (layout.root / "state" / "audit.log").read_text(encoding="utf-8")
    assert "alice" in log and "blocklist" in log and "hello" not in log
    metrics = client.get("/_og/metrics", headers={"authorization": f"Bearer {TOKEN}"})
    assert metrics.status_code == 200 and "onionglass_up 1" in metrics.text


def test_the_example_with_hooks_uncommented_builds_signed_http_hooks(layout: Layout) -> None:
    secret(layout.root / "secrets" / "gateway.private.pem", pem_private(generate_key()))
    (layout.root / "keys" / "service-2026-10.public.pem").write_bytes(pem_public(generate_key()))
    whole = layout.text()
    start = whole.index("# [hooks]")  # other commented sections, such as [translate], stay off
    text = whole[:start] + re.sub(
        r"^# (\[hooks\]|url|key_id|signing_key_file|response_keys|use|cache_seconds)",
        r"\1",
        whole[start:],
        flags=re.MULTILINE,
    )
    layout.config.write_text(without_sections(text, "policy", "audit", "quota"), encoding="utf-8")
    s = load_config(layout.config).settings
    assert isinstance(s.policy, HttpPolicy) and isinstance(s.audit, HttpAudit)
    assert isinstance(s.quota, HttpQuota)


# --- strictness ----------------------------------------------------------------------------------

KEYS_BLOCK = (
    'keys = [\n  { id = "signin-2026-10", public_key_file = "keys/signin-2026-10.public.pem" },\n]'
)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('domain = "gateway.example.org"', "", "domain is required"),
        ('scheme = "https"', 'scheme = "ftp"', "scheme"),
        ("port = 8080", 'port = "8080"', "port must be a whole number"),
        ("port = 8080", "port = 70000", "between 1 and 65535"),
        ("ports = [9050, 9052]", "ports = [0]", r"\[tor\]"),
        ("ports = [9050, 9052]", 'ports = ["a"]', r"\[tor\]"),
        ("session_hours = 8", 'session_hours = "8"', "session_hours"),
        ("allow_images = false", 'allow_images = "no"', "allow_images must be a true or false"),
        ("max_page_bytes = 5000000", "max_page_bytes = 5.5", "whole number"),
        ('preset = "restricted"', 'preset = "everything"', "preset"),
        ('address_form = "origin"', 'address_form = "everything"', "address_form"),
        ('file = "state/kill"', "file = 7", "must be a string"),
        (KEYS_BLOCK, "keys = []", "at least one key"),
        ("hold_after = 3", "hold_after = 0", "at least 1"),
        ("daily_quota = 20", "daily_quota = 0", "at least 1"),
        ("port = 8080", "port = true", "port must be a whole number"),
        ("hook_timeout = 2.0", "hook_timeout = true", "hook_timeout must be a number"),
        ("rewrite_timeout = 15", "rewrite_timeout = false", "rewrite_timeout must be"),
        ("hook_timeout = 2.0", "hook_timeout = 0", "must be above zero"),
        ("hook_timeout = 2.0", "hook_timeout = -1", "must be above zero"),
        ('scheme = "https"', 'scheme = ""', "must not be empty"),
        ('listen = "127.0.0.1"', 'listen = ""', "must not be empty"),
        ("ports = [9050, 9052]", "ports = []", "must not be empty"),
        ('audience = "onionglass"', 'audience = ""', "must not be empty"),
        ('address_form = "origin"', 'address_form = ""', "must not be empty"),
        ('host = "127.0.0.1"\nports', 'host = ""\nports', "must not be empty"),
    ],
)
def test_wrong_settings_are_refused_with_the_place_named(
    layout: Layout, old: str, new: str, message: str
) -> None:
    layout.edit(old, new)
    with pytest.raises(ConfigError, match=message):
        load_config(layout.config)


def test_an_unknown_section_or_a_missing_required_part_is_refused(layout: Layout) -> None:
    with pytest.raises(ConfigError, match=r"unknown section \[surprise\]"):
        loads(layout.text() + "\n[surprise]\na = 1\n", layout.root)
    with pytest.raises(ConfigError, match="tickets"):
        loads(without_sections(layout.text(), "tickets"), layout.root)


def test_a_key_entry_with_a_stray_field_is_refused(layout: Layout) -> None:
    layout.edit(
        'public_key_file = "keys/signin-2026-10.public.pem" }',
        'public_key_file = "keys/signin-2026-10.public.pem", note = "x" }',
    )
    with pytest.raises(ConfigError, match="note"):
        load_config(layout.config)


def test_a_bad_toml_file_or_a_missing_file_is_an_error(layout: Layout, tmp_path: Path) -> None:
    layout.config.write_text("this = is = not toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(layout.config)
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.toml")
    layout.config.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(layout.config)


def test_relative_paths_belong_to_the_config_folder_not_to_where_it_is_started(
    layout: Layout, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert load_config(layout.config).settings.policy is not None


TOR_BLOCK = 'host = "127.0.0.1"\nports = [9050, 9052]'


def test_the_tor_pool_can_be_several_hosts(layout: Layout) -> None:
    text = layout.text().replace(
        TOR_BLOCK, 'endpoints = ["tor-a:9050", "tor-b:9050", "[::1]:9051"]'
    )
    layout.config.write_text(text, encoding="utf-8")
    pool = load_config(layout.config).tor.pool
    assert pool == (("tor-a", 9050), ("tor-b", 9050), ("::1", 9051))


@pytest.mark.parametrize(
    ("endpoints", "message"),
    [
        ("endpoints = []", "must not be empty"),
        ('endpoints = ["tor-a"]', "host:port"),
        ('endpoints = ["tor-a:0"]', "from 1 to 65535"),
        ('endpoints = ["tor-a:99999"]', "from 1 to 65535"),
        ('endpoints = ["tor-a:abc"]', "from 1 to 65535"),
        ('endpoints = [":9050"]', "from 1 to 65535"),
        ("endpoints = [9050]", "host:port"),
        ('endpoints = ["tor-a:9050"]\nports = [9050]', "not both"),
        ('endpoints = ["tor-a:9050"]\nhost = "tor-b"', "not both"),
    ],
)
def test_bad_tor_endpoints_are_refused(layout: Layout, endpoints: str, message: str) -> None:
    layout.config.write_text(layout.text().replace(TOR_BLOCK, endpoints), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_config(layout.config)


# --- keys and secrets ----------------------------------------------------------------------------


def test_a_key_file_must_be_a_pem_ed25519_public_key(layout: Layout) -> None:
    public = layout.root / "keys" / f"{KEY_ID}.public.pem"
    public.write_text("not a key", encoding="utf-8")
    with pytest.raises(ConfigError, match="not a PEM public key"):
        load_config(layout.config)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public.write_bytes(
        other.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises(ConfigError, match="not an Ed25519 key"):
        load_config(layout.config)
    public.unlink()
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(layout.config)


def test_a_private_key_must_be_unencrypted_pem_ed25519(tmp_path: Path) -> None:
    good = tmp_path / "good.pem"
    secret(good, pem_private(generate_key()))
    assert isinstance(load_private_key(good, "x"), Ed25519PrivateKey)
    bad = tmp_path / "bad.pem"
    secret(bad, b"nonsense")
    with pytest.raises(ConfigError, match="not an unencrypted PEM private key"):
        load_private_key(bad, "x")
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_kind = tmp_path / "other.pem"
    secret(
        wrong_kind,
        other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    with pytest.raises(ConfigError, match="not an Ed25519 key"):
        load_private_key(wrong_kind, "x")
    empty = tmp_path / "empty.pem"
    secret(empty, b"  \n")
    with pytest.raises(ConfigError, match="empty or too large"):
        load_private_key(empty, "x")


def test_which_file_modes_count_as_readable_by_others() -> None:
    assert not mode_too_open(0o600) and not mode_too_open(0o700) and not mode_too_open(0o400)
    for mode in (0o640, 0o644, 0o604, 0o660, 0o666, 0o610, 0o601):
        assert mode_too_open(mode), oct(mode)


def test_a_secret_file_that_others_can_read_is_refused(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows has no file modes, so the check is switched on and the mode is supplied, to prove
    # that the refusal happens wherever the system does have them.
    monkeypatch.setattr("onionglass.config._HAS_FILE_MODES", True)
    seen: list[Path] = []

    def mode_of(path: Path) -> int:
        seen.append(path)
        return 0o644

    monkeypatch.setattr("onionglass.config._mode_of", mode_of)
    with pytest.raises(ConfigError, match="chmod 600"):
        load_config(layout.config)
    assert seen  # the secret files were looked at
    monkeypatch.setattr("onionglass.config._mode_of", lambda _path: 0o600)
    assert load_config(layout.config).settings.metrics_token == TOKEN


def test_a_short_token_or_salt_is_refused(layout: Layout) -> None:
    secret(layout.root / "secrets" / "metrics.token", b"short")
    with pytest.raises(ConfigError, match="metrics token"):
        load_config(layout.config)
    secret(layout.root / "secrets" / "metrics.token", TOKEN.encode())
    secret(layout.root / "secrets" / "audit.salt", b"short")
    with pytest.raises(ConfigError, match="at least 16 bytes"):
        load_config(layout.config)


def test_files_the_gateway_writes_need_a_folder_that_exists(layout: Layout) -> None:
    shutil.rmtree(layout.root / "state")
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(layout.config)


def test_lists_that_cannot_be_read_stop_the_gateway_starting(layout: Layout) -> None:
    (layout.root / "lists" / "blocked.txt").write_text("not an address\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="line 1"):
        load_config(layout.config)
    (layout.root / "lists" / "blocked.txt").unlink()
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(layout.config)


# --- where it listens ----------------------------------------------------------------------------


def test_the_gateway_only_listens_beyond_this_machine_when_told_to(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    everywhere = "0.0.0.0"  # noqa: S104 - this is the case under test
    monkeypatch.delenv("ONIONGLASS_IN_CONTAINER", raising=False)
    layout.edit('listen = "127.0.0.1"', f'listen = "{everywhere}"')
    with pytest.raises(ConfigError, match="allow_non_loopback"):
        load_config(layout.config)
    monkeypatch.setenv("ONIONGLASS_IN_CONTAINER", "1")
    assert load_config(layout.config).listen == everywhere
    monkeypatch.delenv("ONIONGLASS_IN_CONTAINER")
    layout.edit("# allow_non_loopback = true", "allow_non_loopback = true")
    assert load_config(layout.config).listen == everywhere


@pytest.mark.parametrize(
    ("scheme", "public", "shown"),
    [
        ("https", None, None),
        ("https", 443, None),
        ("https", 8443, 8443),
        ("http", 80, None),
        ("http", 8080, 8080),
    ],
)
def test_the_port_visitors_use_is_only_kept_when_unusual(
    layout: Layout, scheme: str, public: int | None, shown: int | None
) -> None:
    layout.edit('scheme = "https"', f'scheme = "{scheme}"')
    if public is not None:
        layout.edit("# public_port = 8443", f"public_port = {public}")
    assert load_config(layout.config).settings.port == shown


# --- combinations that cannot work ---------------------------------------------------------------


def test_a_profile_with_a_quota_needs_the_quota_section(layout: Layout) -> None:
    layout.config.write_text(without_sections(layout.text(), "quota"), encoding="utf-8")
    with pytest.raises(ConfigError, match="quota meter"):
        load_config(layout.config)


def test_a_name_list_needs_a_held_list(layout: Layout) -> None:
    layout.config.write_text(without_sections(layout.text(), "held", "reports"), encoding="utf-8")
    with pytest.raises(ConfigError, match="held list"):
        load_config(layout.config)


def add_hooks(layout: Layout, *, use: str = '["policy"]', extra: str = "") -> None:
    secret(layout.root / "secrets" / "gateway.private.pem", pem_private(generate_key()))
    (layout.root / "keys" / "service.public.pem").write_bytes(pem_public(generate_key()))
    block = f"""
[hooks]
url = "https://hooks.example.org/x"
key_id = "gw1"
signing_key_file = "secrets/gateway.private.pem"
response_keys = [{{ id = "svc1", public_key_file = "keys/service.public.pem" }}]
use = {use}
{extra}
"""
    layout.config.write_text(layout.text() + block, encoding="utf-8")


def test_a_service_and_a_built_in_for_the_same_job_is_an_error(layout: Layout) -> None:
    add_hooks(layout)
    with pytest.raises(ConfigError, match="policy is configured twice"):
        load_config(layout.config)


@pytest.mark.parametrize(
    ("use", "extra", "message"),
    [
        ("[]", "", "must list some of"),
        ('["everything"]', "", "must list some of"),
        ('["audit"]', 'allow_plain_http = "yes"', "true or false"),
        ('["audit"]', "unknown_hook_setting = 1", "unknown_hook_setting"),
    ],
)
def test_hook_settings_are_checked(layout: Layout, use: str, extra: str, message: str) -> None:
    layout.config.write_text(
        without_sections(layout.text(), "policy", "audit", "quota"), encoding="utf-8"
    )
    add_hooks(layout, use=use, extra=extra)
    with pytest.raises(ConfigError, match=message):
        load_config(layout.config)


def test_a_hook_address_that_is_not_https_is_refused(layout: Layout) -> None:
    layout.config.write_text(
        without_sections(layout.text(), "policy", "audit", "quota"), encoding="utf-8"
    )
    add_hooks(layout, use='["audit"]')
    layout.edit("https://hooks.example.org/x", "http://hooks.example.org/x")
    with pytest.raises(ConfigError, match="https"):
        load_config(layout.config)


# --- the commands --------------------------------------------------------------------------------


def test_check_config_says_what_it_would_do_and_never_shows_a_secret(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["check-config", "--config", str(layout.config)]) == 0
    out = capsys.readouterr().out
    assert "serves https://gateway.example.org" in out and KEY_ID in out
    assert "profiles: standard, analyst, restricted" in out
    assert SALT not in out and TOKEN not in out and "warning" not in out


def test_check_config_warns_about_what_is_missing(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    text = without_sections(layout.text(), "policy", "audit", "kill", "held", "names", "reports")
    layout.config.write_text(text, encoding="utf-8")
    assert teamcli.run(["check-config", "--config", str(layout.config)]) == 0
    out = capsys.readouterr().out
    for fragment in ("no audit log", "no kill file", "no held list", "no policy"):
        assert fragment in out


def test_a_bad_config_stops_every_command_with_a_clear_message(
    layout: Layout, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    layout.edit("port = 8080", "port = 0")
    ran: list[Any] = []
    monkeypatch.setattr("onionglass.teamcli.uvicorn.run", lambda *_a, **k: ran.append(k))
    for command in ("serve", "check-config"):
        assert cli.main([command, "--config", str(layout.config)]) == 2
    assert "config error" in capsys.readouterr().err and ran == []


def test_serve_starts_the_gateway_the_way_a_proxy_expects(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: dict[str, Any] = {}
    monkeypatch.setattr(
        "onionglass.teamcli.uvicorn.run", lambda app, **kwargs: started.update(kwargs, app=app)
    )
    assert cli.main(["serve", "--config", str(layout.config)]) == 0
    assert (started["host"], started["port"]) == ("127.0.0.1", 8080)
    assert started["access_log"] is False and started["proxy_headers"] is False
    assert started["server_header"] is False and started["app"] is not None


def test_personal_mode_is_untouched_by_the_new_commands() -> None:
    assert cli.parse_arguments([]).port == 8080
    assert {"serve", "check-config", "keys", "ticket", "admin"} == cli.TEAM_COMMANDS


def test_the_private_key_is_created_for_its_owner_only_and_never_over_another_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open
    calls: list[tuple[str, int, int]] = []

    def spy(path: Any, flags: int, mode: int = 0o777, **kwargs: Any) -> int:
        calls.append((str(path), flags, mode))
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr("onionglass.teamcli.os.open", spy)
    assert cli.main(["keys", "generate", "--id", "k9", "--out", str(tmp_path)]) == 0
    [(_name, flags, mode)] = [c for c in calls if c[0].endswith("k9.private.pem")]
    assert mode == 0o600 and flags & os.O_EXCL and flags & os.O_CREAT


def test_keys_generate_makes_a_pair_that_works_and_never_overwrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "keys"
    assert cli.main(["keys", "generate", "--id", "gw-2026-10", "--out", str(out)]) == 0
    shown = capsys.readouterr().out
    private, public = out / "gw-2026-10.private.pem", out / "gw-2026-10.public.pem"
    assert str(private) in shown and "BEGIN" not in shown  # the key itself is never printed
    if os.name != "nt":
        assert private.stat().st_mode & 0o077 == 0
    signing = load_private_key(private, "x")
    assert pem_public(signing) == public.read_bytes()
    assert cli.main(["keys", "generate", "--id", "gw-2026-10", "--out", str(out)]) == 2
    assert private.read_bytes() == pem_private(signing)  # untouched
    assert cli.main(["keys", "generate", "--id", "bad id!", "--out", str(out)]) == 2
    assert "key id" in capsys.readouterr().err


def ticket_command(layout: Layout, *extra: str) -> list[str]:
    private = layout.root / "secrets" / "signin.private.pem"
    secret(private, pem_private(layout.signer))
    return [
        "ticket", "--key-file", str(private), "--key-id", KEY_ID, "--subject", "bob",
        "--group", "team", "--profile", "analyst", "--url", "https://gateway.example.org/",
        *extra,
    ]  # fmt: skip


def test_a_ticket_made_by_the_command_signs_a_visitor_in(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(ticket_command(layout, "--onion", DUCKDUCKGO)) == 0
    link = capsys.readouterr().out.strip()
    assert link.startswith("https://gateway.example.org/enter?t=og1.")
    gateway = Gateway(load_config(layout.config).settings, fetcher=FakeFetcher())
    client = TestClient(gateway.app, base_url="https://gateway.example.org", follow_redirects=False)
    response = enter(client, link.split("t=", 1)[1])
    assert response.status_code == 303 and "/view?l=" in response.headers["location"]
    assert DUCKDUCKGO not in response.headers["location"]


def test_the_ticket_command_refuses_bad_input(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(ticket_command(layout, "--seconds", "100000")) == 2
    assert cli.main(ticket_command(layout, "--onion", "not-an-onion")) == 2
    command = ticket_command(layout)
    command[command.index("--key-file") + 1] = str(layout.root / "missing.pem")
    assert cli.main(command) == 2
    assert capsys.readouterr().err.count("onionglass:") == 3


@pytest.mark.parametrize("form", ["full", "origin", "hash", "none"])
def test_the_form_in_which_the_audit_service_is_told_the_site_is_read(
    layout: Layout, form: str
) -> None:
    layout.config.write_text(without_sections(layout.text(), "policy", "audit"), encoding="utf-8")
    add_hooks(layout, use='["audit"]', extra=f'audit_address_form = "{form}"')
    audit = load_config(layout.config).settings.audit
    assert isinstance(audit, HttpAudit) and audit.address_form == form


def test_the_audit_service_is_told_the_origin_only_unless_the_operator_says_otherwise(
    layout: Layout,
) -> None:
    layout.config.write_text(without_sections(layout.text(), "policy", "audit"), encoding="utf-8")
    add_hooks(layout, use='["audit"]')
    audit = load_config(layout.config).settings.audit
    assert isinstance(audit, HttpAudit) and audit.address_form == "origin"


def test_an_unknown_audit_form_for_the_audit_service_is_refused(layout: Layout) -> None:
    layout.config.write_text(without_sections(layout.text(), "policy", "audit"), encoding="utf-8")
    add_hooks(layout, use='["audit"]', extra='audit_address_form = "all"')
    with pytest.raises(ConfigError, match="audit_address_form"):
        load_config(layout.config)


def test_a_short_salt_for_the_audit_service_is_refused(layout: Layout) -> None:
    layout.config.write_text(without_sections(layout.text(), "policy", "audit"), encoding="utf-8")
    secret(layout.root / "secrets" / "audit.salt", b"short")
    add_hooks(
        layout,
        use='["audit"]',
        extra='audit_address_form = "hash"\naudit_salt_file = "secrets/audit.salt"',
    )
    with pytest.raises(ConfigError, match="audit_salt_file"):
        load_config(layout.config)
