# SPDX-License-Identifier: AGPL-3.0-only
"""Entry domains: a separate gateway for each group of users, all described in one config file.

If a censor blocks one domain, only the group that was given it is affected. Each entry has its
own domain, port, sign-in audience and state files, so nothing is shared between groups.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from onionglass.admin import AdminPaths, paths_from_config
from onionglass.config import ConfigError, load_config
from onionglass.gateway import Gateway
from onionglass.teamcli import run
from onionglass.tickets import TicketIssuer
from test_config import KEY_ID, Layout, pem_private, secret, without_sections
from test_gateway import FakeFetcher

BLOCK = """
[entries.alpha]
domain = "a.example.net"
port = 8081

[entries.bravo]
domain = "b.example.net"
port = 8082
public_port = 8443
"""


def with_entries(layout: Layout, block: str = BLOCK, *, folders: bool = True) -> Path:
    layout.config.write_text(layout.text() + block, encoding="utf-8")
    if folders:
        for name in ("alpha", "bravo"):
            (layout.root / "state" / name).mkdir(exist_ok=True)
    return layout.config


@pytest.fixture
def layout(tmp_path: Path) -> Layout:
    return Layout(tmp_path)


# --- loading an entry ----------------------------------------------------------------------------


def test_without_entries_nothing_changes(layout: Layout) -> None:
    settings = load_config(layout.config).settings
    assert settings.base_domain == "gateway.example.org"
    with pytest.raises(ConfigError, match="no entry named"):
        load_config(layout.config, entry="alpha")


def test_the_whole_file_still_loads_as_the_main_gateway(layout: Layout) -> None:
    config = with_entries(layout)
    assert load_config(config).settings.base_domain == "gateway.example.org"


def test_an_entry_has_its_own_domain_port_and_public_port(layout: Layout) -> None:
    config = with_entries(layout)
    alpha, bravo = load_config(config, entry="alpha"), load_config(config, entry="bravo")
    assert (alpha.settings.base_domain, alpha.port) == ("a.example.net", 8081)
    assert (bravo.settings.base_domain, bravo.port) == ("b.example.net", 8082)
    assert alpha.settings.port is None and bravo.settings.port == 8443


def test_an_entry_has_its_own_sign_in_audience(layout: Layout) -> None:
    config = with_entries(layout)
    assert load_config(config, entry="alpha").settings.audience == "onionglass-alpha"
    assert load_config(config, entry="bravo").settings.audience == "onionglass-bravo"
    assert load_config(config).settings.audience == "onionglass"


def test_an_audience_can_be_chosen(layout: Layout) -> None:
    config = with_entries(
        layout, BLOCK.replace("port = 8081", 'port = 8081\naudience = "group-one"')
    )
    assert load_config(config, entry="alpha").settings.audience == "group-one"


def test_an_entry_keeps_its_state_in_a_folder_of_its_own(layout: Layout) -> None:
    config = with_entries(layout)
    root = layout.root
    alpha, bravo, main = (
        paths_from_config(config, entry="alpha"),
        paths_from_config(config, entry="bravo"),
        paths_from_config(config),
    )
    assert alpha == AdminPaths(
        root / "state" / "alpha" / "kill",
        root / "state" / "alpha" / "held.txt",
        root / "state" / "alpha" / "reports.log",
    )
    assert bravo.kill == root / "state" / "bravo" / "kill"
    assert main.kill == root / "state" / "kill"


def test_an_entry_whose_folder_is_missing_stops_the_start(layout: Layout) -> None:
    config = with_entries(layout, folders=False)
    with pytest.raises(ConfigError, match="alpha"):
        load_config(config, entry="alpha")


def test_the_lists_that_are_only_read_are_shared(layout: Layout) -> None:
    config = with_entries(layout)
    main, alpha = load_config(config).settings, load_config(config, entry="alpha").settings
    assert main.name_gate is not None and alpha.name_gate is not None
    assert main.known_sites is not None and alpha.known_sites is not None


def test_a_ticket_for_one_entry_does_not_work_on_another(layout: Layout) -> None:
    config = with_entries(layout)

    def gateway(entry: str) -> TestClient:
        settings = load_config(config, entry=entry).settings
        domain = settings.base_domain
        return TestClient(
            Gateway(settings, fetcher=FakeFetcher()).app,
            base_url=f"https://{domain}",
            follow_redirects=False,
        )

    issuer = TicketIssuer(layout.signer, KEY_ID, "onionglass-alpha")
    ticket = issuer.issue(subject="s", group="g", profile="standard")
    assert gateway("bravo").get("/enter", params={"t": ticket}).status_code == 403
    assert gateway("alpha").get("/enter", params={"t": ticket}).status_code in (200, 303)


# --- the entries must make sense ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("block", "message"),
    [
        (BLOCK + '\n[entries.alpha2]\ndomain = "a.example.net"\nport = 8083\n', "domain"),
        ('\n[entries.alpha]\ndomain = "gateway.example.org"\nport = 8081\n', "domain"),
        (BLOCK + '\n[entries.sub]\ndomain = "x.a.example.net"\nport = 8083\n', "inside"),
        (BLOCK + '\n[entries.alpha2]\ndomain = "c.example.net"\nport = 8081\n', "port"),
        ('\n[entries.alpha]\ndomain = "a.example.net"\nport = 8080\n', "port"),
        ('\n[entries.Alpha]\ndomain = "a.example.net"\nport = 8081\n', "name"),
        ('\n[entries."-a"]\ndomain = "a.example.net"\nport = 8081\n', "name"),
        ("\n[entries." + "a" * 40 + ']\ndomain = "a.example.net"\nport = 8081\n', "name"),
        ("\n[entries.alpha]\nport = 8081\n", "domain"),
        ('\n[entries.alpha]\ndomain = "a.example.net"\n', "port"),
        ('\n[entries.alpha]\ndomain = "A.Example.NET"\nport = 8081\n', "domain"),
        ('\n[entries.alpha]\ndomain = "a.example.net"\nport = 0\n', "port"),
        ('\n[entries.alpha]\ndomain = "a.example.net"\nport = "x"\n', "port"),
        (
            '\n[entries.alpha]\ndomain = "a.example.net"\nport = 8081\nlisten = "0.0.0.0"\n',
            "listen",
        ),
        ('\n[entries.alpha]\ndomain = ""\nport = 8081\n', "domain"),
        (
            BLOCK
            + '\n[entries.alpha2]\ndomain = "c.example.net"\nport = 8083\naudience = "onionglass-alpha"\n',
            "audience",
        ),
        ("\n[entries]\nalpha = 5\n", "table"),
    ],
)
def test_a_mistake_in_an_entry_stops_the_start_even_for_the_main_gateway(
    layout: Layout, block: str, message: str
) -> None:
    config = with_entries(layout, block)
    with pytest.raises(ConfigError, match=message):
        load_config(config)


# --- the commands --------------------------------------------------------------------------------


def command(*args: str) -> int:
    return run(list(args))


def test_list_shows_every_entry_and_what_it_will_use(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(layout)
    assert command("domains", "list", "--config", str(config)) == 0
    shown = capsys.readouterr().out
    for expected in ("alpha", "a.example.net", "8081", "onionglass-alpha", "bravo", "8082"):
        assert expected in shown
    assert "state/alpha" in shown.replace("\\", "/")


def test_add_writes_the_entry_makes_its_folder_and_says_what_is_next(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    before = layout.text()
    args = ("domains", "add", "--config", str(layout.config), "--name", "alpha")
    assert command(*args, "--domain", "a.example.net", "--port", "8081") == 0
    assert (layout.root / "state" / "alpha").is_dir()
    assert layout.text().startswith(before)
    assert load_config(layout.config, entry="alpha").settings.base_domain == "a.example.net"
    shown = capsys.readouterr().out
    assert "caddy" in shown and "ticket" in shown and "DNS" in shown


def test_add_chooses_the_next_free_port_when_none_is_given(layout: Layout) -> None:
    config = with_entries(layout)
    args = ("domains", "add", "--config", str(config), "--name", "charlie")
    assert command(*args, "--domain", "c.example.net") == 0
    assert load_config(config, entry="charlie").port == 8083


@pytest.mark.parametrize(
    ("name", "domain"),
    [("alpha", "z.example.net"), ("zulu", "a.example.net"), ("Bad", "z.example.net")],
)
def test_add_refuses_a_clash_and_leaves_the_file_as_it_was(
    layout: Layout, capsys: pytest.CaptureFixture[str], name: str, domain: str
) -> None:
    config = with_entries(layout)
    before = config.read_text(encoding="utf-8")
    args = ("domains", "add", "--config", str(config), "--name", name, "--domain", domain)
    assert command(*args) == 2
    assert config.read_text(encoding="utf-8") == before
    assert "onionglass:" in capsys.readouterr().err


def test_retire_stops_that_entry_and_no_other(layout: Layout) -> None:
    config = with_entries(layout)
    assert command("domains", "retire", "--config", str(config), "--name", "alpha") == 0
    assert (layout.root / "state" / "alpha" / "kill").read_text(encoding="utf-8").strip() == "all"
    assert not (layout.root / "state" / "bravo" / "kill").exists()
    assert not (layout.root / "state" / "kill").exists()


def test_retire_needs_a_kill_file_to_stop_anything(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(layout)
    config.write_text(
        without_sections(config.read_text(encoding="utf-8"), "kill"), encoding="utf-8"
    )
    assert command("domains", "retire", "--config", str(config), "--name", "alpha") == 2
    assert "kill" in capsys.readouterr().err


def test_retire_names_an_entry_that_exists(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(layout)
    assert command("domains", "retire", "--config", str(config), "--name", "nobody") == 2
    assert "no entry named" in capsys.readouterr().err


def test_the_proxy_text_has_a_block_for_each_domain(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(layout)
    assert command("domains", "caddy", "--config", str(config)) == 0
    shown = capsys.readouterr().out
    for domain in ("gateway.example.org", "a.example.net", "b.example.net"):
        assert f"{domain}, *.{domain} {{" in shown
    assert "reverse_proxy gateway:8080" in shown
    assert "reverse_proxy gateway-alpha:8081" in shown
    assert "reverse_proxy gateway-bravo:8082" in shown
    assert shown.count("respond @metrics 404") == 3 and shown.count("header -Server") == 3
    assert shown.count("header_up -X-Forwarded-For") == 3
    assert "CLOUDFLARE_API_TOKEN" in shown and "{env." in shown  # a placeholder, never a value


def test_a_ticket_for_an_entry_is_made_for_its_domain_and_audience(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(layout)
    key_file = layout.root / "secrets" / "signin.private.pem"
    secret(key_file, pem_private(layout.signer))
    args = (
        "ticket", "--config", str(config), "--entry", "bravo", "--key-file", str(key_file),
        "--key-id", KEY_ID, "--subject", "s", "--group", "g", "--profile", "standard",
    )  # fmt: skip
    assert command(*args) == 0
    link = capsys.readouterr().out.strip()
    assert link.startswith("https://b.example.net:8443/enter?t=")
    settings = load_config(config, entry="bravo").settings
    client = TestClient(
        Gateway(settings, fetcher=FakeFetcher()).app,
        base_url="https://b.example.net:8443",
        follow_redirects=False,
    )
    token = link.split("t=", 1)[1]
    assert client.get("/enter", params={"t": token}).status_code in (200, 303)


def test_a_ticket_needs_either_an_entry_or_an_address_and_audience(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    key_file = layout.root / "secrets" / "signin.private.pem"
    secret(key_file, pem_private(layout.signer))
    args = (
        "ticket", "--key-file", str(key_file), "--key-id", KEY_ID, "--subject", "s",
        "--group", "g", "--profile", "standard",
    )  # fmt: skip
    assert command(*args) == 2
    assert "--url" in capsys.readouterr().err


def test_check_config_says_which_entry_it_is_checking(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(layout)
    assert command("check-config", "--config", str(config), "--entry", "alpha") == 0
    shown = capsys.readouterr().out
    assert "a.example.net" in shown and "onionglass-alpha" in shown


def test_admin_commands_can_work_on_one_entry(
    layout: Layout, capsys: pytest.CaptureFixture[str]
) -> None:
    config = with_entries(layout)
    args = ("admin", "--config", str(config), "--entry", "bravo", "kill", "on", "--all")
    assert command(*args) == 0
    assert (layout.root / "state" / "bravo" / "kill").exists()
    assert not (layout.root / "state" / "alpha" / "kill").exists()
