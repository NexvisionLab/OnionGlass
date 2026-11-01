# SPDX-License-Identifier: AGPL-3.0-only
"""The censorship guidance: the pages say true things, link to real places, and the examples in the
config file work when switched on."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from onionglass import pages
from onionglass.config import load_config
from onionglass.teamcli import _parser
from test_config import Layout

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
CENSORSHIP = (DOCS / "censorship.md").read_text(encoding="utf-8")


def headings(path: Path) -> set[str]:
    found = set()
    for title in re.findall(r"^#{1,6} (.+)$", path.read_text(encoding="utf-8"), re.MULTILINE):
        found.add(re.sub(r"[^a-z0-9 -]", "", title.lower()).strip().replace(" ", "-"))
    return found


def test_every_link_to_another_page_or_heading_goes_somewhere() -> None:
    for target in re.findall(r"\]\(((?!https?:)[^)\s]+)\)", CENSORSHIP):
        page, _, anchor = target.partition("#")
        path = DOCS / page if page else DOCS / "censorship.md"
        assert path.exists(), target
        if anchor:
            assert anchor in headings(path), target


def test_the_first_thing_the_page_says_is_that_nothing_is_unblockable() -> None:
    summary = CENSORSHIP.split("## The short version", 1)[1][:900].lower()
    assert "nothing is unblockable" in summary
    assert "operator sees everything" in summary and "tor browser" in summary


def test_the_page_never_claims_to_beat_the_censor() -> None:
    lowered = CENSORSHIP.lower()
    for claim in ("cannot be blocked", "can not be blocked", "guarantee", "uncensorable"):
        assert claim not in lowered


def test_the_commands_the_page_and_the_guides_name_exist() -> None:
    parser = _parser()
    text = CENSORSHIP + (DOCS / "running.md").read_text(encoding="utf-8")
    for sub in sorted(set(re.findall(r"onionglass domains (\w+)", text))):
        parsed = parser.parse_args(
            ["domains", sub, "--config", "x.toml", *(["--name", "n"] if sub == "retire" else [])]
            if sub != "add"
            else ["domains", "add", "--config", "x", "--name", "n", "--domain", "d.example.net"]
        )
        assert parsed.action == sub
    assert parser.parse_args(["serve", "--config", "x", "--entry", "alpha"]).entry == "alpha"


def test_the_readme_and_the_deploy_guide_point_to_the_page() -> None:
    assert "docs/censorship.md" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "censorship.md" in (DOCS / "deploying.md").read_text(encoding="utf-8")


def test_the_deploy_guide_says_what_encrypted_client_hello_needs_and_what_is_untested() -> None:
    text = (DOCS / "deploying.md").read_text(encoding="utf-8")
    ech = text.split("**Encrypted Client Hello**", 1)[1].split("\n", 1)[0]
    assert "2.10" in ech and "DNS" in ech  # the version that has it, and the plugin it needs
    assert "not tried" in ech  # it has not been run here, and the guide says so
    assert "have not checked" not in text  # the open question is answered
    assert "Encrypted client hello is planned" not in text


def test_the_bundle_builds_caddy_with_a_dns_plugin_so_that_ech_can_work() -> None:
    dockerfile = (ROOT / "deploy" / "team" / "proxy" / "Dockerfile").read_text(encoding="utf-8")
    assert "xcaddy build --with github.com/caddy-dns/" in dockerfile
    assert "FROM caddy:2" in dockerfile  # a 2.x tag, so it follows to 2.10 and later


def test_the_entry_page_warns_that_the_operator_sees_everything() -> None:
    text = pages.landing_page(can_open=False).decode("utf-8")
    assert "can see every address you open" in text and "Tor Browser" in text


def test_the_examples_in_the_config_file_work_when_switched_on(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    start, end = text.index("# Where the internet is censored"), text.index("# Or serve the policy")
    block = re.sub(r"^# (\[[a-z.]+\]|[a-z_]+ = .*)$", r"\1", text[start:end], flags=re.MULTILINE)
    assert "[cover]" in block and "[entries.alpha]" in block
    layout.config.write_text(text[:start] + block + text[end:], encoding="utf-8")
    (layout.root / "lists" / "cover.html").write_text("<p>Hello</p>", encoding="utf-8")
    (layout.root / "state" / "alpha").mkdir()
    assert load_config(layout.config).settings.cover is not None
    assert load_config(layout.config, entry="alpha").settings.base_domain == "a.example.net"


def test_the_compose_example_names_the_entry_and_the_command() -> None:
    compose = (ROOT / "deploy" / "team" / "compose.yaml").read_text(encoding="utf-8")
    assert "# gateway-alpha:" in compose and '"--entry", "alpha"' in compose


@pytest.mark.parametrize("name", ["cover.py", "entries.py", "reach.py"])
def test_the_new_modules_are_in_the_readme_module_map(name: str) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert name.removesuffix(".py") in readme
