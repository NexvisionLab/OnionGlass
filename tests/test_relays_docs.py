# SPDX-License-Identifier: AGPL-3.0-only
"""The guide to entry relays: what it says is true of the code, every command in it exists, every
setting is explained, and the example files load."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from onionglass import config as team_config
from onionglass import relayconfig
from onionglass.config import load_config
from onionglass.relay import RelaySettings
from onionglass.relayconfig import load_relay_config
from onionglass.settings import Settings
from onionglass.teamcli import _parser
from onionglass.tickets import generate_key
from test_config import Layout, pem_private, pem_public, secret

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
GUIDE = DOCS / "relays.md"


def guide() -> str:
    assert GUIDE.exists(), "docs/relays.md is missing"
    return GUIDE.read_text(encoding="utf-8")


def slugs(path: Path) -> set[str]:
    titles = re.findall(r"^#{1,6} (.+)$", path.read_text(encoding="utf-8"), re.MULTILINE)
    return {re.sub(r"[^a-z0-9 -]", "", t.lower()).strip().replace(" ", "-") for t in titles}


# --- what the guide says first, and what it will not claim ---------------------------------------


def test_the_first_things_the_guide_says_are_what_a_relay_can_read_and_who_may_run_one() -> None:
    opening = guide().split("## How a request travels", 1)[0].lower().replace("*", "")
    assert "reads every page" in opening
    assert "servers that you run" in opening
    assert "volunteers" in opening
    assert "stolen relay" in opening


def test_the_guide_says_what_has_not_been_tried() -> None:
    lowered = guide().lower()
    assert "never been run on a real" in lowered or "has not been run on a real" in lowered
    assert lowered.count("not tried here") >= 2  # the proxy block and the service unit


def test_the_guide_never_claims_to_beat_the_censor() -> None:
    lowered = guide().lower()
    for claim in ("cannot be blocked", "can not be blocked", "guarantee", "uncensorable"):
        assert claim not in lowered
    assert "unblockable" not in lowered.replace("nothing is unblockable", "")
    assert "can still be blocked" in lowered or "blocking an address costs" in lowered


def test_the_guide_says_the_relay_does_not_help_when_the_domain_is_blocked() -> None:
    assert "does not stop the domain being blocked" in guide().lower()


def test_the_guide_is_plain_ascii() -> None:
    assert guide().isascii()


# --- links and commands --------------------------------------------------------------------------


def test_every_link_to_another_page_or_heading_goes_somewhere() -> None:
    for target in re.findall(r"\]\(((?!https?:)[^)\s]+)\)", guide()):
        name, _, anchor = target.partition("#")
        path = DOCS / name if name else GUIDE
        assert path.exists(), target
        if anchor:
            assert anchor in slugs(path), target


def test_the_other_guides_and_the_readme_point_to_it() -> None:
    for page in ("censorship.md", "running.md", "deploying.md"):
        assert "relays.md" in (DOCS / page).read_text(encoding="utf-8"), page
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/relays.md" in readme
    for module in ("relay", "relayauth", "relayconfig", "relaycli"):
        assert f"`{module}`" in readme, module


def commands_in(text: str) -> list[list[str]]:
    """Every ``onionglass relay`` or ``onionglass relays`` command in the text, as arguments."""
    joined = re.sub(r"\\\n\s*", " ", text)
    found = []
    for raw in joined.splitlines():
        line = raw.strip()
        if re.match(r"onionglass relays? ", line):
            cleaned = re.sub(r"<[^>]*>", "x", line)
            tokens = shlex.split(cleaned, comments=True)
            found.append(["x" if token == "..." else token for token in tokens[1:]])
    return found


@pytest.mark.parametrize("page", [GUIDE, DOCS / "running.md"])
def test_every_relay_command_in_the_guides_is_a_real_command(page: Path) -> None:
    found = commands_in(page.read_text(encoding="utf-8"))
    assert found, page.name
    parser = _parser()
    for arguments in found:
        parser.parse_args(arguments)


def test_the_guide_shows_every_relay_command() -> None:
    shown = {
        (c[0], c[1])
        for c in commands_in(guide() + (DOCS / "running.md").read_text(encoding="utf-8"))
    }
    assert shown >= {
        ("relays", "add"),
        ("relays", "list"),
        ("relays", "revoke"),
        ("relay", "run"),
        ("relay", "check"),
    }


# --- every setting is explained, and the numbers are the code's ----------------------------------


@pytest.mark.parametrize(
    ("section", "names"),
    [
        ("relay", relayconfig.RELAY_SETTINGS),
        ("origin", relayconfig.ORIGIN_SETTINGS),
        ("sign", relayconfig.SIGN_SETTINGS),
        ("limits", relayconfig.LIMIT_SETTINGS),
        ("relays", team_config.RELAYS_SETTINGS - {"keys"}),
    ],
)
def test_every_setting_the_loaders_accept_is_in_the_guide(
    section: str, names: frozenset[str]
) -> None:
    text = guide()
    for name in sorted(names):
        assert re.search(rf"`(?:\[+[a-z.]+\]+\.)?{name}`", text), f"[{section}] {name}"


def test_the_guide_names_the_keys_list_of_the_gateway_file() -> None:
    assert "[[relays.keys]]" in guide()


def test_the_defaults_in_the_guide_are_the_defaults_in_the_code() -> None:
    defaults = {f.name: f.default for f in RelaySettings.__dataclass_fields__.values()}
    text = guide()
    assert f"Defaults {defaults['max_concurrent']} and {defaults['max_per_client']}" in text
    assert (
        f"Defaults {defaults['max_request_body']:,} and {defaults['max_response_body']:,}" in text
    )
    assert f"Defaults {defaults['connect_timeout']:g} and {defaults['idle_timeout']:g}" in text
    assert f"Default `127.0.0.1` and {relayconfig.DEFAULT_PORT}" in text


def test_the_gateway_defaults_in_the_guide_are_the_defaults_in_the_code(tmp_path: Path) -> None:
    from onionglass.relayauth import DEFAULT_SKEW_SECONDS  # noqa: PLC0415

    assert f"default {DEFAULT_SKEW_SECONDS}" in guide()
    assert "5 to 600" in guide()  # the range the settings accept


# --- the example files ---------------------------------------------------------------------------


def test_the_example_relay_file_loads_once_its_key_is_there(tmp_path: Path) -> None:
    secret(tmp_path / "relay-r1.key", pem_private(generate_key()))
    (tmp_path / "relay.toml").write_bytes((DOCS / "examples" / "relay.toml").read_bytes())
    config = load_relay_config(tmp_path / "relay.toml")
    assert config.settings.domains == ("gateway.example.org",)
    assert config.settings.signer.key_id == "r1"


def test_the_example_relay_file_says_its_fingerprint_is_a_placeholder() -> None:
    text = (DOCS / "examples" / "relay.toml").read_text(encoding="utf-8")
    assert "placeholder" in text and (DOCS / "examples" / "relay.toml").read_bytes().isascii()


def test_the_relays_in_the_example_gateway_file_work_when_switched_on(tmp_path: Path) -> None:
    layout = Layout(tmp_path)
    text = layout.text()
    start = text.index("# Entry relays")
    block = re.sub(r"^# (\[+[a-z.]+\]+|[a-z_]+ = .*)$", r"\1", text[start:], flags=re.MULTILINE)
    assert "[relays]" in block and "[[relays.keys]]" in block
    (tmp_path / "keys" / "relay-r1.public.pem").write_bytes(pem_public(generate_key()))
    layout.config.write_text(text[:start] + block + "\n[cover]\nenabled = true\n", encoding="utf-8")
    settings = load_config(layout.config).settings
    assert settings.relay_keys is not None and settings.relay_keys.ids() == ["r1"]
    assert settings.relay_required is False


def test_the_example_gateway_file_leaves_relays_off() -> None:
    assert load_config_without_relays().relay_keys is None


def load_config_without_relays() -> Settings:
    import tempfile  # noqa: PLC0415

    with tempfile.TemporaryDirectory() as folder:
        return load_config(Layout(Path(folder)).config).settings


def test_the_total_time_default_in_the_guide_is_the_codes() -> None:
    defaults = {f.name: f.default for f in RelaySettings.__dataclass_fields__.values()}
    assert f"Default {defaults['max_request_seconds']:g}." in guide()


def test_the_guide_tells_the_operator_to_delete_the_gateways_copy_of_the_key_as_the_command_does() -> (
    None
):
    assert "delete the copy on the gateway server" in guide()


def test_the_guide_explains_renewing_the_certificate_with_a_list_of_fingerprints() -> None:
    text = guide()
    assert "without a gap" in text and "list" in text and "any one" in text
