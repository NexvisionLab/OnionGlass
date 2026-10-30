# SPDX-License-Identifier: AGPL-3.0-only
"""The team deployment bundle in ``deploy/team``, checked for structure.

Docker was not available when the bundle was written, so these tests cannot start it. They pin
the properties that matter: what is published, which container can reach the internet, what each
container may do, that no secret is written in a file, and that the config the bundle ships is
one the real loader accepts. Bring the bundle up on a test machine before relying on it.
"""

from __future__ import annotations

import re
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization

from onionglass.config import load_config
from onionglass.tickets import generate_key

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "deploy" / "team"
COMPOSE_TEXT = (BUNDLE / "compose.yaml").read_text(encoding="utf-8")
COMPOSE: dict[str, Any] = yaml.safe_load(COMPOSE_TEXT)
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
CADDYFILE = (BUNDLE / "proxy" / "Caddyfile").read_text(encoding="utf-8")


def networks(name: str) -> set[str]:
    return set(SERVICES[name]["networks"])


# --- the layout -----------------------------------------------------------------------------------


def test_the_bundle_has_the_four_services_and_nothing_else() -> None:
    assert set(SERVICES) == {"tor-a", "tor-b", "gateway", "proxy"}


def test_only_the_proxy_is_published_and_only_on_the_web_ports() -> None:
    for name, service in SERVICES.items():
        if name == "proxy":
            assert service["ports"] == ["80:80", "443:443"]
        else:
            assert "ports" not in service, name
    assert "network_mode" not in COMPOSE_TEXT and "host" not in {
        v for s in SERVICES.values() for v in s.get("networks", [])
    }


def test_the_gateway_cannot_reach_the_internet() -> None:
    assert networks("gateway") == {"private"}
    assert COMPOSE["networks"]["private"] == {"internal": True}
    assert "internal" not in (COMPOSE["networks"]["egress"] or {})
    assert "internal" not in (COMPOSE["networks"]["frontend"] or {})


def test_only_tor_goes_out_to_the_tor_network_and_only_the_proxy_to_the_web() -> None:
    assert networks("tor-a") == networks("tor-b") == {"private", "egress"}
    assert networks("proxy") == {"private", "frontend"}
    on_egress = {n for n in SERVICES if "egress" in networks(n)}
    on_frontend = {n for n in SERVICES if "frontend" in networks(n)}
    assert on_egress == {"tor-a", "tor-b"} and on_frontend == {"proxy"}


def test_the_two_tor_processes_keep_separate_state() -> None:
    assert SERVICES["tor-a"]["volumes"] != SERVICES["tor-b"]["volumes"]
    assert SERVICES["tor-a"]["build"] == SERVICES["tor-b"]["build"] == "../../tor"


# --- what each container may do ----------------------------------------------------------------


@pytest.mark.parametrize("name", ["tor-a", "tor-b", "gateway", "proxy"])
def test_every_container_is_locked_down(name: str) -> None:
    service = SERVICES[name]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["mem_limit"] and service["pids_limit"]
    assert service["restart"] == "unless-stopped"
    for forbidden in ("privileged", "pid", "ipc", "devices", "network_mode", "user", "sysctls"):
        assert forbidden not in service, (name, forbidden)
    assert not any("docker.sock" in str(v) for v in service.get("volumes", []))


def test_the_only_added_capability_is_binding_the_web_ports() -> None:
    added = {n: s["cap_add"] for n, s in SERVICES.items() if "cap_add" in s}
    assert added == {"proxy": ["NET_BIND_SERVICE"]}


def test_the_gateway_runs_the_config_and_can_only_write_its_state_folder() -> None:
    gateway = SERVICES["gateway"]
    assert gateway["command"] == ["serve", "--config", "/etc/onionglass/team.toml"]
    mounts = gateway["volumes"]
    assert "./config:/etc/onionglass:ro" in mounts
    writable = [m for m in mounts if not m.endswith(":ro")]
    assert writable == ["./state:/var/lib/onionglass"]


def test_no_secret_is_written_in_the_bundle() -> None:
    assert SERVICES["proxy"]["env_file"] == "./secrets/proxy.env"
    for path in BUNDLE.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert not re.search(
                r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}", text
            ), path
            assert "BEGIN" not in text or "PRIVATE" not in text, path


def test_the_files_that_hold_secrets_and_state_are_ignored_by_git() -> None:
    result = subprocess.run(
        [
            "git",
            "check-ignore",
            "deploy/team/secrets/proxy.env",
            "deploy/team/config/secrets/metrics.token",
            "deploy/team/state/audit.log",
            "deploy/team/config/keys/signin-1.private.pem",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 128:
        pytest.skip("not a git checkout")
    assert len(result.stdout.split()) == 4


# --- the settings the proxy needs ---------------------------------------------------------------


def test_the_domain_and_email_are_required_before_anything_starts() -> None:
    environment = SERVICES["proxy"]["environment"]
    assert environment["DOMAIN"].startswith("${DOMAIN:?")
    assert environment["ACME_EMAIL"].startswith("${ACME_EMAIL:?")
    env_example = (BUNDLE / "env.example").read_text(encoding="utf-8")
    assert set(re.findall(r"^([A-Z_]+)=", env_example, re.MULTILINE)) == {"DOMAIN", "ACME_EMAIL"}
    assert "example.org" in env_example


def test_the_proxy_gets_a_wildcard_certificate_and_hides_the_visitor() -> None:
    assert re.search(r"^\{\$DOMAIN\}, \*\.\{\$DOMAIN\} \{", CADDYFILE, re.MULTILINE)
    assert "dns cloudflare" in CADDYFILE and "{env.CLOUDFLARE_API_TOKEN}" in CADDYFILE
    assert "admin off" in CADDYFILE
    for stripped in ("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"):
        assert f"header_up -{stripped}" in CADDYFILE
    assert "reverse_proxy gateway:8080" in CADDYFILE
    assert "auto_https off" not in CADDYFILE
    assert not re.search(
        r"^\s*(log|encode)\b", CADDYFILE, re.MULTILINE
    )  # no request log, no compression


def test_the_proxy_image_includes_the_dns_plugin_for_the_certificate() -> None:
    dockerfile = (BUNDLE / "proxy" / "Dockerfile").read_text(encoding="utf-8")
    assert "--with github.com/caddy-dns/cloudflare" in dockerfile


# --- the shipped config is one the real loader accepts ---------------------------------------------


def lay_out(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    shutil.copytree(BUNDLE / "config", config)
    (config / "keys").mkdir()
    (config / "secrets").mkdir()
    public = (
        generate_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    (config / "keys" / "signin-1.public.pem").write_bytes(public)
    token = config / "secrets" / "metrics.token"
    token.write_text(secrets.token_urlsafe(24), encoding="utf-8")
    token.chmod(0o600)
    state = tmp_path / "state"
    state.mkdir()
    team = config / "team.toml"
    team.write_text(
        team.read_text(encoding="utf-8").replace("/var/lib/onionglass", state.as_posix()),
        encoding="utf-8",
    )
    return team


def test_the_shipped_config_loads_and_matches_the_compose_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ONIONGLASS_IN_CONTAINER", "1")  # the gateway image sets this itself
    config = load_config(lay_out(tmp_path))
    s = config.settings
    # The Tor endpoints are the compose service names, on the port the torrc opens.
    assert config.tor.pool == (("tor-a", 9050), ("tor-b", 9050))
    assert set(SERVICES) >= {host for host, _port in config.tor.pool}
    torrc = (ROOT / "tor" / "torrc").read_text(encoding="utf-8")
    assert "SocksPort 0.0.0.0:9050" in torrc and "IsolateSOCKSAuth" in torrc
    assert "ClientOnly 1" in torrc
    # Tor itself refuses anything that is not an onion address, whatever reaches its port.
    socks_line = next(line for line in torrc.splitlines() if line.startswith("SocksPort"))
    assert "OnionTrafficOnly" in socks_line
    assert (config.listen, config.port) == ("0.0.0.0", 8080)  # noqa: S104
    assert "gateway:8080" in CADDYFILE and (s.scheme, s.port) == ("https", None)
    # The metrics endpoint is answered with 404 at the proxy, before the gateway is asked.
    assert "@metrics path /_og/metrics" in CADDYFILE
    assert CADDYFILE.index("respond @metrics 404") < CADDYFILE.index("reverse_proxy")
    # The cautious profile is the default, and a stronger one exists by name.
    assert (
        s.profile.name == "free" and not s.profile.allow_images and not s.profile.allow_post_forms
    )
    assert "pro" in s.profiles and s.profiles["pro"].allow_images
    assert s.policy and s.audit and s.kill and s.held and s.reports and s.metrics_token


def test_the_config_and_the_env_template_use_the_same_placeholder_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ONIONGLASS_IN_CONTAINER", "1")
    domain = load_config(lay_out(tmp_path)).settings.base_domain
    env_example = (BUNDLE / "env.example").read_text(encoding="utf-8")
    assert f"DOMAIN={domain}" in env_example


def test_the_gateway_image_allows_listening_inside_the_container() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ONIONGLASS_IN_CONTAINER=1" in dockerfile
    assert 'ENTRYPOINT ["onionglass"]' in dockerfile  # so the compose command is a sub-command
