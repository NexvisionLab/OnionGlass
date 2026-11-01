# SPDX-License-Identifier: AGPL-3.0-only
"""The file an entry relay is started from (``docs/examples/relay.toml``).

A relay holds almost nothing: the domains it serves, where the gateway is and the fingerprint to
check it against, its own signing key, and a few limits. Every mistake is caught at start, and a
setting that is wrong never falls back to something looser.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from onionglass.config import (
    ConfigError,
    _check_secret_file,
    _get,
    _get_or,
    _positive,
    _Reader,
    load_private_key,
)
from onionglass.relay import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_MAX_REQUEST_SECONDS,
    Origin,
    RelaySettings,
    is_loopback,
)
from onionglass.relayauth import RelaySigner

SECTIONS = frozenset({"relay", "origin", "sign", "limits"})
# What each section may say. The guide lists every one of these, and a test keeps them in step.
RELAY_SETTINGS = frozenset(
    {"domains", "listen", "port", "tls_cert_file", "tls_key_file", "trust_forwarded"}
)
ORIGIN_SETTINGS = frozenset({"url", "pin_sha256", "allow_plain", "connect_timeout", "idle_timeout"})
SIGN_SETTINGS = frozenset({"key_id", "key_file"})
COUNT_LIMITS = frozenset(
    {"max_concurrent", "max_per_client", "max_request_body", "max_response_body"}
)
LIMIT_SETTINGS = COUNT_LIMITS | {"max_request_seconds"}
DEFAULT_PORT = 8081


@dataclass(frozen=True, slots=True)
class RelayConfig:
    settings: RelaySettings
    listen: str
    port: int
    tls_cert: Path | None
    tls_key: Path | None


def _required(reader: _Reader, name: str, allowed: frozenset[str]) -> dict[str, Any]:
    if name not in reader.root:
        raise ConfigError(f"[{name}] is required")
    return reader.table(name, allowed)


def _domains(table: dict[str, Any]) -> tuple[str, ...]:
    value = table.get("domains")
    if value is None:
        raise ConfigError("[relay].domains is required: the entry domains this relay serves")
    if not isinstance(value, list):
        raise ConfigError("[relay].domains must be a list of domain names")
    if not value or not all(isinstance(item, str) for item in value):
        raise ConfigError("[relay].domains must be a list with at least one domain name")
    return tuple(value)


def _listen(table: dict[str, Any]) -> tuple[str, int]:
    listen: str = _get_or(table, "listen", str, "[relay]", "127.0.0.1")
    try:
        ipaddress.ip_address(listen)
    except ValueError:
        raise ConfigError("[relay].listen must be an IP address") from None
    port: int = _get_or(table, "port", int, "[relay]", DEFAULT_PORT)
    if not 1 <= port <= 65535:
        raise ConfigError("[relay].port must be 1 to 65535")
    return listen, port


def _tls(reader: _Reader, table: dict[str, Any], listen: str) -> tuple[Path | None, Path | None]:
    cert_name = _get(table, "tls_cert_file", str, "[relay]")
    key_name = _get(table, "tls_key_file", str, "[relay]")
    if (cert_name is None) != (key_name is None):
        raise ConfigError("[relay]: a TLS certificate and key must be given together")
    if cert_name is None:
        if not is_loopback(listen):
            raise ConfigError(
                "[relay]: a relay that listens on a public address must end TLS itself, with "
                "tls_cert_file and tls_key_file, or listen on this machine behind a proxy"
            )
        return None, None
    cert, key = reader.path(cert_name), reader.path(key_name)
    if not cert.is_file():
        raise ConfigError(f"[relay].tls_cert_file: cannot read {cert.name}")
    _check_secret_file(key, "[relay].tls_key_file")
    return cert, key


def parse_origin(
    url: str | None, pin_sha256: str | list[str] | None, allow_plain: bool = False
) -> Origin:
    """The gateway's address, from a URL such as https://host:8443 and the fingerprint to check
    its certificate against. Raises ``ConfigError`` for anything that could not be trusted."""
    if not url:
        raise ConfigError(
            "[origin].url is required: where the gateway is, such as https://host:8443"
        )
    if any(ord(char) <= 32 or ord(char) >= 127 or char in "\"'\\" for char in url):
        raise ConfigError(
            "[origin].url must not contain spaces, quotes, backslashes or control characters"
        )
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ConfigError("[origin].url is not a valid address") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("[origin].url must be an http or https address with a host")
    if parts.username is not None or parts.password is not None:
        raise ConfigError("[origin].url must not carry a user name or password")
    if parts.query or parts.fragment:
        raise ConfigError("[origin].url must not carry a query or a fragment")
    if parts.path not in ("", "/"):
        raise ConfigError("[origin].url must not have a path, only a host and a port")
    secure = parts.scheme == "https"
    try:
        return Origin(
            host=parts.hostname,
            port=port if port is not None else (443 if secure else 80),
            tls=secure,
            pin_sha256=tuple(pin_sha256) if isinstance(pin_sha256, list) else pin_sha256,
            allow_plain=allow_plain,
        )
    except ValueError as exc:
        raise ConfigError(f"[origin]: {exc}") from exc


def _pins(value: Any) -> str | list[str] | None:
    """One fingerprint, or a list of them so that a certificate can be renewed without a gap."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ConfigError("[origin].pin_sha256 must be a fingerprint or a list of fingerprints")


def _origin(table: dict[str, Any]) -> Origin:
    return parse_origin(
        _get(table, "url", str, "[origin]"),
        _pins(table.get("pin_sha256")),
        _get_or(table, "allow_plain", bool, "[origin]", False),
    )


def _signer(reader: _Reader, table: dict[str, Any]) -> RelaySigner:
    key_id = _get(table, "key_id", str, "[sign]")
    key_file = _get(table, "key_file", str, "[sign]")
    if not key_id:
        raise ConfigError("[sign].key_id is required: the id this relay's public key has")
    if not key_file:
        raise ConfigError("[sign].key_file is required: this relay's private key")
    key = load_private_key(reader.path(key_file), "[sign].key_file")
    try:
        return RelaySigner(key_id, key)
    except ValueError as exc:
        raise ConfigError(f"[sign]: {exc}") from exc


def parse_relay_config(data: dict[str, Any], base: Path) -> RelayConfig:
    """Turn parsed TOML into a relay's settings. ``base`` is where relative paths start."""
    unknown = sorted(set(data) - SECTIONS)
    if unknown:
        raise ConfigError(f"unknown section [{unknown[0]}]")
    reader = _Reader(data, base)
    relay = _required(reader, "relay", RELAY_SETTINGS)
    origin_table = _required(reader, "origin", ORIGIN_SETTINGS)
    sign = _required(reader, "sign", SIGN_SETTINGS)
    limits = reader.table("limits", LIMIT_SETTINGS)
    domains = _domains(relay)
    listen, port = _listen(relay)
    tls_cert, tls_key = _tls(reader, relay, listen)
    options: dict[str, Any] = {
        key: _get(limits, key, int, "[limits]") for key in sorted(COUNT_LIMITS)
    }
    options = {key: value for key, value in options.items() if value is not None}
    options["max_request_seconds"] = _positive(
        limits, "max_request_seconds", "[limits]", DEFAULT_MAX_REQUEST_SECONDS
    )
    for key, default in (
        ("connect_timeout", DEFAULT_CONNECT_TIMEOUT),
        ("idle_timeout", DEFAULT_IDLE_TIMEOUT),
    ):
        options[key] = _positive(origin_table, key, "[origin]", default)
    options["trust_forwarded"] = _get_or(relay, "trust_forwarded", bool, "[relay]", False)
    try:
        settings = RelaySettings(
            domains=domains,
            origin=_origin(origin_table),
            signer=_signer(reader, sign),
            **options,
        )
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    return RelayConfig(settings, listen, port, tls_cert, tls_key)


def load_relay_config(path: str | Path) -> RelayConfig:
    """Read a relay's file. Raises ``ConfigError`` for anything wrong with it."""
    config_path = Path(path)
    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc.strerror}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{config_path.name} is not valid TOML: {exc}") from exc
    return parse_relay_config(data, config_path.resolve().parent)
