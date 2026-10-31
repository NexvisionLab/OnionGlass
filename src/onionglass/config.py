# SPDX-License-Identifier: AGPL-3.0-only
"""Team and public mode: the whole gateway described in one TOML file.

Rules the loader enforces so a mistake cannot quietly weaken the gateway:

* A setting it does not know is an error, so a typo never means "setting ignored".
* Secrets are never written in the file. Keys, salts and tokens are paths to files, and on
  systems that have file modes, a secret file that other users can read is refused.
* Relative paths are relative to the folder the config file is in, not to where the program
  happens to be started.
* Anything that cannot be read, understood or combined is an error at start-up, never a surprise
  on the first request.

See ``docs/examples/team.toml`` for every setting with its meaning.
"""

from __future__ import annotations

import os
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from onionglass.audit import ADDRESS_FORMS, AuditSink, JsonLinesAudit
from onionglass.held import HeldList
from onionglass.hooks import HookClient, HttpAudit, HttpEntitySink, HttpPolicy, HttpQuota
from onionglass.killswitch import KillSwitch
from onionglass.lookalike import KnownSites, load_known_sites
from onionglass.namegate import load_name_gate
from onionglass.policy import PolicyConfigError, StaticPolicy, load_address_list
from onionglass.quota import LocalQuota, QuotaError
from onionglass.reports import ReportError, ReportQueue
from onionglass.settings import Profile, Settings
from onionglass.tickets import KeyRing
from onionglass.upstream import TorConfig

SECTIONS = frozenset(
    {
        "server", "tor", "tickets", "limits", "profile", "profiles", "policy", "kill", "audit",
        "held", "names", "reports", "metrics", "quota", "hooks", "abuse", "known_sites",
    }
)  # fmt: skip
PROFILE_FIELDS = frozenset(f.name for f in fields(Profile))
# The type each profile field takes from the config file. A field missing here would be accepted
# by the file check and then ignored, so a test keeps this in step with ``Profile``.
PROFILE_KINDS: dict[str, type | tuple[type, ...]] = {
    "name": str, "allow_images": bool, "allow_fonts": bool, "allow_post_forms": bool,
    "allow_uploads": bool, "allow_password_fields": bool, "max_page_bytes": int,
    "max_asset_bytes": int, "rewrite_timeout": (int, float), "max_requests_per_minute": int,
    "daily_quota": int, "open_cost": int, "page_cost": int, "show_entities": bool,
    "send_entities": bool,
}  # fmt: skip
HOOK_USES = frozenset({"policy", "audit", "quota", "entities"})
MAX_SECRET_BYTES = 16_384
# Windows has no file modes to check. Tests turn this on to prove the check works.
_HAS_FILE_MODES = os.name != "nt"


class ConfigError(Exception):
    """The configuration is wrong. The message says where, and never repeats a secret."""


@dataclass(frozen=True, slots=True)
class TeamConfig:
    settings: Settings
    tor: TorConfig
    listen: str
    port: int


class _Reader:
    """Reads one file's tables, with the folder that relative paths hang from."""

    def __init__(self, root: Mapping[str, Any], base: Path) -> None:
        self.root = root
        self.base = base

    def table(self, name: str, allowed: set[str] | frozenset[str]) -> dict[str, Any]:
        value = self.root.get(name, {})
        if not isinstance(value, dict):
            raise ConfigError(f"[{name}] must be a table")
        return self.check(value, allowed, f"[{name}]")

    @staticmethod
    def check(
        table: Mapping[str, Any], allowed: set[str] | frozenset[str], where: str
    ) -> dict[str, Any]:
        unknown = sorted(set(table) - set(allowed))
        if unknown:
            raise ConfigError(f"{where}: unknown setting {unknown[0]!r}")
        return dict(table)

    def path(self, text: str) -> Path:
        path = Path(text)
        return path if path.is_absolute() else self.base / path


def _get(table: Mapping[str, Any], key: str, kind: type | tuple[type, ...], where: str) -> Any:
    value = table.get(key)
    if value is None:
        return None
    if isinstance(value, bool) and kind is not bool:
        raise ConfigError(f"{where}.{key} must be a {_kind_name(kind)}")
    if not isinstance(value, kind):
        raise ConfigError(f"{where}.{key} must be a {_kind_name(kind)}")
    return value


def _kind_name(kind: type | tuple[type, ...]) -> str:
    if isinstance(kind, tuple):
        if set(kind) == {int, float}:
            return "number"
        return " or ".join(k.__name__ for k in kind)
    return {"str": "string", "int": "whole number", "float": "number", "bool": "true or false"}.get(
        kind.__name__, kind.__name__
    )


def _get_or(
    table: Mapping[str, Any], key: str, kind: type | tuple[type, ...], where: str, default: Any
) -> Any:
    """A setting, or ``default`` only when it is absent. A present but empty value is an error."""
    value = _get(table, key, kind, where)
    if value is None:
        return default
    if isinstance(value, str | list) and not value:
        raise ConfigError(f"{where}.{key} must not be empty")
    return value


def _positive(table: Mapping[str, Any], key: str, where: str, default: float) -> float:
    """A number above zero, or ``default`` when absent. Zero and below are errors."""
    value = _number(table, key, where)
    if value is None:
        return default
    if value <= 0:
        raise ConfigError(f"{where}.{key} must be above zero")
    return value


def _number(table: Mapping[str, Any], key: str, where: str) -> float | None:
    value = _get(table, key, (int, float), where)
    return None if value is None else float(value)


def mode_too_open(mode: int) -> bool:
    """True if anyone but the owner can read, write or run the file."""
    return bool(mode & (stat.S_IRWXG | stat.S_IRWXO))


def _mode_of(path: Path) -> int:
    return path.stat().st_mode


def _check_secret_file(path: Path, where: str) -> None:
    """Refuse a secret file that other users can read, where the system has file modes."""
    try:
        mode = _mode_of(path)
    except OSError as exc:
        raise ConfigError(f"{where}: cannot read {path.name}: {exc.strerror}") from exc
    if _HAS_FILE_MODES and mode_too_open(mode):
        raise ConfigError(f"{where}: {path.name} can be read by other users, run chmod 600 on it")


def _secret_bytes(path: Path, where: str) -> bytes:
    _check_secret_file(path, where)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"{where}: cannot read {path.name}: {exc.strerror}") from exc
    if not data.strip() or len(data) > MAX_SECRET_BYTES:
        raise ConfigError(f"{where}: {path.name} is empty or too large")
    return data


def load_private_key(path: Path, where: str) -> Ed25519PrivateKey:
    data = _secret_bytes(path, where)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"{where}: {path.name} is not an unencrypted PEM private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError(f"{where}: {path.name} is not an Ed25519 key")
    return key


def load_public_key(path: Path, where: str) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
        key = serialization.load_pem_public_key(data)
    except OSError as exc:
        raise ConfigError(f"{where}: cannot read {path.name}: {exc.strerror}") from exc
    except ValueError as exc:
        raise ConfigError(f"{where}: {path.name} is not a PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigError(f"{where}: {path.name} is not an Ed25519 key")
    return key


def _key_ring(reader: _Reader, entries: Any, where: str) -> KeyRing:
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"{where} must be a list with at least one key")
    ring = KeyRing()
    for index, entry in enumerate(entries, start=1):
        label = f"{where}[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{label} must be a table")
        reader.check(entry, {"id", "public_key_file"}, label)
        key_id = _get(entry, "id", str, label)
        file = _get(entry, "public_key_file", str, label)
        if not key_id or not file:
            raise ConfigError(f"{label} needs an id and a public_key_file")
        try:
            ring.add(key_id, load_public_key(reader.path(file), label))
        except ValueError as exc:
            raise ConfigError(f"{label}: {exc}") from exc
    return ring


def _profile(reader: _Reader, table: Mapping[str, Any], where: str, name: str | None) -> Profile:
    data = reader.check(table, PROFILE_FIELDS | {"preset"}, where)
    preset = _get(data, "preset", str, where)
    if preset not in (None, "default", "restricted"):
        raise ConfigError(f"{where}.preset must be 'default' or 'restricted'")
    profile = Profile.restricted() if preset == "restricted" else Profile()
    changes: dict[str, Any] = {}
    for key, kind in PROFILE_KINDS.items():
        value = _get(data, key, kind, where)
        if value is not None:
            changes[key] = float(value) if key == "rewrite_timeout" else value
    if name is not None:
        changes["name"] = name
    try:
        return replace(profile, **changes)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


def _salt(reader: _Reader, file: str, where: str) -> bytes:
    """The secret that keys the hashed form of an address in the audit log."""
    salt = _secret_bytes(reader.path(file), where).strip()
    if len(salt) < 16:
        raise ConfigError(f"{where} must hold at least 16 bytes")
    return salt


def _audit(reader: _Reader) -> AuditSink | None:
    table = reader.table("audit", {"file", "address_form", "salt_file"})
    if not table:
        return None
    file = _get(table, "file", str, "[audit]")
    if not file:
        raise ConfigError("[audit] needs a file")
    form = _get_or(table, "address_form", str, "[audit]", "origin")
    if form not in ADDRESS_FORMS:
        raise ConfigError(f"[audit].address_form must be one of {', '.join(ADDRESS_FORMS)}")
    salt_file = _get(table, "salt_file", str, "[audit]")
    salt = _salt(reader, salt_file, "[audit].salt_file") if salt_file else None
    return JsonLinesAudit(
        _writable_folder(reader.path(file), "[audit]"),
        address_form=form,
        salt=salt,
    )


def _hooks(reader: _Reader, timeout: float) -> tuple[HookClient | None, dict[str, Any]]:
    table = reader.table(
        "hooks",
        {
            "url", "key_id", "signing_key_file", "response_keys", "use", "cache_seconds",
            "allow_plain_http", "timeout", "audit_address_form", "audit_salt_file",
        },
    )  # fmt: skip
    if not table:
        return None, {}
    url = _get(table, "url", str, "[hooks]")
    key_id = _get(table, "key_id", str, "[hooks]")
    key_file = _get(table, "signing_key_file", str, "[hooks]")
    if not (url and key_id and key_file):
        raise ConfigError("[hooks] needs url, key_id, signing_key_file and response_keys")
    uses = _get(table, "use", list, "[hooks]") or []
    if not uses or not all(isinstance(u, str) and u in HOOK_USES for u in uses):
        raise ConfigError("[hooks].use must list some of: policy, audit, quota, entities")
    ring = _key_ring(reader, table.get("response_keys"), "[hooks].response_keys")
    try:
        client = HookClient(
            url,
            signing_key=load_private_key(reader.path(key_file), "[hooks].signing_key_file"),
            key_id=key_id,
            response_keys=ring,
            timeout=_positive(table, "timeout", "[hooks]", timeout),
            allow_plain_http=bool(_get(table, "allow_plain_http", bool, "[hooks]")),
        )
    except ValueError as exc:
        raise ConfigError(f"[hooks]: {exc}") from exc
    cache = _number(table, "cache_seconds", "[hooks]")
    if cache is not None and cache < 0:
        raise ConfigError("[hooks].cache_seconds cannot be negative")
    form = _get_or(table, "audit_address_form", str, "[hooks]", "origin")
    if form not in ADDRESS_FORMS:
        raise ConfigError(f"[hooks].audit_address_form must be one of {', '.join(ADDRESS_FORMS)}")
    salt_file = _get(table, "audit_salt_file", str, "[hooks]")
    salt = _salt(reader, salt_file, "[hooks].audit_salt_file") if salt_file else None
    return client, {"use": set(uses), "cache": cache or 0.0, "audit_form": form, "audit_salt": salt}


def _build_hook_parts(client: HookClient | None, hook: dict[str, Any]) -> dict[str, Any]:
    parts: dict[str, Any] = {}
    if client is None:
        return parts
    uses = hook["use"]
    if "policy" in uses:
        parts["policy"] = HttpPolicy(client, cache_seconds=hook["cache"])
    if "audit" in uses:
        parts["audit"] = HttpAudit(client, address_form=hook["audit_form"], salt=hook["audit_salt"])
    if "quota" in uses:
        parts["quota"] = HttpQuota(client)
    if "entities" in uses:
        parts["entity_sink"] = HttpEntitySink(
            client, address_form=hook["audit_form"], salt=hook["audit_salt"]
        )
    return parts


def _local_policy(reader: _Reader) -> StaticPolicy | None:
    table = reader.table("policy", {"blocklist", "allowlist", "rated_list"})
    if not table:
        return None
    paths = {
        key: reader.path(value)
        for key in ("blocklist", "allowlist", "rated_list")
        if (value := _get(table, key, str, "[policy]"))
    }
    return StaticPolicy(
        blocked=load_address_list(paths["blocklist"]) if "blocklist" in paths else (),
        allowed=load_address_list(paths["allowlist"]) if "allowlist" in paths else None,
        rated=load_address_list(paths["rated_list"]) if "rated_list" in paths else None,
    )


def _writable_folder(path: Path, where: str) -> Path:
    """The file the gateway writes to. Its folder must exist, or every request would be refused."""
    folder = path.parent
    if not folder.is_dir() or not os.access(folder, os.W_OK):
        raise ConfigError(f"{where}: the folder {folder} does not exist or cannot be written to")
    return path


def _single_path(
    reader: _Reader, section: str, *, writes: bool = False, extra: frozenset[str] = frozenset()
) -> Path | None:
    table = reader.table(section, {"file"} | extra)
    file = _get(table, "file", str, f"[{section}]") if table else None
    if table and not file:
        raise ConfigError(f"[{section}] needs a file")
    if not file:
        return None
    path = reader.path(file)
    return _writable_folder(path, f"[{section}]") if writes else path


def _server(reader: _Reader) -> tuple[str, str, str, int, int | None]:
    """The domain, scheme, listen address, listen port and the port visitors use, if unusual."""
    table = reader.table(
        "server", {"listen", "port", "domain", "scheme", "public_port", "allow_non_loopback"}
    )
    domain = _get(table, "domain", str, "[server]")
    if not domain:
        raise ConfigError("[server].domain is required")
    scheme = _get_or(table, "scheme", str, "[server]", "https")
    listen = _get_or(table, "listen", str, "[server]", "127.0.0.1")
    port = _get_or(table, "port", int, "[server]", 8080)
    public_port = _get(table, "public_port", int, "[server]")
    allowed_elsewhere = (
        _get(table, "allow_non_loopback", bool, "[server]")
        or os.environ.get("ONIONGLASS_IN_CONTAINER") == "1"
    )
    if listen not in ("127.0.0.1", "::1", "localhost") and not allowed_elsewhere:
        raise ConfigError(
            "[server].listen is not this machine. The gateway has no TLS of its own and must sit "
            "behind a proxy. Set allow_non_loopback = true if the proxy reaches it over a private "
            "network."
        )
    if not 1 <= port <= 65535:
        raise ConfigError("[server].port must be between 1 and 65535")
    default_port = 443 if scheme == "https" else 80
    return (
        domain,
        scheme,
        listen,
        port,
        None if public_port in (None, default_port) else public_port,
    )


def _endpoint(text: Any, where: str) -> tuple[str, int]:
    """``host:port`` or ``[ipv6]:port`` as a pair."""
    if not isinstance(text, str) or ":" not in text:
        raise ConfigError(f"{where} must be host:port")
    host, _, port_text = text.rpartition(":")
    host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if not host or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ConfigError(f"{where} must be host:port with a port from 1 to 65535")
    return host, int(port_text)


def _tor(reader: _Reader) -> TorConfig:
    table = reader.table("tor", {"host", "ports", "endpoints"})
    if "endpoints" in table:
        if "host" in table or "ports" in table:
            raise ConfigError("[tor]: use either endpoints, or host and ports, not both")
        listed = _get(table, "endpoints", list, "[tor]")
        if not listed:
            raise ConfigError("[tor].endpoints must not be empty")
        pool = tuple(_endpoint(item, f"[tor].endpoints[{i}]") for i, item in enumerate(listed, 1))
        try:
            return TorConfig(endpoints=pool)
        except ValueError as exc:
            raise ConfigError(f"[tor]: {exc}") from exc
    ports = _get_or(table, "ports", list, "[tor]", [9050])
    if not all(isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in ports):
        raise ConfigError("[tor].ports must be whole numbers between 1 and 65535")
    try:
        return TorConfig(
            socks_host=_get_or(table, "host", str, "[tor]", "127.0.0.1"),
            socks_ports=tuple(ports),
        )
    except ValueError as exc:
        raise ConfigError(f"[tor]: {exc}") from exc


def _limits(reader: _Reader) -> dict[str, Any]:
    table = reader.table(
        "limits",
        {
            "session_hours", "max_labels_per_session", "max_labels_per_page",
            "max_new_sessions_per_minute", "max_concurrent_fetches", "max_fetches_per_session",
            "max_request_body", "max_reports_per_session", "hook_timeout", "max_opens_per_session",
            "max_entity_sends_per_session",
        },
    )  # fmt: skip
    found: dict[str, Any] = {}
    for key in (
        "max_labels_per_session", "max_labels_per_page", "max_new_sessions_per_minute",
        "max_concurrent_fetches", "max_fetches_per_session", "max_request_body",
        "max_reports_per_session", "max_opens_per_session", "max_entity_sends_per_session",
    ):  # fmt: skip
        value = _get(table, key, int, "[limits]")
        if value is not None:
            found[key] = value
    hours = _number(table, "session_hours", "[limits]")
    if hours is not None:
        found["session_ttl"] = hours * 3600
    found["hook_timeout"] = _positive(table, "hook_timeout", "[limits]", 2.0)
    return found


def _profiles(reader: _Reader) -> tuple[Profile, dict[str, Profile]]:
    default = _profile(
        reader, reader.table("profile", PROFILE_FIELDS | {"preset"}), "[profile]", None
    )
    section = reader.root.get("profiles", {})
    if not isinstance(section, dict):
        raise ConfigError("[profiles] must be a table of profiles")
    named: dict[str, Profile] = {}
    for name, body in section.items():
        if not isinstance(body, dict):
            raise ConfigError(f"[profiles.{name}] must be a table")
        named[name] = _profile(reader, body, f"[profiles.{name}]", name)
    return default, named


def _services(reader: _Reader, hook_timeout: float) -> dict[str, Any]:
    """Policy, audit and quota, each built-in or served by another program, never both."""
    client, hook = _hooks(reader, hook_timeout)
    parts = _build_hook_parts(client, hook)
    local: dict[str, Any] = {
        "policy": _local_policy(reader),
        "audit": _audit(reader),
        "quota": _single_path(reader, "quota", writes=True),
    }
    for kind, value in local.items():
        if value is not None and kind in parts:
            raise ConfigError(f"{kind} is configured twice: in [hooks].use and in [{kind}]")
        if kind not in parts and value is not None:
            parts[kind] = value
    if isinstance(parts.get("quota"), Path):
        try:
            parts["quota"] = LocalQuota(parts["quota"])
        except QuotaError as exc:
            raise ConfigError(f"[quota]: {exc}") from exc
    return parts


def _abuse_contact(reader: _Reader) -> str | None:
    table = reader.table("abuse", {"contact"})
    if not table:
        return None
    contact = _get(table, "contact", str, "[abuse]")
    if not contact:
        raise ConfigError("[abuse] needs a contact")
    return str(contact)


def _known_sites(reader: _Reader) -> KnownSites | None:
    path = _single_path(reader, "known_sites")
    return load_known_sites(path) if path else None


def _safety_files(reader: _Reader) -> dict[str, Any]:
    """The kill file, held list, name gate, report queue and metrics token."""
    kill_file = _single_path(reader, "kill")
    held_file = _single_path(reader, "held", writes=True)
    names_file = _single_path(reader, "names", extra=frozenset({"hold_after"}))
    held = HeldList(held_file) if held_file else None
    found: dict[str, Any] = {
        "kill": KillSwitch(kill_file) if kill_file else None,
        "held": held,
        "name_gate": load_name_gate(names_file) if names_file else None,
        "abuse_contact": _abuse_contact(reader),
        "known_sites": _known_sites(reader),
        "name_gate_hold_after": _get_or(
            reader.table("names", {"file", "hold_after"}), "hold_after", int, "[names]", 2
        ),
        "reports": None,
        "metrics_token": None,
    }
    reports = reader.table("reports", {"file", "hold_after"})
    if reports:
        file = _get(reports, "file", str, "[reports]")
        if not file:
            raise ConfigError("[reports] needs a file")
        try:
            found["reports"] = ReportQueue(
                _writable_folder(reader.path(file), "[reports]"),
                held=held,
                hold_after=_get(reports, "hold_after", int, "[reports]"),
            )
        except (ReportError, ValueError) as exc:
            raise ConfigError(f"[reports]: {exc}") from exc
    metrics = reader.table("metrics", {"token_file"})
    if metrics:
        token_file = _get(metrics, "token_file", str, "[metrics]")
        if not token_file:
            raise ConfigError("[metrics] needs a token_file")
        raw = _secret_bytes(reader.path(token_file), "[metrics].token_file")
        found["metrics_token"] = raw.decode("utf-8", "replace").strip()
    return found


def parse_config(data: Mapping[str, Any], base: Path) -> TeamConfig:
    """Turn parsed TOML into settings. ``base`` is the folder relative paths hang from."""
    unknown = sorted(set(data) - SECTIONS)
    if unknown:
        raise ConfigError(f"unknown section [{unknown[0]}]")
    reader = _Reader(data, base)
    domain, scheme, listen, port, public_port = _server(reader)
    tor = _tor(reader)
    tickets = reader.table("tickets", {"audience", "keys", "confirm_sign_in"})
    if "keys" not in tickets:
        raise ConfigError("[tickets].keys is required: the public keys that sign visitors in")
    limits = _limits(reader)
    default_profile, profiles = _profiles(reader)
    services = _services(reader, limits["hook_timeout"])
    files = _safety_files(reader)
    try:
        settings = Settings(
            base_domain=domain,
            scheme=scheme,
            port=public_port,
            audience=_get_or(tickets, "audience", str, "[tickets]", "onionglass"),
            confirm_sign_in=_get_or(tickets, "confirm_sign_in", bool, "[tickets]", True),
            profile=default_profile,
            profiles=profiles,
            keys=_key_ring(reader, tickets["keys"], "[tickets].keys"),
            **limits,
            **services,
            **files,
        )
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    return TeamConfig(settings=settings, tor=tor, listen=listen, port=port)


def load_config(path: str | Path) -> TeamConfig:
    """Read a config file. Raises ``ConfigError`` for anything wrong with it."""
    config_path = Path(path)
    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc.strerror}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{config_path.name} is not valid TOML: {exc}") from exc
    try:
        return parse_config(data, config_path.resolve().parent)
    except PolicyConfigError as exc:
        raise ConfigError(str(exc)) from exc
