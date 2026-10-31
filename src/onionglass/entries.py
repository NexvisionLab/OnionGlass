# SPDX-License-Identifier: AGPL-3.0-only
"""Entry domains: a separate gateway for each group of users, described in one config file.

A censor blocks a domain. If every user shares one, that is everyone. So each group is given a
domain of its own, and each domain runs as its own gateway process: its own port, its own sign-in
audience, its own sessions and its own state files. Nothing is shared between groups that could
link them, and a domain that is blocked or leaks costs one group and tells you which.

An entry is a table in the config file::

    [entries.alpha]
    domain = "a.example.net"
    port = 8081

and ``serve --entry alpha`` runs the gateway with that table laid over the main settings. The
lists the gateway only reads (policy, names, look-alikes, keys) stay shared. The files it writes
move to a folder named for the entry, so ``state/audit.log`` becomes ``state/alpha/audit.log``.

One gateway serving several domains was considered and rejected. The domain is built into the
security headers, the host parsing, the rewritten links and the cookies, and changing all of that
would put the most security-sensitive code at risk to save starting a few more processes.
"""

from __future__ import annotations

import copy
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from onionglass.hosts import GatewayHosts

NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
STATE_SECTIONS = ("audit", "held", "reports", "kill", "quota")
_ALLOWED = frozenset({"domain", "port", "public_port", "audience"})
_MAIN_PORT = 8080
_MAIN_AUDIENCE = "onionglass"


@dataclass(frozen=True, slots=True)
class Entry:
    name: str
    domain: str
    port: int
    public_port: int | None
    audience: str


def _whole(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _table(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = data.get(name, {})
    return value if isinstance(value, dict) else {}


def _one(name: str, table: Mapping[str, Any], main_audience: str) -> Entry:
    where = f"[entries.{name}]"
    if not NAME.fullmatch(name):
        raise ValueError(f"{where}: the name must be 1 to 31 lower-case letters, digits or dashes")
    unknown = sorted(set(table) - _ALLOWED)
    if unknown:
        raise ValueError(f"{where}: unknown setting {unknown[0]!r}")
    domain = table.get("domain")
    if not isinstance(domain, str) or not domain:
        raise ValueError(f"{where}: domain is required")
    try:
        GatewayHosts(domain)
    except ValueError as exc:
        raise ValueError(f"{where}: domain: {exc}") from exc
    port = table.get("port")
    if port is None:
        raise ValueError(f"{where}: port is required, so that each gateway has its own")
    if not _whole(port) or not 1 <= port <= 65535:
        raise ValueError(f"{where}: port must be a whole number from 1 to 65535")
    public = table.get("public_port")
    if public is not None and (not _whole(public) or not 1 <= public <= 65535):
        raise ValueError(f"{where}: public_port must be a whole number from 1 to 65535")
    audience = table.get("audience", f"{main_audience}-{name}")
    if not isinstance(audience, str) or not audience:
        raise ValueError(f"{where}: audience must be text")
    return Entry(name, domain, int(port), None if public is None else int(public), audience)


def entries_in(data: Mapping[str, Any]) -> dict[str, Entry]:
    """Every entry in a parsed config file, checked as a set. Raises ``ValueError`` naming the
    first thing that is wrong, so a mistake stops the start of every gateway, not only one."""
    raw = data.get("entries", {})
    if not isinstance(raw, dict):
        raise ValueError("[entries] must be a table")
    server = _table(data, "server")
    main_domain = server.get("domain")
    main_port = server.get("port", _MAIN_PORT)
    main_audience = _table(data, "tickets").get("audience", _MAIN_AUDIENCE)
    found: dict[str, Entry] = {}
    for name, table in raw.items():
        if not isinstance(table, dict):
            raise ValueError(f"[entries.{name}] must be a table")
        entry = _one(name, table, str(main_audience))
        if entry.domain == main_domain:
            raise ValueError(f"[entries.{name}]: domain is the main gateway's domain")
        if entry.port == main_port:
            raise ValueError(f"[entries.{name}]: port is the main gateway's port")
        if entry.audience == main_audience:
            raise ValueError(f"[entries.{name}]: audience is the main gateway's audience")
        for other in found.values():
            _clash(entry, other)
        found[name] = entry
    if isinstance(main_domain, str):
        for entry in found.values():
            _inside(entry.name, entry.domain, "the main gateway", main_domain)
    return found


def _clash(new: Entry, old: Entry) -> None:
    where = f"[entries.{new.name}]"
    if new.domain == old.domain:
        raise ValueError(f"{where}: domain is already used by {old.name}")
    if new.port == old.port:
        raise ValueError(f"{where}: port {new.port} is already used by {old.name}")
    if new.audience == old.audience:
        raise ValueError(f"{where}: audience is already used by {old.name}")
    _inside(new.name, new.domain, old.name, old.domain)
    _inside(old.name, old.domain, new.name, new.domain)


def _inside(name: str, domain: str, other_name: str, other: str) -> None:
    """A domain inside another would be taken for one of that gateway's session hosts."""
    if domain.endswith(f".{other}"):
        raise ValueError(
            f"[entries.{name}]: domain {domain} is inside the domain of {other_name}, "
            "and would be taken for one of its session hosts"
        )


def with_folder(file: str, name: str) -> str:
    """The same file in a folder for this entry: ``state/a.log`` becomes ``state/alpha/a.log``."""
    path = PurePosixPath(file)
    return str(PurePosixPath(path.parent) / name / path.name)


def apply_entry(data: Mapping[str, Any], name: str) -> dict[str, Any]:
    """The config with one entry laid over it: its domain, ports and audience, and its own folder
    for every file the gateway writes. Raises ``ValueError`` if there is no such entry."""
    entries = entries_in(data)
    if name not in entries:
        raise ValueError(f"no entry named {name!r}")
    entry = entries[name]
    changed: dict[str, Any] = copy.deepcopy(dict(data))
    server = changed.setdefault("server", {})
    server["domain"], server["port"] = entry.domain, entry.port
    server.pop("public_port", None)
    if entry.public_port is not None:
        server["public_port"] = entry.public_port
    changed.setdefault("tickets", {})["audience"] = entry.audience
    for section in STATE_SECTIONS:
        table = changed.get(section)
        if isinstance(table, dict) and isinstance(table.get("file"), str) and table["file"]:
            table["file"] = with_folder(table["file"], name)
    return changed


def state_folders(data: Mapping[str, Any], name: str, base: Path) -> list[Path]:
    """The folders an entry needs for the files it writes, which must exist before it starts."""
    folders: list[Path] = []
    changed = apply_entry(data, name)
    for section in STATE_SECTIONS:
        table = changed.get(section)
        if isinstance(table, dict) and isinstance(table.get("file"), str) and table["file"]:
            folder = Path(table["file"]).parent
            folder = folder if folder.is_absolute() else base / folder
            if folder not in folders:
                folders.append(folder)
    return folders


def next_port(data: Mapping[str, Any]) -> int:
    """A port no gateway in the file uses yet: one above the highest."""
    used = [_table(data, "server").get("port", _MAIN_PORT)]
    used += [entry.port for entry in entries_in(data).values()]
    return int(max(port for port in used if _whole(port))) + 1


def write_text_atomic(path: Path, text: str) -> None:
    """Replace a file in one step, so a failure part way never leaves half a config."""
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temporary, path)
    except OSError:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def proxy_text(data: Mapping[str, Any], main_host: str = "gateway") -> str:
    """Blocks for the proxy's Caddyfile, one for the main domain and one for each entry.

    Each domain needs its own wildcard certificate, so the DNS token must be able to edit every
    zone that holds one. The global options and the rest are in ``deploy/team/proxy/Caddyfile``.
    """
    server = _table(data, "server")
    targets: list[tuple[str, str, int]] = []
    domain = server.get("domain")
    if isinstance(domain, str):
        targets.append((domain, main_host, int(server.get("port", _MAIN_PORT))))
    for entry in entries_in(data).values():
        targets.append((entry.domain, f"gateway-{entry.name}", entry.port))
    blocks = [
        "# Blocks for the proxy, made by 'onionglass domains caddy'. Put them in the Caddyfile",
        "# after its global options. Each domain gets its own wildcard certificate.",
    ]
    for name, host, port in targets:
        blocks.append(
            f"""
{name}, *.{name} {{
    tls {{
        dns cloudflare {{env.CLOUDFLARE_API_TOKEN}}
    }}
    header -Server
    @metrics path /_og/metrics /_og/metrics/*
    respond @metrics 404
    reverse_proxy {host}:{port} {{
        header_up -X-Forwarded-For
        header_up -X-Forwarded-Host
        header_up -X-Forwarded-Proto
        header_up -X-Real-IP
    }}
}}"""
        )
    return "\n".join(blocks) + "\n"
