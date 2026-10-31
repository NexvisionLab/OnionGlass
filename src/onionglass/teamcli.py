# SPDX-License-Identifier: AGPL-3.0-only
"""Commands for running a gateway for other people, and the keys that sign them in.

    onionglass serve --config team.toml        run the gateway described in the file
    onionglass check-config --config team.toml read the file and say what it would do
    onionglass keys generate --id k1 --out DIR make a signing key pair
    onionglass ticket --key-file ... ...       make one sign-in link, to test a deployment

Personal mode, started with no command, is in ``cli.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import serialization

from onionglass import reach
from onionglass.admin import (
    AdminError,
    AdminPaths,
    held_add,
    held_list,
    held_release,
    kill_off,
    kill_on,
    kill_status,
    paths_from_config,
    reports_summary,
)
from onionglass.config import (
    ConfigError,
    TeamConfig,
    load_config,
    load_private_key,
    tor_endpoints,
)
from onionglass.entries import (
    entries_in,
    next_port,
    proxy_text,
    state_folders,
    write_text_atomic,
)
from onionglass.gateway import Gateway
from onionglass.hooks import HttpAudit, HttpPolicy, HttpQuota
from onionglass.hosts import GatewayHosts
from onionglass.tickets import TicketIssuer, generate_key
from onionglass.torcheck import TorStatus, check_tor
from onionglass.upstream import TorFetcher

COMMANDS = frozenset({"serve", "check-config", "keys", "ticket", "admin", "domains", "check-tor"})
ENTRY_HELP = "run, check or work on this entry (see [entries] in the config file)"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onionglass", description="Run onionglass for other people."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("serve", "run the gateway"), ("check-config", "check a config file")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True, help="the TOML config file")
        command.add_argument("--entry", help=ENTRY_HELP)
    keys = commands.add_parser("keys", help="manage signing keys").add_subparsers(
        dest="action", required=True
    )
    generate = keys.add_parser("generate", help="make a new key pair")
    generate.add_argument("--id", required=True, help="the key id, for example gw-2026-10")
    generate.add_argument("--out", type=Path, default=Path(), help="folder for the two files")
    ticket = commands.add_parser("ticket", help="make a sign-in link for testing")
    ticket.add_argument("--config", type=Path, help="the TOML config file, with --entry")
    ticket.add_argument("--entry", help="make the link for this entry's domain and audience")
    ticket.add_argument("--key-file", type=Path, required=True, help="the private key file")
    ticket.add_argument("--key-id", required=True)
    ticket.add_argument("--audience", default="onionglass")
    ticket.add_argument("--subject", required=True)
    ticket.add_argument("--group", required=True)
    ticket.add_argument("--profile", required=True)
    ticket.add_argument("--onion", help="open this onion address on arrival")
    ticket.add_argument("--url", help="the gateway's address, https://example.org")
    ticket.add_argument("--seconds", type=int, default=60, help="how long the link works")
    _admin_parser(commands)
    _domains_parser(commands)
    tor = commands.add_parser(
        "check-tor", help="check that Tor is running and can find onion sites"
    )
    tor.add_argument(
        "--config", type=Path, help="check the Tor processes named in this config file"
    )
    tor.add_argument("--tor-host", default="127.0.0.1", help="where Tor listens")
    tor.add_argument("--tor-port", type=int, action="append", help="a Tor SOCKS port (9050)")
    tor.add_argument("--wait", type=_wait, default=30.0, help="seconds to give the lookup")
    return parser


def _wait(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        seconds = 0.0
    if not 0 < seconds <= 300:
        raise argparse.ArgumentTypeError("the wait must be above 0 and at most 300 seconds")
    return seconds


def _check_tor(args: argparse.Namespace) -> int:
    """Try every Tor and say, for each, whether it works and what is wrong if not."""
    try:
        if args.config is not None:
            where = tor_endpoints(args.config)
        else:
            where = [(args.tor_host, port) for port in args.tor_port or [9050]]
    except ConfigError as exc:
        print(f"onionglass: config error: {exc}", file=sys.stderr)
        return 2

    async def every() -> list[TorStatus]:
        return list(
            await asyncio.gather(*(check_tor(host, port, wait=args.wait) for host, port in where))
        )

    results = asyncio.run(every())
    for status in results:
        label = "ok  " if status.ok else "FAIL"
        detail = status.message if status.ok else f"[{status.state}] {status.message}"
        print(f"{label} {detail}")
    return 0 if all(status.ok for status in results) else 1


def _seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        seconds = 0.0
    if not 0 < seconds <= 120:
        raise argparse.ArgumentTypeError("the timeout must be above 0 and at most 120 seconds")
    return seconds


def _domains_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    domains = commands.add_parser("domains", help="the domains for each group of users")
    action = domains.add_subparsers(dest="action", required=True)
    check = action.add_parser("check", help="see where a connection to a domain fails")
    check.add_argument("--config", type=Path, help="check every domain in this config file")
    check.add_argument("--domain", action="append", default=[], help="a domain to check")
    check.add_argument("--port", type=int, default=443)
    check.add_argument("--expect-address", action="append", help="an address it should resolve to")
    check.add_argument("--expect-sha256", help="the hash of the front page you expect")
    check.add_argument("--timeout", type=_seconds, default=10.0, help="seconds for each step")
    check.add_argument("--no-wildcard", action="store_true", help="skip the session host lookup")
    for name, text in (
        ("list", "show every entry and what it uses"),
        ("add", "add an entry for a new group or a replacement domain"),
        ("retire", "stop an entry that has been blocked or leaked"),
        ("caddy", "print the proxy blocks for the main domain and every entry"),
    ):
        command = action.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True, help="the TOML config file")
        if name in ("add", "retire"):
            command.add_argument("--name", required=True, help="the entry's name")
        if name == "add":
            command.add_argument("--domain", required=True, help="the domain for this group")
            command.add_argument(
                "--port", type=int, help="its port (the next free one if left out)"
            )
        if name == "caddy":
            command.add_argument("--main-host", default="gateway", help="the main gateway's host")


def _admin_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    admin = commands.add_parser("admin", help="stop, release and read reports")
    admin.add_argument("--config", type=Path, required=True, help="the TOML config file")
    admin.add_argument("--entry", help=ENTRY_HELP)
    area = admin.add_subparsers(dest="area", required=True)

    kill = area.add_parser("kill", help="stop and resume serving").add_subparsers(
        dest="action", required=True
    )
    kill.add_parser("status", help="say what is stopped")
    for name, text in (("on", "stop serving"), ("off", "resume serving")):
        command = kill.add_parser(name, help=text)
        scope = command.add_mutually_exclusive_group(required=name == "on")
        scope.add_argument("--all", action="store_true", help="everything")
        scope.add_argument("--profile", help="one profile")
        scope.add_argument("--onion", help="one onion site")

    held = area.add_parser("held", help="sites held for review").add_subparsers(
        dest="action", required=True
    )
    held.add_parser("list", help="show the held sites")
    add = held.add_parser("add", help="hold a site now")
    add.add_argument("address")
    add.add_argument("--reason", default="by an operator")
    release = held.add_parser("release", help="serve a site again")
    release.add_argument("address")

    reports = area.add_parser("reports", help="visitor reports").add_subparsers(
        dest="action", required=True
    )
    summary = reports.add_parser("summary", help="the most reported sites")
    summary.add_argument("--at-least", type=int, default=1, help="only sites with this many")


def _scope(args: argparse.Namespace) -> tuple[str | None, str | None]:
    if args.all:
        return "all", None
    if args.profile:
        return "profile", args.profile
    if args.onion:
        return "onion", args.onion
    return None, None


def _admin_action(args: argparse.Namespace, paths: AdminPaths) -> list[str]:
    scoped = args.area == "kill" and args.action in ("on", "off")
    scope, value = _scope(args) if scoped else (None, None)
    actions: dict[tuple[str, str], Callable[[], list[str]]] = {
        ("kill", "status"): lambda: kill_status(paths),
        ("kill", "on"): lambda: [kill_on(paths, scope or "all", value)],
        ("kill", "off"): lambda: [kill_off(paths, scope, value)],
        ("held", "list"): lambda: held_list(paths),
        ("held", "add"): lambda: [held_add(paths, args.address, args.reason)],
        ("held", "release"): lambda: [held_release(paths, args.address)],
        ("reports", "summary"): lambda: reports_summary(paths, at_least=args.at_least),
    }
    return actions[(args.area, args.action)]()


def _admin(args: argparse.Namespace) -> int:
    try:
        lines = _admin_action(args, paths_from_config(args.config, args.entry))
    except AdminError as exc:
        print(f"onionglass: {exc}", file=sys.stderr)
        return 2
    print(chr(10).join(lines))
    return 0


def describe(config: TeamConfig) -> list[str]:
    """What a config would do, in plain lines. Never includes a key, token or salt."""
    s = config.settings
    where = f"{s.scheme}://{s.apex_host}"
    lines = [
        f"serves {where}, listening on {config.listen}:{config.port}",
        f"sign-in audience: {s.audience}",
        f"sign-in keys: {', '.join(sorted(s.keys.ids() if s.keys else []))}",
        f"profiles: {', '.join([s.profile.name, *sorted(s.profiles)])}",
        f"policy: {_kind(s.policy, HttpPolicy)}",
        f"audit log: {_kind(s.audit, HttpAudit)}",
        f"quotas: {_kind(s.quota, HttpQuota)}",
        f"kill file: {'yes' if s.kill else 'no'}",
        f"held list: {'yes' if s.held else 'no'}, name list: {'yes' if s.name_gate else 'no'}",
        f"reports: {'yes' if s.reports else 'no'}, metrics: {'on' if s.metrics_token else 'off'}",
    ]
    lines.append("cover mode: on, a stranger sees a plain page" if s.cover else "cover mode: off")
    if s.cover is not None and s.abuse_contact is not None:
        lines.append(
            "warning: cover mode keeps the public abuse page hidden, so publish "
            "the abuse contact somewhere else"
        )
    if s.audit is None:
        lines.append("warning: no audit log, so nothing records who opened what")
    if s.kill is None:
        lines.append("warning: no kill file, so there is no way to stop it without a restart")
    if s.held is None:
        lines.append("warning: no held list, so nothing can be held for review")
    if s.policy is None:
        lines.append("warning: no policy, so any valid onion address can be opened")
    if s.abuse_contact is None:
        lines.append("warning: no abuse contact, so the abuse page has nobody to name")
    return lines


def _kind(value: object, hook_type: type) -> str:
    if value is None:
        return "none"
    return "another service (signed HTTP)" if isinstance(value, hook_type) else "built in"


def _generate(key_id: str, out: Path) -> int:
    key = generate_key()
    try:
        TicketIssuer(key, key_id, "onionglass")  # checks the key id
    except ValueError:
        print("onionglass: a key id may use letters, digits, - and _ only", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    private_path, public_path = out / f"{key_id}.private.pem", out / f"{key_id}.public.pem"
    if private_path.exists() or public_path.exists():
        print("onionglass: those key files already exist, not overwriting them", file=sys.stderr)
        return 2
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(f"private key (keep it secret, never share it): {private_path}")
    print(f"public key (give this to whatever must trust it): {public_path}")
    return 0


def _ticket_target(args: argparse.Namespace) -> tuple[str, str]:
    """The address and audience a link is made for: the entry's own, or the ones given."""
    if args.entry is None:
        if not args.url:
            raise ValueError("--url is required, unless --entry names an entry in --config")
        return str(args.url), str(args.audience)
    if args.config is None:
        raise ValueError("--entry needs --config")
    data = _read_config(args.config)
    entries = entries_in(data)
    if args.entry not in entries:
        raise ValueError(f"no entry named {args.entry!r}")
    entry = entries[args.entry]
    scheme = data.get("server", {}).get("scheme", "https")
    port = f":{entry.public_port}" if entry.public_port else ""
    return f"{scheme}://{entry.domain}{port}", entry.audience


def _ticket(args: argparse.Namespace) -> int:
    try:
        url, audience = _ticket_target(args)
        key = load_private_key(args.key_file, "--key-file")
        issuer = TicketIssuer(key, args.key_id, audience)
        token = issuer.issue(
            subject=args.subject,
            group=args.group,
            profile=args.profile,
            onion=args.onion,
            lifetime=args.seconds,
        )
    except (ConfigError, ValueError) as exc:
        print(f"onionglass: {exc}", file=sys.stderr)
        return 2
    print(f"{url.rstrip('/')}/enter?t={token}")
    return 0


def _read_config(path: Path) -> dict[str, Any]:
    try:
        data: dict[str, Any] = tomllib.loads(path.read_bytes().decode("utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror}") from exc
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path.name} is not valid TOML") from exc
    return data


def _shown(folder: Path, base: Path) -> str:
    try:
        return folder.relative_to(base).as_posix()
    except ValueError:
        return folder.as_posix()


def _entry_lines(data: dict[str, Any], base: Path) -> list[str]:
    lines = []
    for entry in entries_in(data).values():
        folders = state_folders(data, entry.name, base)
        where = ", ".join(_shown(folder, base) for folder in folders) or "none"
        public = f", public port {entry.public_port}" if entry.public_port else ""
        lines.append(
            f"{entry.name}: {entry.domain}, port {entry.port}{public}, "
            f"audience {entry.audience}, state {where}"
        )
    return lines or ["no entries"]


def _add_entry(args: argparse.Namespace, data: dict[str, Any], text: str) -> list[str]:
    if args.name in entries_in(data):
        raise ValueError(f"the entry {args.name!r} already exists")
    port = args.port if args.port is not None else next_port(data)
    newline = chr(10)
    block = newline.join(
        ["", f"[entries.{args.name}]", f'domain = "{args.domain}"', f"port = {port}", ""]
    )
    new_text = text if text.endswith(newline) else text + newline
    new_text += block
    new_data = tomllib.loads(new_text)
    entry = entries_in(new_data)[args.name]  # raises ValueError for a clash in name, domain or port
    base = args.config.resolve().parent
    write_text_atomic(args.config, new_text)
    folders = state_folders(new_data, args.name, base)
    for folder in folders:
        folder.mkdir(parents=True, exist_ok=True)
    config = args.config
    return [
        f"added {entry.name}: {entry.domain}, port {entry.port}, audience {entry.audience}",
        f"state folders made: {', '.join(_shown(f, base) for f in folders) or 'none needed'}",
        "next:",
        f"  1. DNS: point {entry.domain} and *.{entry.domain} at the proxy, as the main domain is.",
        f"  2. Proxy: onionglass domains caddy --config {config}, then add the new block.",
        f"  3. Run it: onionglass serve --config {config} --entry {entry.name}",
        f"  4. Links: onionglass ticket --config {config} --entry {entry.name} --key-file ...",
    ]


def _check_domains(args: argparse.Namespace) -> int:
    """Try each domain and say where it stops. Exits 1 if any of them does not work."""
    domains = list(args.domain)
    try:
        if args.config is not None:
            data = _read_config(args.config)
            main = data.get("server", {}).get("domain")
            domains += ([main] if isinstance(main, str) else []) + [
                entry.domain for entry in entries_in(data).values()
            ]
        if not domains:
            raise ValueError("give --domain, or --config to check every domain in a file")
        for domain in domains:
            GatewayHosts(domain)
    except ValueError as exc:
        print(f"onionglass: {exc}", file=sys.stderr)
        return 2
    expect = frozenset(args.expect_address) if args.expect_address else None

    async def everything() -> list[reach.Reach]:
        return list(
            await asyncio.gather(
                *(
                    reach.check_domain(
                        domain,
                        port=args.port,
                        expect=expect,
                        expect_sha256=args.expect_sha256,
                        timeout=args.timeout,
                        check_wildcard=not args.no_wildcard,
                    )
                    for domain in dict.fromkeys(domains)
                )
            )
        )

    results = asyncio.run(everything())
    for result in results:
        label = "ok  " if result.ok else "FAIL"
        detail = result.message if result.ok else f"[{result.stage}] {result.message}"
        print(f"{label} {result.domain}  {detail}")
    return 0 if all(result.ok for result in results) else 1


def _domains(args: argparse.Namespace) -> int:
    if args.action == "check":
        return _check_domains(args)
    try:
        text = args.config.read_text(encoding="utf-8")
        data = _read_config(args.config)
        entries = entries_in(data)
        base = args.config.resolve().parent
        if args.action == "list":
            lines = _entry_lines(data, base)
        elif args.action == "add":
            lines = _add_entry(args, data, text)
        elif args.action == "caddy":
            lines = proxy_text(data, args.main_host).splitlines()
        else:
            if args.name not in entries:
                raise ValueError(f"no entry named {args.name!r}")
            message = kill_on(paths_from_config(args.config, args.name), "all")
            lines = [
                f"{args.name} ({entries[args.name].domain}): {message}",
                "to finish: remove its DNS records, its block in the proxy and its process.",
            ]
    except (AdminError, OSError, ValueError) as exc:
        print(f"onionglass: {exc}", file=sys.stderr)
        return 2
    print(chr(10).join(lines))
    return 0


def _without_a_gateway(args: argparse.Namespace) -> int | None:
    """The commands that work on keys, links and files and never start a gateway."""
    if args.command == "keys":
        return _generate(args.id, args.out)
    if args.command == "ticket":
        return _ticket(args)
    if args.command == "admin":
        return _admin(args)
    if args.command == "domains":
        return _domains(args)
    if args.command == "check-tor":
        return _check_tor(args)
    return None


def run(argv: Sequence[str]) -> int:
    args = _parser().parse_args(list(argv))
    done = _without_a_gateway(args)
    if done is not None:
        return done
    try:
        config = load_config(args.config, args.entry)
    except ConfigError as exc:
        print(f"onionglass: config error: {exc}", file=sys.stderr)
        return 2
    if args.command == "check-config":
        print("\n".join(describe(config)))
        return 0
    gateway = Gateway(config.settings, fetcher=TorFetcher(config.tor))
    print("\n".join(describe(config)))
    # The gateway sits behind a proxy that ends TLS. Access logging stays off, because a log of
    # requests would be a log of the sites people looked at, and forwarded headers are ignored.
    uvicorn.run(
        gateway.app,
        host=config.listen,
        port=config.port,
        log_level="warning",
        access_log=False,
        proxy_headers=False,
        server_header=False,
    )
    return 0
