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
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import uvicorn
from cryptography.hazmat.primitives import serialization

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
from onionglass.config import ConfigError, TeamConfig, load_config, load_private_key
from onionglass.gateway import Gateway
from onionglass.hooks import HttpAudit, HttpPolicy, HttpQuota
from onionglass.tickets import TicketIssuer, generate_key
from onionglass.upstream import TorFetcher

COMMANDS = frozenset({"serve", "check-config", "keys", "ticket", "admin"})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onionglass", description="Run onionglass for other people."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("serve", "run the gateway"), ("check-config", "check a config file")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True, help="the TOML config file")
    keys = commands.add_parser("keys", help="manage signing keys").add_subparsers(
        dest="action", required=True
    )
    generate = keys.add_parser("generate", help="make a new key pair")
    generate.add_argument("--id", required=True, help="the key id, for example gw-2026-10")
    generate.add_argument("--out", type=Path, default=Path(), help="folder for the two files")
    ticket = commands.add_parser("ticket", help="make a sign-in link for testing")
    ticket.add_argument("--key-file", type=Path, required=True, help="the private key file")
    ticket.add_argument("--key-id", required=True)
    ticket.add_argument("--audience", default="onionglass")
    ticket.add_argument("--subject", required=True)
    ticket.add_argument("--group", required=True)
    ticket.add_argument("--profile", required=True)
    ticket.add_argument("--onion", help="open this onion address on arrival")
    ticket.add_argument("--url", required=True, help="the gateway's address, https://example.org")
    ticket.add_argument("--seconds", type=int, default=60, help="how long the link works")
    _admin_parser(commands)
    return parser


def _admin_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    admin = commands.add_parser("admin", help="stop, release and read reports")
    admin.add_argument("--config", type=Path, required=True, help="the TOML config file")
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
        lines = _admin_action(args, paths_from_config(args.config))
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
        f"sign-in keys: {', '.join(sorted(s.keys.ids() if s.keys else []))}",
        f"profiles: {', '.join([s.profile.name, *sorted(s.profiles)])}",
        f"policy: {_kind(s.policy, HttpPolicy)}",
        f"audit log: {_kind(s.audit, HttpAudit)}",
        f"quotas: {_kind(s.quota, HttpQuota)}",
        f"kill file: {'yes' if s.kill else 'no'}",
        f"held list: {'yes' if s.held else 'no'}, name list: {'yes' if s.name_gate else 'no'}",
        f"reports: {'yes' if s.reports else 'no'}, metrics: {'on' if s.metrics_token else 'off'}",
    ]
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


def _ticket(args: argparse.Namespace) -> int:
    try:
        key = load_private_key(args.key_file, "--key-file")
        issuer = TicketIssuer(key, args.key_id, args.audience)
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
    print(f"{args.url.rstrip('/')}/enter?t={token}")
    return 0


def run(argv: Sequence[str]) -> int:
    args = _parser().parse_args(list(argv))
    if args.command == "keys":
        return _generate(args.id, args.out)
    if args.command == "ticket":
        return _ticket(args)
    if args.command == "admin":
        return _admin(args)
    try:
        config = load_config(args.config)
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
