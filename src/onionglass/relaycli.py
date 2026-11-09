# SPDX-License-Identifier: AGPL-3.0-only
"""Commands for entry relays (``docs/relays.md``).

    onionglass relays add --config team.toml --name r1   make a relay's key and its file
    onionglass relays list --config team.toml            the relays the gateway answers
    onionglass relays revoke --config team.toml --name r1  stop answering one
    onionglass relay run --config relay.toml             run a relay
    onionglass relay check --config relay.toml           ask the gateway if it knows this relay

The first three work on the gateway's side, on its config file. The last two run on a relay host.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import serialization

from onionglass.config import ConfigError, parse_config
from onionglass.entries import entries_in, write_text_atomic
from onionglass.policy import PolicyConfigError
from onionglass.relay import ConnectionAbort, Relay, probe
from onionglass.relayconfig import RelayConfig, load_relay_config, parse_origin
from onionglass.tickets import generate_key, is_valid_key_id

COMMANDS = frozenset({"relay", "relays"})
_PLACEHOLDER_URL = "https://GATEWAY-ADDRESS:8443"
_PLACEHOLDER_PIN = "FINGERPRINT-OF-THE-GATEWAYS-CERTIFICATE"


def add_parsers(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    relay = commands.add_parser("relay", help="run or check an entry relay")
    action = relay.add_subparsers(dest="action", required=True)
    run = action.add_parser("run", help="run the relay")
    run.add_argument("--config", type=Path, required=True, help="the relay's TOML file")
    run.add_argument(
        "--check-config", action="store_true", help="read the file, say what it would do and stop"
    )
    check = action.add_parser("check", help="ask the gateway whether it knows this relay")
    check.add_argument("--config", type=Path, required=True, help="the relay's TOML file")

    relays = commands.add_parser("relays", help="the relays a gateway answers")
    manage = relays.add_subparsers(dest="action", required=True)
    for name, text in (
        ("add", "make a key and a file for a new relay"),
        ("list", "show the relays the gateway answers"),
        ("revoke", "stop answering a relay that was blocked or found out"),
    ):
        command = manage.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True, help="the gateway's TOML file")
        if name in ("add", "revoke"):
            command.add_argument(
                "--name", required=True, help="the relay's name, which is its key id"
            )
        if name == "add":
            command.add_argument(
                "--domain",
                action="append",
                default=[],
                help="a domain the relay serves (the gateway's own, if it has only one)",
            )
            command.add_argument(
                "--out", type=Path, default=Path(), help="folder for the relay's files"
            )
            command.add_argument("--origin-url", help="where the relay reaches the gateway")
            command.add_argument(
                "--pin-sha256", help="the fingerprint of the gateway's certificate"
            )


def run(args: argparse.Namespace) -> int:
    return _relay(args) if args.command == "relay" else _relays(args)


# --- on a relay host -----------------------------------------------------------------------------


def _describe(config: RelayConfig) -> list[str]:
    s = config.settings
    origin = s.origin
    ends = "this relay ends TLS" if config.tls_cert else "behind a proxy on this machine"
    hop = "encrypted, certificate pinned" if origin.tls else "NOT encrypted"
    return [
        f"relay for: {', '.join(s.domains)}",
        f"listens on {config.listen}:{config.port} ({ends})",
        f"gateway: {origin.host}:{origin.port} ({hop})",
        f"signs as: {s.signer.key_id}",
        f"limits: {s.max_concurrent} at once, {s.max_per_client} for one visitor",
    ]


class QuietAbort(logging.Filter):
    """Leaves out the server's error line for an answer the relay cut off on purpose. The line
    comes with a traceback, which a visitor who does not take an answer could make as often as
    they like, and which says nothing that the relay's own account of it does not."""

    def filter(self, record: logging.LogRecord) -> bool:
        error = record.exc_info[1] if record.exc_info else None
        return not isinstance(error, ConnectionAbort)


def _relay(args: argparse.Namespace) -> int:
    try:
        config = load_relay_config(args.config)
    except ConfigError as exc:
        print(f"onionglass: config error: {exc}", file=sys.stderr)
        return 2
    if args.action == "check":
        return _check(config)
    print("\n".join(_describe(config)))
    if args.check_config:
        return 0
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("uvicorn.error").addFilter(QuietAbort())
    # Access logging stays off: a log of requests would be a log of who read what. The relay is
    # the one thing here that could write down visitors' addresses, so it writes nothing.
    uvicorn.run(
        Relay(config.settings),
        host=config.listen,
        port=config.port,
        log_level="warning",
        log_config=None,  # the server's own logging setup would replace the filter above
        access_log=False,
        proxy_headers=False,
        server_header=False,
        # The server turns away more connections than the relay will serve, and does not keep an
        # idle one for long. It has no limit on how long a visitor takes to send a request head,
        # so a relay on a public address belongs behind a proxy that has one (docs/relays.md).
        limit_concurrency=config.settings.max_concurrent * 2,
        timeout_keep_alive=5,
        ssl_certfile=str(config.tls_cert) if config.tls_cert else None,
        ssl_keyfile=str(config.tls_key) if config.tls_key else None,
    )
    return 0


def _check(config: RelayConfig) -> int:
    """Send the gateway a signed question and say what its answer means."""
    settings = config.settings
    try:
        status, body = asyncio.run(probe(Relay(settings), settings.domains[0], "/_og/relay-check"))
    except ConnectionAbort:
        print("FAIL the gateway began to answer and the answer was cut short.")
        return 1
    if status == 200 and body.startswith(b"ok "):
        print(f"ok   the gateway knows this relay ({body.decode('ascii', 'replace').strip()})")
        return 0
    if status == 404:
        print(
            "FAIL the gateway answered as it does to a stranger, so it does not know this relay. "
            "Check that the key id and the public key match, that the gateway was restarted "
            "after the key was added, and that this machine's clock is right."
        )
    elif status == 502:
        print(
            "FAIL this relay could not reach the gateway, or the certificate it was shown is "
            "not the pinned one. Check [origin].url and pin_sha256."
        )
    else:
        print(f"FAIL unexpected answer from the gateway: {status}")
    return 1


# --- on the gateway's side -----------------------------------------------------------------------


def _relays(args: argparse.Namespace) -> int:
    try:
        text = args.config.read_bytes().decode("utf-8")  # as written: line endings are kept
        data = tomllib.loads(text)
        action = {"add": _add, "list": _list, "revoke": _revoke}[args.action]
        lines = action(args, data, text)
    except (OSError, ValueError, ConfigError) as exc:
        print(f"onionglass: {exc}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    return 0


def _keys(data: dict[str, Any]) -> list[dict[str, Any]]:
    relays = data.get("relays", {})
    keys = relays.get("keys", []) if isinstance(relays, dict) else []
    return [key for key in keys if isinstance(key, dict)]


def _required(data: dict[str, Any]) -> bool:
    relays = data.get("relays", {})
    return bool(isinstance(relays, dict) and relays.get("require", False))


def _list(args: argparse.Namespace, data: dict[str, Any], text: str) -> list[str]:
    keys = _keys(data)
    if not keys:
        return ["no relays"]
    state = "required" if _required(data) else "not required yet"
    return [f"relays: {state}", *(f"{key.get('id')}  {key.get('public_key_file')}" for key in keys)]


def _served_domains(data: dict[str, Any]) -> list[str]:
    server = data.get("server", {})
    main = server.get("domain") if isinstance(server, dict) else None
    return ([main] if isinstance(main, str) else []) + [
        entry.domain for entry in entries_in(data).values()
    ]


def _domains_for(args: argparse.Namespace, data: dict[str, Any]) -> list[str]:
    served = _served_domains(data)
    if not args.domain:
        if len(served) != 1:
            raise ValueError("this gateway serves several domains, so say which with --domain")
        return served
    for domain in args.domain:
        if domain not in served:
            raise ValueError(f"{domain!r} is not a domain this gateway serves")
    return list(dict.fromkeys(args.domain))


def _toml(value: str) -> str:
    """A string as TOML writes it, quoted and escaped, so that no value can add settings."""
    return json.dumps(value)


def _relay_file(name: str, domains: list[str], url: str, pin: str) -> str:
    listed = ", ".join(_toml(domain) for domain in domains)
    fill = "  # EDIT: fill this in before the relay can start"
    url_note = fill if url == _PLACEHOLDER_URL else ""
    pin_note = fill if pin == _PLACEHOLDER_PIN else ""
    return "\n".join(
        [
            f"# Settings for the entry relay {name}, made by 'onionglass relays add'.",
            f"# Copy this file and relay-{name}.key to the relay host. Keep both private: the",
            "# key is a secret, and so are the gateway's address and fingerprint below.",
            "",
            "[relay]",
            f"domains = [{listed}]",
            'listen = "127.0.0.1"      # behind a proxy on this machine that ends TLS',
            "port = 8081",
            "trust_forwarded = true    # the proxy writes the visitor's address, for limits only",
            "# To end TLS in the relay instead, listen on a public address and give a certificate:",
            '# listen = "0.0.0.0"',
            '# tls_cert_file = "tls/fullchain.pem"',
            '# tls_key_file = "tls/privkey.pem"',
            "",
            "[origin]",
            f"url = {_toml(url)}{url_note}",
            f"pin_sha256 = {_toml(pin)}{pin_note}",
            "",
            "[sign]",
            f"key_id = {_toml(name)}",
            f"key_file = {_toml(f'relay-{name}.key')}",
            "",
        ]
    )


def _write_new(path: Path, data: bytes, mode: int) -> None:
    """Make a file that must not exist yet, so that nothing is ever overwritten."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _newline(text: str) -> str:
    """The file's own line ending, so that an edit does not change every line of it."""
    return "\r\n" if "\r\n" in text else "\n"


def _with_relay(text: str, data: dict[str, Any], name: str, public: str) -> str:
    nl = _newline(text)
    new = text if text.endswith("\n") else text + nl
    if "relays" not in data:
        new += f"{nl}[relays]{nl}require = false  # set to true once every visitor uses a relay{nl}"
    entry = f"[[relays.keys]]{nl}id = {_toml(name)}{nl}public_key_file = {_toml(public)}{nl}"
    return new + nl + entry


def _add(args: argparse.Namespace, data: dict[str, Any], text: str) -> list[str]:
    name: str = args.name
    if not is_valid_key_id(name):
        raise ValueError("a relay name is 1 to 32 letters, digits, - or _")
    if any(key.get("id") == name for key in _keys(data)):
        raise ValueError(f"the relay {name!r} is already in the config file")
    _blocks(text.splitlines(keepends=True), data)  # refuses a file this command cannot edit
    domains = _domains_for(args, data)
    if args.pin_sha256 is not None and not args.origin_url:
        raise ValueError("--pin-sha256 goes with --origin-url")
    if args.origin_url:
        parse_origin(args.origin_url, args.pin_sha256)  # refuses an address that could not work
    base = args.config.resolve().parent
    public_name = f"keys/relay-{name}.public.pem"
    paths = [args.out / f"relay-{name}.key", args.out / f"relay-{name}.toml", base / public_name]
    for path in paths:
        if path.exists():
            raise ValueError(f"{path} already exists, not overwriting it")
    new_text = _with_relay(text, data, name, public_name)

    key = generate_key()
    # A folder this command makes is removed again if it fails and nothing else has gone into it.
    new_folders = [folder for folder in (args.out, base / "keys") if not folder.exists()]
    args.out.mkdir(parents=True, exist_ok=True)
    (base / "keys").mkdir(exist_ok=True)
    made: list[Path] = []
    try:
        private = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        relay_text = _relay_file(
            name, domains, args.origin_url or _PLACEHOLDER_URL, args.pin_sha256 or _PLACEHOLDER_PIN
        )
        for path, content, mode in (
            (paths[0], private, 0o600),
            (paths[2], public, 0o644),
            (paths[1], relay_text.encode("utf-8"), 0o600),
        ):
            _write_new(path, content, mode)
            made.append(path)
        try:
            parse_config(tomllib.loads(new_text), base)  # the gateway must still load with it
        except (ConfigError, PolicyConfigError) as exc:
            raise ValueError(f"the config file would not work with this relay: {exc}") from exc
        write_text_atomic(args.config, new_text)
    except BaseException:
        for path in made:
            with contextlib.suppress(OSError):
                path.unlink()
        for folder in new_folders:
            with contextlib.suppress(OSError):
                folder.rmdir()  # refuses, harmlessly, if anything is in it
        raise
    required = "relays are required" if _required(data) else "relays are not required yet"
    return [
        f"added relay {name}",
        f"gateway side: its public key is {public_name}, under [relays] in {args.config.name}",
        f"relay side: copy {paths[1]} and {paths[0]} (secret) to the relay host, then delete the "
        "copy of the key here: whoever holds it can speak to the gateway as this relay",
        "next:",
        "  1. Edit the relay's file if the gateway's address and fingerprint are still to fill in.",
        "  2. Restart the gateway, so that it knows the new key.",
        f"  3. On the relay host: onionglass relay check --config relay-{name}.toml",
        f"  4. Then: onionglass relay run --config relay-{name}.toml",
        f"  5. {required}. Set require = true under [relays] once every visitor comes through "
        "a relay, and restart the gateway.",
    ]


_KEYS_HEADER = re.compile(r"^\s*\[\[\s*relays\.keys\s*\]\]\s*(#.*)?$")
_RELAYS_HEADER = re.compile(r"^\s*\[\s*relays\s*\]\s*(#.*)?$")


def _section_end(lines: list[str], start: int) -> int:
    """Where the table that begins on line ``start`` ends: at the next table, less the blank lines
    and comments just before it, which belong to what follows."""
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines)
    )
    while end > start + 1 and (not lines[end - 1].strip() or lines[end - 1].lstrip()[0] == "#"):
        end -= 1
    return end


def _blocks(lines: list[str], data: dict[str, Any]) -> list[tuple[int, int, str]]:
    """Where each ``[[relays.keys]]`` entry starts and ends in the file, and its id.

    A file that writes some of its keys any other way, as an inline list, is refused, because
    this command edits lines and could not change that safely.
    """
    found = []
    for start, line in enumerate(lines):
        if _KEYS_HEADER.match(line.rstrip("\r\n")):
            end = _section_end(lines, start)
            entry = tomllib.loads("".join(lines[start:end]))["relays"]["keys"][0]
            found.append((start, end, str(entry.get("id", ""))))
    if len(found) != len(_keys(data)):
        raise ValueError(
            "this file writes some relay keys as an inline list, which this command cannot "
            "change. Write each one as a [[relays.keys]] block, or edit the file by hand"
        )
    return found


def _revoke(args: argparse.Namespace, data: dict[str, Any], text: str) -> list[str]:
    lines = text.splitlines(keepends=True)
    blocks = _blocks(lines, data)
    match = [(start, end) for start, end, key_id in blocks if key_id == args.name]
    if not match:
        raise ValueError(f"no relay named {args.name!r} in the config file")
    last = len(match) == len(blocks)  # nothing would be left
    if last and _required(data):
        raise ValueError(
            "this is the last relay and relays are required, so the gateway would not start. "
            "Add another relay first, or set require = false on purpose"
        )
    keep = list(lines)
    for start, end in reversed(match):  # every block with that name, the last one first
        del keep[start:end]
        if start and not keep[start - 1].strip():
            del keep[start - 1]  # the blank line that came before it
    if last:  # no relay is left, so the section goes too and relay mode ends
        keep = _without_relays_table(keep)
    new_text = "".join(keep)
    base = args.config.resolve().parent
    if _starts(text, base):  # it worked before, so it must still work
        try:
            parse_config(tomllib.loads(new_text), base)
        except (ConfigError, PolicyConfigError) as exc:
            raise ValueError(f"the config file would not work without this relay: {exc}") from exc
    else:
        tomllib.loads(new_text)  # at least a valid file
    write_text_atomic(args.config, new_text)
    public = next(
        (str(key.get("public_key_file")) for key in _keys(data) if key.get("id") == args.name), ""
    )
    said = [f"revoked relay {args.name}"]
    if last:
        said.append(
            "that was the last relay, so the [relays] section was removed and relay mode is off. "
            "Anything else in that section, such as max_skew_seconds, went with it"
        )
    return [
        *said,
        "the gateway stops answering it when it is restarted, so restart the gateway now",
        f"its public key file is still on disk ({public}), delete it when you no longer need it",
        "on the relay host: stop the relay and delete its key",
    ]


def _starts(text: str, base: Path) -> bool:
    """Whether the gateway would start from this text."""
    try:
        parse_config(tomllib.loads(text), base)
    except (ConfigError, PolicyConfigError, ValueError):
        return False
    return True


def _without_relays_table(lines: list[str]) -> list[str]:
    for start, line in enumerate(lines):
        if _RELAYS_HEADER.match(line.rstrip("\r\n")):
            end = _section_end(lines, start)
            tidy = start - 1 if start and not lines[start - 1].strip() else start
            return lines[:tidy] + lines[end:]
    return lines
