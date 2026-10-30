# SPDX-License-Identifier: AGPL-3.0-only
"""Command line entry point. Runs onionglass in personal mode on this machine."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from onionglass.audit import ADDRESS_FORMS, AddressForm, JsonLinesAudit
from onionglass.gateway import Gateway
from onionglass.held import HeldList
from onionglass.killswitch import KillSwitch
from onionglass.namegate import load_name_gate
from onionglass.pages import OPERATOR_NOTICE
from onionglass.policy import PolicyConfigError, StaticPolicy, load_address_list
from onionglass.reports import ReportError, ReportQueue
from onionglass.settings import Profile, Settings
from onionglass.upstream import TorConfig, TorFetcher

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# Inside a container the gateway must listen on all the container's addresses so the published
# port reaches it. The container image sets this variable, and the compose file publishes the
# port on the host's loopback address only.
CONTAINER_VARIABLE = "ONIONGLASS_IN_CONTAINER"


def build_gateway(  # noqa: PLR0913
    *,
    port: int,
    tor_host: str = "127.0.0.1",
    tor_ports: Sequence[int] = (9050,),
    allow_images: bool = False,
    blocklist: Path | None = None,
    allowlist: Path | None = None,
    kill_file: Path | None = None,
    audit_log: Path | None = None,
    audit_address: AddressForm = "origin",
    rated_list: Path | None = None,
    name_list: Path | None = None,
    held_file: Path | None = None,
    report_file: Path | None = None,
    hold_after: int | None = None,
) -> Gateway:
    """A personal-mode gateway: reachable only from this machine, no sign-in needed.

    Raises ``PolicyConfigError`` if a list cannot be read, so a typo never means no list.
    """
    policy = None
    if blocklist is not None or allowlist is not None or rated_list is not None:
        policy = StaticPolicy(
            blocked=load_address_list(blocklist) if blocklist is not None else (),
            allowed=load_address_list(allowlist) if allowlist is not None else None,
            rated=load_address_list(rated_list) if rated_list is not None else None,
        )
    if name_list is not None and held_file is None:
        raise PolicyConfigError("--name-list needs --held-file, or it could only refuse once")
    held = HeldList(held_file) if held_file is not None else None
    reports = None
    if report_file is not None:
        try:
            reports = ReportQueue(report_file, held=held, hold_after=hold_after)
        except (ReportError, ValueError) as exc:
            raise PolicyConfigError(str(exc)) from exc
    elif hold_after is not None:
        raise PolicyConfigError("--hold-after needs --report-file")
    settings = Settings(
        base_domain="localhost",
        scheme="http",
        port=port,
        open_mode=True,
        profile=Profile(name="personal", allow_images=allow_images),
        policy=policy,
        kill=KillSwitch(kill_file) if kill_file is not None else None,
        audit=JsonLinesAudit(audit_log, address_form=audit_address)
        if audit_log is not None
        else None,
        held=held,
        reports=reports,
        name_gate=load_name_gate(name_list) if name_list is not None else None,
    )
    fetcher = TorFetcher(TorConfig(socks_host=tor_host, socks_ports=tuple(tor_ports)))
    return Gateway(settings, fetcher=fetcher)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="onionglass",
        description="Open onion sites in an ordinary browser. Personal mode: this machine only.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (loopback only)")
    parser.add_argument("--port", type=int, default=8080, help="port to listen on")
    parser.add_argument(
        "--public-port",
        type=int,
        help="port your browser uses to reach the gateway, if different from --port",
    )
    parser.add_argument("--tor-host", default="127.0.0.1", help="where Tor's SOCKS port is")
    parser.add_argument(
        "--tor-port",
        type=int,
        action="append",
        help="Tor SOCKS port, repeat to use several Tor processes (default 9050)",
    )
    parser.add_argument(
        "--allow-images",
        action="store_true",
        help="load images from onion sites (off by default, and never loaded when off)",
    )
    parser.add_argument(
        "--blocklist", type=Path, help="file of onion addresses that are never opened"
    )
    parser.add_argument(
        "--allowlist", type=Path, help="file of the only onion addresses that may be opened"
    )
    parser.add_argument(
        "--kill-file",
        type=Path,
        help="stop serving while this file lists a scope (see docs/running.md)",
    )
    parser.add_argument(
        "--rated-list",
        type=Path,
        help="file of rated onion addresses; every other address is shown as text only",
    )
    parser.add_argument(
        "--name-list",
        type=Path,
        help="file of phrases that hold a site when they appear in a page title or heading",
    )
    parser.add_argument(
        "--held-file",
        type=Path,
        help="file of sites held until reviewed (delete a line to release one)",
    )
    parser.add_argument(
        "--report-file",
        type=Path,
        help="let visitors report a site, and keep the reports in this file",
    )
    parser.add_argument(
        "--hold-after",
        type=int,
        help="hold a site once this many different visitors have reported it (needs --held-file)",
    )
    parser.add_argument("--audit-log", type=Path, help="append an audit line for every request")
    parser.add_argument(
        "--audit-address",
        choices=ADDRESS_FORMS,
        default="origin",
        help="how the audit log names the onion site (default: origin, no path)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    in_container = os.environ.get(CONTAINER_VARIABLE) == "1"
    if args.host not in LOOPBACK_HOSTS and not (in_container and args.host == "0.0.0.0"):  # noqa: S104
        print(
            "onionglass personal mode only listens on this machine (127.0.0.1). "
            "Use team mode to serve other people.",
            file=sys.stderr,
        )
        return 2
    public_port = args.public_port or args.port
    if not (1 <= args.port <= 65535 and 1 <= public_port <= 65535):
        print("the port must be between 1 and 65535", file=sys.stderr)
        return 2
    try:
        gateway = build_gateway(
            port=public_port,
            tor_host=args.tor_host,
            tor_ports=args.tor_port or (9050,),
            allow_images=args.allow_images,
            blocklist=args.blocklist,
            allowlist=args.allowlist,
            kill_file=args.kill_file,
            audit_log=args.audit_log,
            audit_address=args.audit_address,
            rated_list=args.rated_list,
            name_list=args.name_list,
            held_file=args.held_file,
            report_file=args.report_file,
            hold_after=args.hold_after,
        )
    except PolicyConfigError as exc:
        print(f"onionglass: {exc}", file=sys.stderr)
        return 2
    print(f"onionglass is running. Open http://localhost:{public_port}/ in your browser.")
    print(OPERATOR_NOTICE)
    # Access logging stays off: a log of requests would be a log of the sites you looked at.
    uvicorn.run(gateway.app, host=args.host, port=args.port, log_level="warning", access_log=False)
    return 0
