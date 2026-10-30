# SPDX-License-Identifier: AGPL-3.0-only
"""Command line entry point. Runs onionglass in personal mode on this machine."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

import uvicorn

from onionglass.gateway import Gateway
from onionglass.pages import OPERATOR_NOTICE
from onionglass.settings import Profile, Settings
from onionglass.upstream import TorConfig, TorFetcher

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# Inside a container the gateway must listen on all the container's addresses so the published
# port reaches it. The container image sets this variable, and the compose file publishes the
# port on the host's loopback address only.
CONTAINER_VARIABLE = "ONIONGLASS_IN_CONTAINER"


def build_gateway(
    *,
    port: int,
    tor_host: str = "127.0.0.1",
    tor_ports: Sequence[int] = (9050,),
    allow_images: bool = False,
) -> Gateway:
    """A personal-mode gateway: reachable only from this machine, no sign-in needed."""
    settings = Settings(
        base_domain="localhost",
        scheme="http",
        port=port,
        open_mode=True,
        profile=Profile(name="personal", allow_images=allow_images),
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
    gateway = build_gateway(
        port=public_port,
        tor_host=args.tor_host,
        tor_ports=args.tor_port or (9050,),
        allow_images=args.allow_images,
    )
    print(f"onionglass is running. Open http://localhost:{public_port}/ in your browser.")
    print(OPERATOR_NOTICE)
    # Access logging stays off: a log of requests would be a log of the sites you looked at.
    uvicorn.run(gateway.app, host=args.host, port=args.port, log_level="warning", access_log=False)
    return 0
