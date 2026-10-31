# SPDX-License-Identifier: AGPL-3.0-only
"""Is Tor there, is it Tor, and can it reach onion sites? A plain answer for each way it can be
wrong, so that a first install does not end in "Tor is not available" and nothing else.

The deep check asks Tor to find an onion address that was just made up, and so does not exist.
That is a question only an onion lookup can answer, and it never leaves Tor through an exit, so it
cannot reach a site on the ordinary internet. The answer Tor gives tells whether it is connected.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onionglass.socks import (
    METHOD_USERNAME_PASSWORD,
    SOCKS_VERSION,
    SocksError,
    socks5_connect,
)

CHECK_USER = "onionglass-check"

# Tor says why an onion lookup failed. Any of these means it reached the network and looked.
_LOOKED_UP = frozenset(
    {
        "descriptor_not_found",
        "descriptor_invalid",
        "introduction_failed",
        "rendezvous_failed",
        "introduction_timeout",
        "auth_required",
        "auth_wrong",
        "invalid_address",
    }
)
_NOT_CONNECTED_YET = frozenset({"general_failure", "network_unreachable", "ttl_expired"})


@dataclass(frozen=True, slots=True)
class TorStatus:
    """What the check found. ``state`` is one word, ``ok`` says whether Tor can be used."""

    state: str  # working, starting, slow, not_listening, not_socks, no_login or refused
    ok: bool
    message: str


def _unused_onion_address() -> str:
    """A well-formed version 3 onion address from a key made just now, which nobody runs."""
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    version = bytes([3])
    checksum = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    return base64.b32encode(key + checksum + version).decode("ascii").lower()


def _status(state: str, ok: bool, message: str) -> TorStatus:
    return TorStatus(state, ok, message)


async def check_tor_quickly(host: str, port: int, timeout: float = 2.0) -> TorStatus:
    """Only whether something answers as a SOCKS5 proxy that takes a user name and password. It
    looks nothing up, so it is fast, and it is what personal mode runs before it starts."""
    where = f"{host}:{port}"
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return _status(
            "not_listening",
            False,
            f"nothing is listening on {where}. Start Tor, or give the right port with --tor-port.",
        )
    try:
        writer.write(bytes([SOCKS_VERSION, 1, METHOD_USERNAME_PASSWORD]))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), timeout)
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        return _status(
            "not_socks",
            False,
            f"something answers on {where}, but it does not speak SOCKS5 and so is not Tor's "
            "SOCKS port.",
        )
    finally:
        writer.close()
    if reply[0] != SOCKS_VERSION:
        return _status(
            "not_socks",
            False,
            f"something answers on {where}, but it does not speak SOCKS5 and so is not Tor's "
            "SOCKS port.",
        )
    if reply[1] != METHOD_USERNAME_PASSWORD:
        return _status("no_login", False, _no_login(where))
    return _status("working", True, f"{where} answers as a SOCKS5 proxy.")


def _no_login(where: str) -> str:
    return (
        f"{where} speaks SOCKS5 but will not take the user name and password that onionglass "
        "uses to keep visitors apart, so it may not be Tor."
    )


async def check_tor(host: str, port: int, *, wait: float = 30.0) -> TorStatus:
    """Everything: that Tor answers, and that it can find an onion site. ``wait`` is how long to
    give the lookup, in seconds, since Tor that has only just started needs a minute."""
    where = f"{host}:{port}"
    first = await check_tor_quickly(host, port)
    if not first.ok:
        return first
    try:
        _, writer = await socks5_connect(
            f"{_unused_onion_address()}.onion",
            80,
            proxy_host=host,
            proxy_port=port,
            username=CHECK_USER,
            connect_timeout=wait,
        )
    except SocksError as exc:
        return _meaning(exc, where, wait)
    writer.close()
    return _status("working", True, f"Tor answers on {where} and can find onion sites.")


def _meaning(error: SocksError, where: str, wait: float) -> TorStatus:
    """What Tor's answer to the lookup tells us about Tor."""
    kind = error.kind
    if kind in ("proxy_refused_auth_method", "proxy_rejected_credentials"):
        return _status("no_login", False, _no_login(where))
    if kind in ("proxy_closed", "proxy_protocol_error"):
        return _status(
            "not_socks",
            False,
            f"{where} closed the connection or answered in a way SOCKS5 does not, so it may not "
            "be Tor.",
        )
    if kind in _LOOKED_UP or kind == "host_unreachable":
        plain = (
            " It does not give detailed reasons when a site fails, as with Tor Browser's Tor, "
            "so error pages will be less specific."
            if kind == "host_unreachable"
            else ""
        )
        return _status("working", True, f"Tor answers on {where} and can find onion sites.{plain}")
    if kind in _NOT_CONNECTED_YET:
        return _status(
            "starting",
            False,
            f"Tor answers on {where} but cannot reach the Tor network yet. If it was only just "
            "started, wait a minute and try again.",
        )
    if kind == "connect_timeout":
        return _status(
            "slow",
            False,
            f"Tor accepted the connection on {where} but did not finish the lookup within "
            f"{wait:g} seconds. It may still be starting, or the network may be slow.",
        )
    return _status(
        "refused",
        False,
        f"Tor on {where} refused the request ({kind}). Check its SOCKS settings.",
    )
