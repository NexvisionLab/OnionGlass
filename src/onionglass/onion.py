# SPDX-License-Identifier: AGPL-3.0-only
"""Version 3 onion service addresses: validation and parsing.

Security property P5: the gateway only ever connects to valid version 3 onion addresses.
Everything that turns text into a destination goes through this module, and it fails closed:
anything it does not fully understand is rejected.

Version 2 addresses are rejected. They stopped working on the Tor network in 2021.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from urllib.parse import urlsplit

ADDRESS_LENGTH = 56
MAX_HOST_LENGTH = 253
MAX_SUBDOMAINS = 4
MAX_URL_LENGTH = 8192
DEFAULT_PORTS = {"http": 80, "https": 443}
DEFAULT_ALLOWED_PORTS = frozenset({80, 443})

_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_CHECKSUM_PREFIX = b".onion checksum"
_VERSION_BYTE = b"\x03"


class InvalidOnionError(ValueError):
    """Anything that is not a well-formed version 3 onion address, host name or URL."""


def _checksum(public_key: bytes) -> bytes:
    return hashlib.sha3_256(_CHECKSUM_PREFIX + public_key + _VERSION_BYTE).digest()[:2]


def normalise_address(address: str) -> str:
    """Return the lower-case 56 character address, or raise InvalidOnionError.

    The address is the label before ``.onion``, without the suffix.
    """
    # The ASCII check must come before lower-casing: a few non-ASCII characters, such as the
    # Kelvin sign, lower-case to plain ASCII letters and would otherwise slip through.
    if not address.isascii():
        raise InvalidOnionError("onion address must be ASCII")
    candidate = address.lower()
    if len(candidate) != ADDRESS_LENGTH:
        raise InvalidOnionError("onion address must be 56 characters")
    if not set(candidate) <= _ALPHABET:
        raise InvalidOnionError("onion address has characters outside base32")
    try:
        raw = base64.b32decode(candidate.upper())
    except (binascii.Error, ValueError) as exc:
        raise InvalidOnionError("onion address is not valid base32") from exc
    public_key, checksum, version = raw[:32], raw[32:34], raw[34:35]
    if version != _VERSION_BYTE:
        raise InvalidOnionError("unsupported onion service version")
    if not hmac.compare_digest(checksum, _checksum(public_key)):
        raise InvalidOnionError("onion address checksum does not match")
    return candidate


def is_valid_address(address: str) -> bool:
    """True when ``address`` is a valid 56 character version 3 address."""
    try:
        normalise_address(address)
    except InvalidOnionError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class OnionHost:
    """A host name ending in a valid onion address, with optional virtual-host labels."""

    address: str
    subdomains: tuple[str, ...] = ()

    @property
    def hostname(self) -> str:
        return ".".join((*self.subdomains, f"{self.address}.onion"))


def _check_label(label: str) -> None:
    if not 1 <= len(label) <= 63:
        raise InvalidOnionError("host label has an invalid length")
    if not set(label) <= _LABEL_CHARS or label[0] == "-" or label[-1] == "-":
        raise InvalidOnionError("host label has invalid characters")


def parse_onion_host(host: str) -> OnionHost:
    """Parse a host name such as ``<address>.onion`` or ``www.<address>.onion``."""
    if not host.isascii():
        raise InvalidOnionError("host must be ASCII")
    value = host.lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > MAX_HOST_LENGTH:
        raise InvalidOnionError("host has an invalid length")
    labels = value.split(".")
    if len(labels) < 2 or labels[-1] != "onion":
        raise InvalidOnionError("host is not an .onion name")
    address = normalise_address(labels[-2])
    subdomains = labels[:-2]
    if len(subdomains) > MAX_SUBDOMAINS:
        raise InvalidOnionError("too many host labels")
    for label in subdomains:
        _check_label(label)
    return OnionHost(address=address, subdomains=tuple(subdomains))


@dataclass(frozen=True, slots=True)
class OnionUrl:
    """A validated http or https URL on an onion host. The fragment is dropped."""

    scheme: str
    host: OnionHost
    port: int
    path: str
    query: str

    @property
    def url(self) -> str:
        default = DEFAULT_PORTS[self.scheme]
        authority = (
            self.host.hostname if self.port == default else f"{self.host.hostname}:{self.port}"
        )
        suffix = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{authority}{self.path}{suffix}"


def _parse_port(text: str) -> int:
    if not text.isascii() or not text.isdigit() or len(text) > 5:
        raise InvalidOnionError("port is not a number")
    port = int(text)
    if not 1 <= port <= 65535:
        raise InvalidOnionError("port is out of range")
    return port


def parse_onion_url(url: str, *, allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS) -> OnionUrl:
    """Parse an absolute http or https URL that must point at an onion host.

    Rejected: control characters, spaces and backslashes (the standard library silently strips
    or reinterprets some of them), user information, IP literals, ports that are not allowed,
    and non-ASCII text. Callers percent-encode before calling.
    """
    if len(url) > MAX_URL_LENGTH:
        raise InvalidOnionError("URL is too long")
    if not url.isascii() or "\\" in url or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url):
        raise InvalidOnionError("URL has control characters, spaces, backslashes or non-ASCII text")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise InvalidOnionError("URL could not be parsed") from exc
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InvalidOnionError("only http and https are allowed")
    netloc = parts.netloc
    if "@" in netloc or netloc.startswith("["):
        raise InvalidOnionError("user information and IP literals are not allowed")
    host_text, separator, port_text = netloc.partition(":")
    port = _parse_port(port_text) if separator else DEFAULT_PORTS[scheme]
    if port not in allowed_ports:
        raise InvalidOnionError("port is not allowed")
    host = parse_onion_host(host_text)
    path = parts.path or "/"
    if not path.startswith("/"):
        raise InvalidOnionError("path must start with a slash")
    return OnionUrl(scheme=scheme, host=host, port=port, path=path, query=parts.query)
