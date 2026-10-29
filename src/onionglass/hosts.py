# SPDX-License-Identifier: AGPL-3.0-only
"""Mapping between opaque labels and the gateway's host names."""

from __future__ import annotations

from dataclasses import dataclass

from onionglass.labels import is_valid_label

_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")


@dataclass(frozen=True, slots=True)
class GatewayHosts:
    """The gateway's own domain. In personal mode this is ``localhost``."""

    base_domain: str

    def __post_init__(self) -> None:
        domain = self.base_domain
        labels = domain.split(".")
        bad = (
            not domain
            or domain != domain.lower()
            or not domain.isascii()
            or not set(domain) <= _DOMAIN_CHARS
            or any(
                not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
                for label in labels
            )
            or len(domain) > 200
        )
        if bad:
            raise ValueError(
                "base_domain must be a lower-case ASCII domain name without a trailing dot"
            )

    def host_for(self, label: str) -> str:
        if not is_valid_label(label):
            raise ValueError("invalid label")
        return f"{label}.{self.base_domain}"

    def label_from_host(self, host_header: str) -> str | None:
        """The label in a ``Host`` header, or None if the host is not ``<label>.<base domain>``."""
        if not host_header.isascii() or host_header.startswith("["):
            return None
        host, separator, port = host_header.rpartition(":")
        if not separator:
            host = host_header
        elif not port.isdigit():
            return None
        host = host.lower().removesuffix(".")
        suffix = f".{self.base_domain}"
        if not host.endswith(suffix):
            return None
        label = host.removesuffix(suffix)
        return label if is_valid_label(label) else None
