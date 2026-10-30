# SPDX-License-Identifier: AGPL-3.0-only
"""Gateway settings and capability profiles."""

from __future__ import annotations

from dataclasses import dataclass, field

from onionglass.headers import HeaderPolicy
from onionglass.hosts import GatewayHosts
from onionglass.tickets import KeyRing

_COOKIE_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


@dataclass(frozen=True, slots=True)
class Profile:
    """What a visitor may do. The defaults are the cautious ones."""

    name: str = "personal"
    allow_images: bool = False
    allow_fonts: bool = True
    allow_post_forms: bool = True
    allow_uploads: bool = False
    allow_password_fields: bool = True
    max_page_bytes: int = 5_000_000
    max_asset_bytes: int = 10_000_000
    rewrite_timeout: float = 15.0


@dataclass(frozen=True, slots=True)
class Settings:
    base_domain: str
    scheme: str = "https"
    port: int | None = None
    audience: str = "onionglass"
    session_ttl: float = 8 * 3600
    cookie_name: str = "og_session"
    profile: Profile = field(default_factory=Profile)
    max_request_body: int = 1_000_000
    max_labels_per_session: int = 1000
    max_labels_per_page: int = 100
    max_new_sessions_per_minute: int = 30
    max_concurrent_fetches: int = 32
    max_fetches_per_session: int = 6
    keys: KeyRing | None = None
    open_mode: bool = False

    def __post_init__(self) -> None:
        if self.scheme not in ("http", "https"):
            raise ValueError("scheme must be http or https")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("port out of range")
        GatewayHosts(self.base_domain)  # raises ValueError if the domain is not acceptable
        if not self.cookie_name or not set(self.cookie_name) <= _COOKIE_NAME_CHARS:
            raise ValueError("cookie name has invalid characters")
        if self.open_mode and self.base_domain != "localhost":
            # Open mode lets anyone who can reach the gateway use it. That is only acceptable
            # when the gateway can be reached from the machine it runs on and nowhere else.
            raise ValueError("open mode is only allowed on localhost")
        if not self.open_mode and self.keys is None:
            raise ValueError("a ticket key ring is required unless open mode is on")

    @property
    def hosts(self) -> GatewayHosts:
        return GatewayHosts(self.base_domain)

    @property
    def apex_host(self) -> str:
        return self.base_domain if self.port is None else f"{self.base_domain}:{self.port}"

    @property
    def apex_origin(self) -> str:
        return f"{self.scheme}://{self.apex_host}"

    @property
    def header_policy(self) -> HeaderPolicy:
        return HeaderPolicy(
            self.scheme, self.base_domain, self.port, viewer_origin=self.apex_origin
        )

    @property
    def require_cookie(self) -> bool:
        """Label hosts must also present the session cookie, except in personal mode.

        In personal mode the cookie cannot be shared across ``*.localhost`` hosts reliably, and
        the gateway is only reachable from the same machine, so the unguessable label itself
        is the capability.
        """
        return self.base_domain != "localhost"
