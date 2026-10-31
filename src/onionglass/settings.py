# SPDX-License-Identifier: AGPL-3.0-only
"""Gateway settings and capability profiles."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from onionglass.audit import AuditSink
from onionglass.entities import EntitySink
from onionglass.headers import HeaderPolicy
from onionglass.held import HeldList
from onionglass.hosts import GatewayHosts
from onionglass.killswitch import KillSwitch
from onionglass.lookalike import KnownSites
from onionglass.namegate import NameGate
from onionglass.policy import Policy
from onionglass.quota import QuotaMeter
from onionglass.reports import ReportQueue
from onionglass.tickets import KeyRing

MAX_PROFILE_BYTES = 1_000_000_000
MAX_CONTACT = 200
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def valid_contact(contact: str) -> bool:
    """True for a plain email address or an https link, in printable ASCII with no spaces."""
    if not 3 <= len(contact) <= MAX_CONTACT:
        return False
    if not all(0x21 <= ord(char) <= 0x7E for char in contact):
        return False
    if contact.startswith("https://"):
        return len(contact) > len("https://x.y") and "@" not in contact.split("/")[2]
    return _EMAIL.fullmatch(contact) is not None


MAX_REWRITE_TIMEOUT = 300.0
_COOKIE_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


@dataclass(frozen=True, slots=True)
class Profile:
    """What a visitor may do. The defaults are the cautious ones."""

    name: str = "personal"
    allow_images: bool = False
    allow_fonts: bool = True
    show_entities: bool = False  # list the wallets, emails and onion addresses a page names
    send_entities: bool = False  # let the visitor send that list on to the entity sink
    allow_post_forms: bool = True
    allow_uploads: bool = False
    allow_password_fields: bool = True
    max_page_bytes: int = 5_000_000
    max_asset_bytes: int = 10_000_000
    rewrite_timeout: float = 15.0
    max_requests_per_minute: int | None = None  # per session, every request counts; None: no limit
    daily_quota: int | None = None  # per account and day, in the units the two costs add up to
    open_cost: int = 1  # taken when an address is opened
    page_cost: int = 0  # taken for every web page that comes back

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("a profile needs a name")
        if self.max_requests_per_minute is not None and self.max_requests_per_minute < 1:
            raise ValueError("the request limit must be at least 1")
        if self.open_cost < 0 or self.page_cost < 0:
            raise ValueError("costs cannot be negative")
        if self.send_entities and not self.show_entities:
            raise ValueError(
                "send_entities needs show_entities, since the visitor sends what is shown"
            )
        self._check_numbers()
        if self.daily_quota is not None:
            if self.daily_quota < 1:
                raise ValueError("the daily quota must be at least 1")
            if self.open_cost == 0 and self.page_cost == 0:
                raise ValueError("a daily quota needs a cost, or nothing ever uses it up")

    def _check_numbers(self) -> None:
        """The sizes and times must be above zero, since zero or less can switch a cap off."""
        for label, number in (
            ("max_page_bytes", self.max_page_bytes),
            ("max_asset_bytes", self.max_asset_bytes),
        ):
            if number < 1:
                raise ValueError(f"{label} must be at least 1")
            if number > MAX_PROFILE_BYTES:
                raise ValueError(f"{label} is too large")
        if self.rewrite_timeout <= 0:
            raise ValueError("rewrite_timeout must be above zero")
        largest = max(
            self.open_cost, self.page_cost, self.max_requests_per_minute or 0, self.daily_quota or 0
        )
        if self.rewrite_timeout > MAX_REWRITE_TIMEOUT or largest > 10**9:
            raise ValueError("a limit, cost or quota is too large")

    def text_only(self) -> Profile:
        """This profile with everything risky turned off, for sites nobody has rated."""
        return replace(
            self,
            allow_images=False,
            allow_fonts=False,
            allow_post_forms=False,
            allow_uploads=False,
            allow_password_fields=False,
        )

    @classmethod
    def restricted(cls) -> Profile:
        """Text only, no forms, no logins, no files, no images or fonts, and a request limit."""
        return cls(
            name="restricted",
            allow_images=False,
            allow_fonts=False,
            allow_post_forms=False,
            allow_uploads=False,
            allow_password_fields=False,
            max_page_bytes=2_000_000,
            max_asset_bytes=2_000_000,
            max_requests_per_minute=60,
        )


@dataclass(frozen=True, slots=True)
class Settings:
    base_domain: str
    scheme: str = "https"
    port: int | None = None
    audience: str = "onionglass"
    session_ttl: float = 8 * 3600
    cookie_name: str = "og_session"
    profile: Profile = field(default_factory=Profile)
    profiles: Mapping[str, Profile] = field(default_factory=dict)
    max_request_body: int = 1_000_000
    max_labels_per_session: int = 1000
    max_labels_per_page: int = 100
    max_new_sessions_per_minute: int = 30
    max_concurrent_fetches: int = 32
    max_fetches_per_session: int = 6
    max_opens_per_session: int = 100
    keys: KeyRing | None = None
    open_mode: bool = False
    policy: Policy | None = None
    kill: KillSwitch | None = None
    audit: AuditSink | None = None
    quota: QuotaMeter | None = None
    held: HeldList | None = None
    reports: ReportQueue | None = None
    max_reports_per_session: int = 10
    entity_sink: EntitySink | None = None
    max_entity_sends_per_session: int = 20
    metrics_token: str | None = None
    name_gate: NameGate | None = None
    hook_timeout: float = 2.0
    name_gate_hold_after: int = 2
    abuse_contact: str | None = None  # shown on the abuse page
    known_sites: KnownSites | None = None  # sites whose look-alikes get a warning
    confirm_sign_in: bool = True  # a sign-in link asks the visitor to confirm before it signs in

    def profile_named(self, name: str) -> Profile | None:
        """The profile a session was given, or None if this gateway does not have it."""
        if name == self.profile.name:
            return self.profile
        return self.profiles.get(name)

    def _check_limits(self) -> None:
        """Every limit must be above zero and sane. A zero or negative one would either stop the
        gateway or, worse, switch a protection off."""
        counts = {
            "max_labels_per_session": self.max_labels_per_session,
            "max_labels_per_page": self.max_labels_per_page,
            "max_opens_per_session": self.max_opens_per_session,
            "max_new_sessions_per_minute": self.max_new_sessions_per_minute,
            "max_concurrent_fetches": self.max_concurrent_fetches,
            "max_fetches_per_session": self.max_fetches_per_session,
            "max_request_body": self.max_request_body,
            "max_reports_per_session": self.max_reports_per_session,
            "max_entity_sends_per_session": self.max_entity_sends_per_session,
            "name_gate_hold_after": self.name_gate_hold_after,
        }
        for label, number in counts.items():
            if number < 1:
                raise ValueError(f"{label} must be at least 1")
        if self.max_concurrent_fetches > 1000 or self.max_request_body > 100_000_000:
            raise ValueError("a limit is too large")
        if any(n > 10_000_000 for n in counts.values() if n != self.max_request_body):
            raise ValueError("a limit is too large")
        if not 0 < self.session_ttl <= 30 * 86_400:
            raise ValueError("the session lifetime must be above zero and at most 30 days")
        if not 0 < self.hook_timeout <= 60:
            raise ValueError("hook_timeout must be above zero and at most 60 seconds")

    def __post_init__(self) -> None:
        self._check_limits()
        if self.abuse_contact is not None and not valid_contact(self.abuse_contact):
            raise ValueError("the abuse contact must be an email address or an https link")
        if self.metrics_token is not None and (
            len(self.metrics_token) < 16
            or not self.metrics_token.isascii()
            or not self.metrics_token.isprintable()
            or " " in self.metrics_token
        ):
            raise ValueError("the metrics token must be 16 or more printable characters, no spaces")
        if self.entity_sink is None and any(
            p.send_entities for p in (self.profile, *self.profiles.values())
        ):
            raise ValueError("a profile sends entities but no entity sink is configured")
        if self.name_gate is not None and self.held is None:
            raise ValueError("a name gate needs a held list, or it could only refuse once")
        if self.quota is None and any(
            p.daily_quota is not None for p in (self.profile, *self.profiles.values())
        ):
            raise ValueError("a profile has a daily quota but no quota meter is configured")
        for key, value in self.profiles.items():
            if key != value.name or key == self.profile.name:
                raise ValueError("profiles must be named by their own name, and names are unique")
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
