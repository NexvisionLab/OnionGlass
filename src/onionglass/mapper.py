# SPDX-License-Identifier: AGPL-3.0-only
"""The URL mapper used while rewriting, which defers label creation until the rewrite is done.

Labels live in the session store, and the rewriter is synchronous and may run in a thread or a
separate process. So the rewriter writes placeholder host names, and once it has finished the
placeholders are replaced with the real labels. The placeholders contain a random value chosen
per page, so a page cannot forge one.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from urllib.parse import quote, urlsplit

from onionglass.onion import OnionOrigin
from onionglass.settings import Settings

MAX_ORIGINS_PER_PAGE = 2000


class PlaceholderMapper:
    """Implements ``UrlMapper`` with placeholders for onion origins."""

    def __init__(self, settings: Settings, nonce: str | None = None) -> None:
        self._settings = settings
        self._nonce = nonce or secrets.token_hex(16)
        self._suffix = f".{self._nonce}.invalid"
        self._indexes: dict[OnionOrigin, int] = {}
        self._port = f":{settings.port}" if settings.port is not None else ""
        self._external_prefix = f"{settings.apex_origin}/_og/external?u="

    # --- the UrlMapper interface -------------------------------------------------------------

    def onion(self, origin: OnionOrigin) -> str:
        index = self._indexes.get(origin)
        if index is None:
            if len(self._indexes) >= MAX_ORIGINS_PER_PAGE:
                raise ValueError("page names too many different onion sites")
            index = len(self._indexes)
            self._indexes[origin] = index
        return f"{self._settings.scheme}://p{index}{self._suffix}{self._port}"

    def external(self, url: str) -> str:
        return self._external_prefix + quote(url, safe="")

    def owns(self, url: str) -> bool:
        if url == "" or url.startswith("#"):
            return True
        if url.startswith(self._external_prefix):
            return True
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return False
        if parts.scheme != self._settings.scheme or not parts.hostname:
            return False
        host = parts.hostname
        if not host.endswith(self._suffix):
            return False
        label = host[: -len(self._suffix)]
        expected = self._settings.port
        return label.startswith("p") and label[1:].isdigit() and port == expected

    # --- after the rewrite ------------------------------------------------------------------

    def origins(self) -> list[OnionOrigin]:
        return list(self._indexes)

    def substitute(self, text: str, labels: Mapping[OnionOrigin, str]) -> str:
        """Replace every placeholder with its label, or with a blocked-link address if none."""
        settings = self._settings
        for origin, index in self._indexes.items():
            placeholder_host = f"p{index}{self._suffix}"
            label = labels.get(origin)
            if label is None:
                prefix = f"{settings.scheme}://{placeholder_host}{self._port}"
                text = text.replace(prefix, f"{settings.apex_origin}/_og/blocked")
            else:
                text = text.replace(placeholder_host, f"{label}.{settings.base_domain}")
        return text
