# SPDX-License-Identifier: AGPL-3.0-only
"""The gateway against the real Tor network, on two harmless public sites.

These tests are skipped unless a real Tor is named in the environment, because they need the
internet and take time. To run them, start a Tor client and say where its SOCKS port is::

    ONIONGLASS_TEST_TOR=127.0.0.1:9050 pytest tests/test_live_tor.py

Only the Tor Project's and DuckDuckGo's public onion sites are used. Nothing here may ever name
another site: the repository holds no address that could lead to harmful material.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from helpers import DUCKDUCKGO, TOR_PROJECT
from onionglass.gateway import Gateway
from onionglass.headers import upstream_request_headers
from onionglass.onion import parse_onion_url
from onionglass.settings import Profile, Settings
from onionglass.upstream import TorConfig, TorFetcher, UpstreamError, UpstreamRequest

SOCKS = os.environ.get("ONIONGLASS_TEST_TOR", "")
pytestmark = [
    pytest.mark.network,
    pytest.mark.timeout(300),
    pytest.mark.skipif(not SOCKS, reason="set ONIONGLASS_TEST_TOR=host:port to use a real Tor"),
]

PORT = 8765
IFRAME = {"sec-fetch-site": "same-origin", "sec-fetch-dest": "iframe", "sec-fetch-mode": "navigate"}


def fetcher() -> TorFetcher:
    host, _, port = SOCKS.rpartition(":")
    return TorFetcher(
        TorConfig(socks_host=host, socks_ports=(int(port),), total_timeout=120, read_timeout=90)
    )


def client() -> TestClient:
    settings = Settings(
        base_domain="localhost",
        scheme="http",
        port=PORT,
        open_mode=True,
        profile=Profile(name="personal"),
    )
    gateway = Gateway(settings, fetcher=fetcher())
    return TestClient(gateway.app, base_url=f"http://localhost:{PORT}", follow_redirects=False)


def label_in(location: str) -> str:
    found = re.search(r"l=([a-z2-7]{26})", location)
    assert found, location
    return found.group(1)


def an_address_nobody_runs() -> str:
    """A well-formed address from a real key, so Tor accepts it and finds nothing behind it."""
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    checksum = hashlib.sha3_256(b".onion checksum" + key + b"\x03").digest()[:2]
    return base64.b32encode(key + checksum + b"\x03").decode().lower()


def test_the_tor_client_reads_a_real_onion_page() -> None:
    url = parse_onion_url(f"http://{TOR_PROJECT}.onion/")
    request = UpstreamRequest(
        origin=url.origin,
        method="GET",
        target="/",
        headers=upstream_request_headers(url.origin, method="GET"),
        isolation_key="live-test",
        body=b"",
    )
    reply = asyncio.run(fetcher().fetch(request))
    assert reply.status == 200 and len(reply.body) > 1000
    assert any(k == "content-type" and v.startswith("text/html") for k, v in reply.headers)


def test_a_valid_address_with_nothing_behind_it_is_site_not_found() -> None:
    url = parse_onion_url(f"http://{an_address_nobody_runs()}.onion/")
    request = UpstreamRequest(
        origin=url.origin,
        method="GET",
        target="/",
        headers=upstream_request_headers(url.origin, method="GET"),
        isolation_key="live-test",
        body=b"",
    )
    with pytest.raises(UpstreamError) as caught:
        asyncio.run(fetcher().fetch(request))
    assert caught.value.kind == "descriptor_not_found"


def test_the_whole_gateway_shows_a_real_page_safely() -> None:
    web = client()
    opened = web.post(
        "/open", data={"address": f"{TOR_PROJECT}.onion"}, headers={"sec-fetch-site": "same-origin"}
    )
    label = label_in(opened.headers["location"])
    page = web.get("/", headers={"host": f"{label}.localhost:{PORT}", **IFRAME})
    assert page.status_code == 200 and "Tor Project" in page.text
    assert not re.search(r"<script", page.text, re.IGNORECASE)
    assert "sandbox" in page.headers["content-security-policy"]
    # Every address in the page is on the gateway. Nothing points at the open internet.
    for found in re.findall(r'(?:href|src|action)="(https?://[^"]+)"', page.text):
        host = urlsplit(found).hostname or ""
        assert host == "localhost" or host.endswith(".localhost"), found
    assert web.get("/_og/current").json()["title"].startswith("Tor Project")


def test_an_https_redirect_between_onions_is_followed_through_the_gateway() -> None:
    web = client()
    opened = web.post(
        "/open", data={"address": f"{DUCKDUCKGO}.onion"}, headers={"sec-fetch-site": "same-origin"}
    )
    label = label_in(opened.headers["location"])
    first = web.get("/", headers={"host": f"{label}.localhost:{PORT}", **IFRAME})
    assert first.status_code in (200, 301, 302, 307, 308)
    reply = first
    if first.status_code != 200:
        target = urlsplit(first.headers["location"])
        assert target.hostname and target.hostname.endswith(".localhost")
        reply = web.get(target.path or "/", headers={"host": target.netloc, **IFRAME})
    assert reply.status_code == 200 and "DuckDuckGo" in reply.text
    assert not re.search(r"<script", reply.text, re.IGNORECASE)
    # The page hides itself and asks scriptless browsers to go to a lighter page. The gateway
    # tells the viewer instead of following, so the visitor can see the request.
    shown = web.get("/_og/current").json()
    assert shown["refresh"].startswith("http://") and shown["refresh"].endswith("/html")
