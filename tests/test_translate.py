# SPDX-License-Identifier: AGPL-3.0-only
"""The translation client: it asks an operator's LibreTranslate-style service for translations.

The service is a separate program, so the client must treat whatever it answers as untrusted: a
wrong count, a wrong type, a huge reply, a redirect or silence is a failure, never a result.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from onionglass.translate import LibreTranslate, TranslateError

Handler = Callable[[dict[str, Any], "Seen"], tuple[int, bytes]]


class Seen:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.paths: list[str] = []
        self.headers: list[dict[str, str]] = []


class Service:
    """A fake translation service on this machine. ``handler`` decides each answer."""

    def __init__(self) -> None:
        self.seen = Seen()
        self.handler: Handler = lambda body, _seen: (
            200,
            json.dumps({"translatedText": [f"T:{t}" for t in body["q"]]}).encode(),
        )
        seen, owner = self.seen, self

        class Request(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("content-length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                seen.requests.append(body)
                seen.paths.append(self.path)
                seen.headers.append({k.lower(): v for k, v in self.headers.items()})
                status, payload = owner.handler(body, seen)
                self.send_response(status)
                if status in (301, 302):
                    self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Request)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def service() -> Iterator[Service]:
    running = Service()
    yield running
    running.stop()


def translate(service: Service, texts: list[str], **options: Any) -> list[str]:
    client = LibreTranslate(service.url, **{"timeout": 3.0, **options})
    return asyncio.run(client.translate(texts))


def test_the_request_has_the_text_the_languages_and_nothing_about_the_visitor(
    service: Service,
) -> None:
    assert translate(service, ["Bonjour", "monde"], target="en") == ["T:Bonjour", "T:monde"]
    body = service.seen.requests[0]
    assert body == {"q": ["Bonjour", "monde"], "source": "auto", "target": "en", "format": "text"}
    assert service.seen.paths == ["/translate"]
    headers = service.seen.headers[0]
    assert headers["content-type"] == "application/json"
    assert "cookie" not in headers and "authorization" not in headers
    assert headers["user-agent"].startswith("onionglass")


def test_the_target_language_can_be_chosen(service: Service) -> None:
    translate(service, ["hola"], target="de")
    assert service.seen.requests[0]["target"] == "de"


def test_the_api_key_goes_in_the_body_when_there_is_one(service: Service) -> None:
    translate(service, ["x"], api_key="k" * 20)
    assert service.seen.requests[0]["api_key"] == "k" * 20
    translate(service, ["x"])
    assert "api_key" not in service.seen.requests[1]


def test_the_key_never_shows_in_the_object_or_in_an_error(service: Service) -> None:
    key = secrets.token_urlsafe(24)
    client = LibreTranslate(service.url, api_key=key)
    assert key not in repr(client) and key not in str(vars(client).get("url", ""))
    service.handler = lambda _b, _s: (500, b"{}")
    with pytest.raises(TranslateError) as caught:
        asyncio.run(client.translate(["x"]))
    assert key not in str(caught.value)


def test_nothing_is_sent_for_an_empty_list(service: Service) -> None:
    assert translate(service, []) == []
    assert service.seen.requests == []


def test_many_texts_go_in_several_calls_and_come_back_in_order(service: Service) -> None:
    texts = [f"text {n}" for n in range(250)]
    assert translate(service, texts) == [f"T:{t}" for t in texts]
    sizes = [len(r["q"]) for r in service.seen.requests]
    assert len(sizes) >= 3 and max(sizes) <= 100 and sum(sizes) == 250


def test_a_long_text_is_not_packed_into_one_call_with_too_much(service: Service) -> None:
    texts = ["a" * 4000 for _ in range(10)]
    translate(service, texts)
    assert all(sum(len(t) for t in r["q"]) <= 20_000 for r in service.seen.requests)


@pytest.mark.parametrize(
    ("status", "payload"),
    [
        (500, b'{"translatedText": ["x"]}'),
        (200, b"not json"),
        (200, b"[]"),
        (200, b"{}"),
        (200, b'{"translatedText": "one string"}'),
        (200, b'{"translatedText": ["only one"]}'),
        (200, b'{"translatedText": ["a", 5]}'),
        (200, b'{"translatedText": ["a", null]}'),
        (302, b'{"translatedText": ["a", "b"]}'),
        (200, b'{"error": "Invalid API key"}'),
    ],
)
def test_an_answer_that_is_not_a_clean_list_of_the_same_length_is_a_failure(
    service: Service, status: int, payload: bytes
) -> None:
    service.handler = lambda _b, _s: (status, payload)
    with pytest.raises(TranslateError):
        translate(service, ["one", "two"])


def test_a_reply_that_is_far_too_large_is_a_failure(service: Service) -> None:
    big = json.dumps({"translatedText": ["x" * 3_000_000, "y"]}).encode()
    service.handler = lambda _b, _s: (200, big)
    with pytest.raises(TranslateError, match="too large"):
        translate(service, ["one", "two"])


def test_one_translation_far_longer_than_its_text_is_a_failure(service: Service) -> None:
    service.handler = lambda b, _s: (
        200,
        json.dumps({"translatedText": ["z" * 60_000 for _ in b["q"]]}).encode(),
    )
    with pytest.raises(TranslateError, match="too long"):
        translate(service, ["short"])


def test_a_service_that_never_answers_is_a_failure(service: Service) -> None:
    def slow(body: dict[str, Any], _seen: Seen) -> tuple[int, bytes]:
        time.sleep(1.0)
        return 200, b"{}"

    service.handler = slow
    started = time.monotonic()
    with pytest.raises(TranslateError):
        translate(service, ["x"], timeout=0.2)
    assert time.monotonic() - started < 0.9


def test_a_service_that_is_not_running_is_a_failure() -> None:
    client = LibreTranslate("http://127.0.0.1:9", timeout=1.0)
    with pytest.raises(TranslateError):
        asyncio.run(client.translate(["x"]))


def test_a_path_prefix_is_kept(service: Service) -> None:
    translate_with_prefix = LibreTranslate(service.url + "/lt", timeout=3.0)
    asyncio.run(translate_with_prefix.translate(["x"]))
    assert service.seen.paths == ["/lt/translate"]


@pytest.mark.parametrize(
    "url",
    [
        "http://translate.example.net",  # plain http to another machine
        "ftp://translate.example.net",
        "https://user:pass" + "@translate.example.net",  # a name and a password in the address
        "https://translate.example.net/?a=1",
        "https://translate.example.net/ x",
        "",
    ],
)
def test_the_address_is_checked(url: str) -> None:
    with pytest.raises(ValueError, match=r"address|https|http"):
        LibreTranslate(url)


def test_plain_http_to_another_machine_needs_to_be_allowed() -> None:
    LibreTranslate("http://translate.internal.example.net", allow_plain_http=True)


@pytest.mark.parametrize("target", ["", "english", "en_US", "e", "en-", "x" * 20, "e n", "en\n"])
def test_the_target_language_is_checked(target: str) -> None:
    with pytest.raises(ValueError, match="language"):
        LibreTranslate("https://translate.example.net", target=target)


@pytest.mark.parametrize(
    "key", ["", "has space in it 123", "caf" + chr(233) + "-key-123456789", "k" * 300]
)
def test_the_api_key_is_checked(key: str) -> None:
    with pytest.raises(ValueError, match="key"):
        LibreTranslate("https://translate.example.net", api_key=key)


@pytest.mark.parametrize("timeout", [0, -1, 1000])
def test_the_timeout_is_checked(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        LibreTranslate("https://translate.example.net", timeout=timeout)
