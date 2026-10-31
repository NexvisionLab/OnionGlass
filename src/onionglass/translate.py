# SPDX-License-Identifier: AGPL-3.0-only
"""Translation of the text of a page, by a service the operator runs.

The gateway asks a LibreTranslate-style service (``POST <base>/translate`` with a JSON body) to
translate the text a visitor is reading. The service is a separate program and is trusted with
the page text and nothing else: it is never told the onion address, the title, the visitor or the
session, and what it answers is checked before it is used. Whatever it returns is inserted as
text by the caller, never as markup.

Translation is a convenience, not a safety check, so a failure here never stops a page: the
caller shows the original text and says so.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from typing import Any, Protocol

import h11

from onionglass import httpexchange as exchange
from onionglass.hooks import HookTarget, parse_hook_url

MAX_REPLY = 2_000_000
MAX_TEXTS_PER_CALL = 100
MAX_ANSWER_CHARS = 1_000_000
MAX_CHARS_PER_CALL = 20_000
MAX_TIMEOUT = 300.0
MAX_KEY = 256
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[A-Za-z]{2,4})?")


class TranslateError(Exception):
    """The text could not be translated."""


class Translator(Protocol):
    """Anything that can translate a list of texts, keeping their order and their number."""

    async def translate(self, texts: list[str]) -> list[str]: ...


def _chunks(texts: list[str]) -> list[list[str]]:
    """Split the texts into calls that are not too many or too long, keeping their order."""
    calls: list[list[str]] = []
    current: list[str] = []
    size = 0
    for text in texts:
        if current and (
            len(current) >= MAX_TEXTS_PER_CALL or size + len(text) > MAX_CHARS_PER_CALL
        ):
            calls.append(current)
            current, size = [], 0
        current.append(text)
        size += len(text)
    if current:
        calls.append(current)
    return calls


class LibreTranslate:
    """A translator that asks a LibreTranslate-compatible service. Source language is detected."""

    def __init__(  # noqa: PLR0913 - an address, a language, a key, a limit and how to reach it
        self,
        url: str,
        *,
        target: str = "en",
        api_key: str | None = None,
        timeout: float = 20.0,
        allow_plain_http: bool = False,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        try:
            self._target_address: HookTarget = parse_hook_url(
                url, allow_plain_http=allow_plain_http
            )
        except ValueError as exc:
            raise ValueError(str(exc).replace("hook", "translation service")) from exc
        if _LANGUAGE.fullmatch(target) is None:
            raise ValueError("the target language must be a code such as en, de or pt-BR")
        if api_key is not None and (
            not 1 <= len(api_key) <= MAX_KEY or not all(0x21 <= ord(c) <= 0x7E for c in api_key)
        ):
            raise ValueError("the translation API key must be printable text with no spaces")
        if not 0 < timeout <= MAX_TIMEOUT:
            raise ValueError("the translation timeout must be above zero and at most 300 seconds")
        self._language = target
        self._api_key = api_key
        self._timeout = timeout
        self._tls: ssl.SSLContext | None = None
        if self._target_address.scheme == "https":
            context = tls_context or ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._tls = context

    def __repr__(self) -> str:
        address = self._target_address
        return f"LibreTranslate({address.scheme}://{address.host}:{address.port}{address.prefix})"

    async def translate(self, texts: list[str]) -> list[str]:
        """The translations, in the same order and number. Raises ``TranslateError``."""
        if not texts:
            return []
        try:
            return await asyncio.wait_for(self._translate_all(texts), timeout=self._timeout)
        except TimeoutError as exc:
            raise TranslateError("the translation service took too long") from exc

    async def _translate_all(self, texts: list[str]) -> list[str]:
        done: list[str] = []
        total = 0
        for chunk in _chunks(texts):
            answers = await self._call(chunk)
            total += sum(len(answer) for answer in answers)
            if total > MAX_ANSWER_CHARS:
                raise TranslateError("the translation service returned too much text")
            done.extend(answers)
        return done

    async def _call(self, texts: list[str]) -> list[str]:
        request: dict[str, Any] = {
            "q": texts,
            "source": "auto",
            "target": self._language,
            "format": "text",
        }
        if self._api_key is not None:
            request["api_key"] = self._api_key
        body = json.dumps(request, separators=(",", ":")).encode("utf-8")
        address = self._target_address
        default = 443 if address.scheme == "https" else 80
        host = f"[{address.host}]" if ":" in address.host else address.host
        headers = [
            (b"host", (host if address.port == default else f"{host}:{address.port}").encode()),
            (b"user-agent", b"onionglass-translate/1"),
            (b"content-type", b"application/json"),
            (b"accept", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"connection", b"close"),
        ]
        try:
            status, _, reply = await exchange.post(
                address.host,
                address.port,
                self._tls,
                f"{address.prefix}/translate",
                headers=headers,
                body=body,
                max_reply=MAX_REPLY,
            )
        except exchange.ExchangeError as exc:
            raise TranslateError(f"the translation service's {exc}") from exc
        except (OSError, ssl.SSLError, h11.ProtocolError) as exc:
            raise TranslateError(
                f"the translation service could not be reached: {type(exc).__name__}"
            ) from exc
        if status != 200:
            raise TranslateError(f"the translation service answered with status {status}")
        return self._checked(texts, reply)

    @staticmethod
    def _checked(texts: list[str], reply: bytes) -> list[str]:
        try:
            data = json.loads(reply)
        except ValueError as exc:
            raise TranslateError("the translation service's reply is not JSON") from exc
        found = data.get("translatedText") if isinstance(data, dict) else None
        if not isinstance(found, list) or len(found) != len(texts):
            raise TranslateError("the translation service did not return one text for each")
        for original, translated in zip(texts, found, strict=True):
            if not isinstance(translated, str):
                raise TranslateError("the translation service returned something that is not text")
            try:
                translated.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise TranslateError(
                    "the translation service returned text that cannot be used"
                ) from exc
            if len(translated) > 20 * len(original) + 1000:
                raise TranslateError("a translation is too long for the text it came from")
        return [str(t) for t in found]
