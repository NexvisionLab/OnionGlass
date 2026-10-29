# SPDX-License-Identifier: AGPL-3.0-only
"""Decoding of compressed response bodies, with a hard limit on the decoded size.

A small compressed body can expand to gigabytes. Decoding stops as soon as the limit is passed,
so memory use stays bounded whatever the page contains.
"""

from __future__ import annotations

import zlib

MAX_ENCODINGS = 2
_GZIP_WINDOW = 31
_ZLIB_WINDOW = 15
_RAW_WINDOW = -15


class DecodeError(Exception):
    """The body cannot be decoded. ``kind`` is ``too_large``, ``unsupported`` or ``corrupt``."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def _inflate(data: bytes, window: int, max_output: int) -> bytes:
    decompressor = zlib.decompressobj(window)
    output = decompressor.decompress(data, max_output + 1)
    if len(output) > max_output or decompressor.unconsumed_tail:
        raise DecodeError("too_large")
    output += decompressor.flush()
    if len(output) > max_output:
        raise DecodeError("too_large")
    if not decompressor.eof:
        # The stream ended early. A cut-off page must not be passed on as if it were complete.
        raise DecodeError("corrupt")
    return output


def _deflate(data: bytes, max_output: int) -> bytes:
    """Servers disagree on what ``deflate`` means: zlib-wrapped or raw. Try both."""
    try:
        return _inflate(data, _ZLIB_WINDOW, max_output)
    except zlib.error:
        return _inflate(data, _RAW_WINDOW, max_output)


def decode_body(body: bytes, content_encoding: str | None, *, max_output: int) -> bytes:
    """Undo the content encoding of a response body."""
    if len(body) > max_output and not content_encoding:
        raise DecodeError("too_large")
    encodings = [e.strip().lower() for e in (content_encoding or "").split(",") if e.strip()]
    if len(encodings) > MAX_ENCODINGS:
        raise DecodeError("unsupported")
    data = body
    for encoding in reversed(encodings):
        try:
            if encoding in ("gzip", "x-gzip"):
                data = _inflate(data, _GZIP_WINDOW, max_output)
            elif encoding == "deflate":
                data = _deflate(data, max_output)
            elif encoding == "identity":
                continue
            else:
                raise DecodeError("unsupported")
        except zlib.error as exc:
            raise DecodeError("corrupt") from exc
    if len(data) > max_output:
        raise DecodeError("too_large")
    return data
