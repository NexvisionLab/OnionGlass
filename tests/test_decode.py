# SPDX-License-Identifier: AGPL-3.0-only
"""Decoding of compressed bodies, with a hard output limit."""

from __future__ import annotations

import gzip
import zlib

import pytest

from onionglass.decode import DecodeError, decode_body

PAYLOAD = b"<html><body>hello world</body></html>" * 20
LIMIT = 100_000


def raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()


def test_identity_and_missing_encoding() -> None:
    assert decode_body(PAYLOAD, None, max_output=LIMIT) == PAYLOAD
    assert decode_body(PAYLOAD, "", max_output=LIMIT) == PAYLOAD
    assert decode_body(PAYLOAD, "identity", max_output=LIMIT) == PAYLOAD


def test_gzip_deflate_and_raw_deflate() -> None:
    assert decode_body(gzip.compress(PAYLOAD), "gzip", max_output=LIMIT) == PAYLOAD
    assert decode_body(gzip.compress(PAYLOAD), "GZIP", max_output=LIMIT) == PAYLOAD
    assert decode_body(gzip.compress(PAYLOAD), "x-gzip", max_output=LIMIT) == PAYLOAD
    assert decode_body(zlib.compress(PAYLOAD), "deflate", max_output=LIMIT) == PAYLOAD
    assert decode_body(raw_deflate(PAYLOAD), "deflate", max_output=LIMIT) == PAYLOAD


def test_stacked_encodings_are_undone_in_reverse_order() -> None:
    twice = zlib.compress(gzip.compress(PAYLOAD))
    assert decode_body(twice, "gzip, deflate", max_output=LIMIT) == PAYLOAD


def test_a_small_body_that_expands_past_the_limit_is_refused() -> None:
    bomb = gzip.compress(b"\x00" * 5_000_000)
    assert len(bomb) < 10_000
    with pytest.raises(DecodeError) as info:
        decode_body(bomb, "gzip", max_output=LIMIT)
    assert info.value.kind == "too_large"


def test_a_limit_just_above_and_below_the_decoded_size() -> None:
    body = b"a" * 1000
    assert decode_body(gzip.compress(body), "gzip", max_output=1000) == body
    with pytest.raises(DecodeError) as info:
        decode_body(gzip.compress(body), "gzip", max_output=999)
    assert info.value.kind == "too_large"


def test_an_oversized_plain_body_is_refused() -> None:
    with pytest.raises(DecodeError) as info:
        decode_body(b"a" * 101, None, max_output=100)
    assert info.value.kind == "too_large"


def test_corrupt_data_is_reported_as_corrupt() -> None:
    for encoding in ("gzip", "deflate"):
        with pytest.raises(DecodeError) as info:
            decode_body(b"this is not compressed", encoding, max_output=LIMIT)
        assert info.value.kind == "corrupt"
    with pytest.raises(DecodeError) as info:
        decode_body(gzip.compress(PAYLOAD)[:-10], "gzip", max_output=LIMIT)
    assert info.value.kind == "corrupt"  # a stream cut short is never accepted as complete


@pytest.mark.parametrize("encoding", ["br", "zstd", "compress", "gzip, gzip, gzip", "gzip, br"])
def test_unsupported_encodings_are_refused(encoding: str) -> None:
    with pytest.raises(DecodeError) as info:
        decode_body(gzip.compress(PAYLOAD), encoding, max_output=LIMIT)
    assert info.value.kind == "unsupported"
