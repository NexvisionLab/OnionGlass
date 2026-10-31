# SPDX-License-Identifier: AGPL-3.0-only
"""Find things worth noting in the text of a page: wallets, email addresses and onion addresses.

Every wallet is checked against its own checksum, so a string that only looks like an address is
not reported. A transaction hash, a random token or a made-up address does not pass. What is found
is shown to the visitor next to the page and, when the operator wires a sink, can be sent on.

It reads the text of the page after the gateway has made it safe. It never fetches anything, so
looking for an entity cannot reach out to it.

Kinds: ``email``, ``onion`` (version 3, with its checksum), ``bitcoin`` (legacy, script and
segwit), ``ethereum`` (a mixed-case address must pass its checksum) and ``monero``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from onionglass.onion import InvalidOnionError
from onionglass.policy import address_of

MAX_TEXT = 500_000
MAX_ENTITIES = 100
MAX_PER_KIND = 40
KINDS = ("email", "onion", "bitcoin", "ethereum", "monero")

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: index for index, char in enumerate(_BASE58)}
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {char: index for index, char in enumerate(_BECH32)}

_NOT_AFTER = r"(?<![A-Za-z0-9_])"
_NOT_BEFORE = r"(?![A-Za-z0-9_])"
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
    r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,5}\.[A-Za-z]{2,24}" + _NOT_BEFORE
)
_ONION = re.compile(_NOT_AFTER + r"(?:[a-z0-9-]{1,63}\.){0,3}([a-z2-7]{56})\.onion" + _NOT_BEFORE)
_LEGACY = re.compile(_NOT_AFTER + r"[13][1-9A-HJ-NP-Za-km-z]{25,34}" + _NOT_BEFORE)
_SEGWIT = re.compile(_NOT_AFTER + r"(?:bc1|BC1)[0-9A-Za-z]{11,87}" + _NOT_BEFORE)
_ETHEREUM = re.compile(_NOT_AFTER + r"0x[0-9a-fA-F]{40}" + _NOT_BEFORE)
_MONERO = re.compile(_NOT_AFTER + r"[48][1-9A-HJ-NP-Za-km-z]{94}" + _NOT_BEFORE)


@dataclass(frozen=True, slots=True)
class Entity:
    kind: str
    value: str


class SinkError(Exception):
    """The entities could not be handed on."""


@dataclass(frozen=True, slots=True)
class EntityBatch:
    """What a visitor sends on: the entities found on one page, who sent them and from where.

    The page's own text and title are never part of it.
    """

    subject: str
    group: str
    profile: str
    origin: str  # scheme://host:port of the onion site
    path: str  # path and query of the page
    entities: tuple[Entity, ...]
    time: float  # seconds since the epoch


class EntitySink(Protocol):
    """Anything that can take a batch, such as a case system. Failing raises ``SinkError``."""

    async def send(self, batch: EntityBatch) -> None: ...


# --- Keccak-256, which the Ethereum and Monero checksums need ----------------------------

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)  # fmt: skip
_ROTATIONS = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)  # fmt: skip
_MASK = (1 << 64) - 1


def _rotate(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(lanes: list[int]) -> None:
    for constant in _ROUND_CONSTANTS:
        columns = [
            lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            mixed = columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1)
            for y in range(5):
                lanes[x + 5 * y] ^= mixed
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate(lanes[x + 5 * y], _ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] = moved[x + 5 * y] ^ (
                    ~moved[(x + 1) % 5 + 5 * y] & moved[(x + 2) % 5 + 5 * y]
                )
        lanes[0] ^= constant


def keccak256(data: bytes) -> bytes:
    """The original Keccak-256, as used by Ethereum and Monero. Not the same as SHA3-256."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    lanes = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for index in range(rate // 8):
            lanes[index] ^= int.from_bytes(block[8 * index : 8 * index + 8], "little")
        _permute(lanes)
    return b"".join(lane.to_bytes(8, "little") for lane in lanes[:4])


# --- the checks ----------------------------------------------------------------------


def _base58_decode(text: str) -> bytes | None:
    number = 0
    for char in text:
        index = _BASE58_INDEX.get(char)
        if index is None:
            return None
        number = number * 58 + index
    padding = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * padding + body


def valid_bitcoin_legacy(text: str) -> bool:
    raw = _base58_decode(text)
    if raw is None or len(raw) != 25 or raw[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for bit in range(5):
            if (top >> bit) & 1:
                check ^= generators[bit]
    return check


def valid_bitcoin_segwit(text: str) -> bool:
    if text != text.lower() and text != text.upper():
        return False  # mixed case is not allowed
    lowered = text.lower()
    hrp, separator, rest = lowered.rpartition("1")
    if hrp != "bc" or not separator or len(rest) < 7 or len(lowered) > 90:
        return False
    data = [_BECH32_INDEX.get(char) for char in rest]
    if any(value is None for value in data):
        return False
    numbers = [value for value in data if value is not None]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    constant = _bech32_polymod(expanded + numbers)
    version = numbers[0]
    if version > 16:
        return False
    return constant == (1 if version == 0 else 0x2BC830A3)


def valid_ethereum(text: str) -> bool:
    digits = text[2:]
    if digits == digits.lower() or digits == digits.upper():
        return True  # no capitals to check, so there is no checksum to fail
    hashed = keccak256(digits.lower().encode("ascii")).hex()
    for char, nibble in zip(digits, hashed[: len(digits)], strict=True):
        if char.isalpha() and char.isupper() != (int(nibble, 16) >= 8):
            return False
    return True


def _monero_decode(text: str) -> bytes | None:
    """Monero writes base58 in blocks: eight characters stand for a block of eleven."""
    block_sizes = (0, 2, 3, 5, 6, 7, 9, 10, 11)  # characters for 0..8 bytes of a block
    out = bytearray()
    for start in range(0, len(text), 11):
        chunk = text[start : start + 11]
        if len(chunk) not in block_sizes:
            return None
        size = block_sizes.index(len(chunk))
        number = 0
        for char in chunk:
            index = _BASE58_INDEX.get(char)
            if index is None:
                return None
            number = number * 58 + index
        if number >> (8 * size):
            return None
        out += number.to_bytes(size, "big")
    return bytes(out)


def valid_monero(text: str) -> bool:
    raw = _monero_decode(text)
    if raw is None or len(raw) != 69 or raw[0] not in (0x12, 0x2A):
        return False
    return keccak256(raw[:65])[:4] == raw[65:]


def _onion_address(match: re.Match[str]) -> str | None:
    try:
        return address_of(match.group(1) + ".onion")
    except InvalidOnionError:
        return None


def _candidates(text: str) -> list[tuple[int, Entity]]:
    """Every entity in the text that passes its own check, with where it starts."""
    found: list[tuple[int, Entity]] = []
    for match in _EMAIL.finditer(text):
        found.append((match.start(), Entity("email", match.group().lower())))
    for match in _ONION.finditer(text):
        address = _onion_address(match)
        if address is not None:
            found.append((match.start(), Entity("onion", address + ".onion")))
    checks = (
        (_LEGACY, "bitcoin", valid_bitcoin_legacy, False),
        (_SEGWIT, "bitcoin", valid_bitcoin_segwit, True),
        (_ETHEREUM, "ethereum", valid_ethereum, False),
        (_MONERO, "monero", valid_monero, False),
    )
    for pattern, kind, check, fold in checks:
        for match in pattern.finditer(text):
            if check(match.group()):
                value = match.group().lower() if fold else match.group()
                found.append((match.start(), Entity(kind, value)))
    return found


def extract_entities(text: str) -> list[Entity]:
    """The entities in a text, each once, in the order they first appear."""
    found = _candidates(text[:MAX_TEXT])
    found.sort(key=lambda item: item[0])
    result: list[Entity] = []
    seen: set[Entity] = set()
    per_kind: dict[str, int] = {}
    for _, entity in found:
        if entity in seen or per_kind.get(entity.kind, 0) >= MAX_PER_KIND:
            continue
        seen.add(entity)
        per_kind[entity.kind] = per_kind.get(entity.kind, 0) + 1
        result.append(entity)
        if len(result) >= MAX_ENTITIES:
            break
    return result
