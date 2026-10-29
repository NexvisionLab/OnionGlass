# SPDX-License-Identifier: AGPL-3.0-only
"""Repository hygiene rules that must hold before anything is pushed.

The forbidden terms are stored as hashes so this file does not itself contain them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# SHA-256 of lower-case words that must not appear in any file, path or commit message.
FORBIDDEN_WORD_HASHES = frozenset(
    {
        "2f77b2a1e16891ca5c81239b4e6e46c1fbe317d05761e53d6121f4f4025fe93a",
        "004a5321959c694537c0266c71998278cfebe17666a1d87ba7ca665a17a094c4",
        "c857d09db23e6822e3600bc06ad8d58f92ed62bc8efd81c753f77048662cb97d",
        "c70eca6b0f88f44d81a41311647e50fda1ac454ec04ffd442b0eb4743a993131",
    }
)
# SHA-256 of a commit message trailer name that must not be used.
FORBIDDEN_TRAILER_HASHES = frozenset(
    {"7813670ff886c2f9397c151cf25b097663b3b1edda5c403ebf162982972b2c8e"}
)

ALLOWED_EMAIL_SUFFIX = "@users.noreply.github.com"
ALLOWED_EMAILS = frozenset({"noreply@github.com"})

WORD = re.compile(r"[a-z0-9]+")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOC_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
TEXT_SUFFIXES = {
    ".py", ".md", ".toml", ".yml", ".yaml", ".txt", ".cfg", ".ini", ".json", ".html",
    ".css", ".js", ".sh", ".service", ".conf", "",
}  # fmt: skip
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}


def _sha(word: str) -> str:
    return hashlib.sha256(word.encode()).hexdigest()


def _project_files() -> list[Path]:
    """Tracked and not-ignored files, or a directory walk when git is unavailable."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout.decode()
        return [ROOT / p for p in out.split("\0") if p and (ROOT / p).is_file()]
    except (OSError, subprocess.CalledProcessError):
        return [
            p
            for p in ROOT.rglob("*")
            if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_DIRS)
        ]


def _commit_log(fmt: str) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "log", f"--format={fmt}%x00"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout.decode()
    except (OSError, subprocess.CalledProcessError):
        return None
    return [chunk for chunk in out.split("\0") if chunk.strip()]


def _is_text(path: Path) -> bool:
    if path.name in {"LICENSE", ".gitignore", ".gitattributes", ".editorconfig"}:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def test_no_forbidden_words_in_paths() -> None:
    for path in _project_files():
        for part in path.relative_to(ROOT).parts:
            for word in WORD.findall(part.lower()):
                assert _sha(word) not in FORBIDDEN_WORD_HASHES, f"forbidden word in path {path}"


def test_no_forbidden_words_in_file_contents() -> None:
    for path in _project_files():
        if not _is_text(path):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        for word in set(WORD.findall(text)):
            assert _sha(word) not in FORBIDDEN_WORD_HASHES, f"forbidden word in {path}"


def test_no_real_looking_ip_addresses() -> None:
    for path in _project_files():
        if not _is_text(path) or path.name == "LICENSE":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in IPV4.findall(text):
            try:
                ip = ipaddress.ip_address(match)
            except ValueError:
                continue
            allowed = ip.is_loopback or ip.is_unspecified or any(ip in n for n in DOC_NETWORKS)
            assert allowed, f"address {match} in {path} is not a documentation or loopback address"


def test_commit_messages_have_no_forbidden_trailers_or_words() -> None:
    messages = _commit_log("%B")
    if messages is None:
        pytest.skip("no git history available")
    for message in messages:
        for line in message.splitlines():
            head = line.split(":", 1)[0].strip().lower() if ":" in line else ""
            assert _sha(head) not in FORBIDDEN_TRAILER_HASHES, "forbidden commit trailer"
        for word in set(WORD.findall(message.lower())):
            assert _sha(word) not in FORBIDDEN_WORD_HASHES, "forbidden word in commit message"


def test_commit_identities_are_no_reply_addresses() -> None:
    emails = _commit_log("%ae%n%ce")
    if emails is None:
        pytest.skip("no git history available")
    for chunk in emails:
        for email in chunk.split():
            ok = email.endswith(ALLOWED_EMAIL_SUFFIX) or email in ALLOWED_EMAILS
            assert ok, "commit identity is not a no-reply address"
