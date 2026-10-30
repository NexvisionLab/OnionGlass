# SPDX-License-Identifier: AGPL-3.0-only
"""Operator commands that work on the files the gateway already watches.

Stopping the gateway, releasing a held site and reading the report queue are things an operator
does in a hurry. These commands do them without a web interface, which would be one more thing to
defend: they edit the same plain files the gateway reads, so a change takes effect on the
gateway's next look at the file, with no restart and no new way in.

They find the files through the same config file the gateway uses, and read only the three paths
they need from it. They can be run from inside the gateway's container.

The held list and the report queue are only ever added to, by the gateway and by these commands
alike, so neither can lose a line the other writes at the same moment. Only the kill file is
replaced, and the gateway never writes it.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
import tomllib
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from onionglass.files import append_line, tail_is_torn
from onionglass.held import RELEASE, hold_line, is_held_line, parse_line, release_line
from onionglass.killswitch import parse_kill_file
from onionglass.onion import InvalidOnionError
from onionglass.policy import address_of
from onionglass.reports import CATEGORIES


class AdminError(Exception):
    """The command cannot be carried out. The message says why."""


@dataclass(frozen=True, slots=True)
class AdminPaths:
    kill: Path | None
    held: Path | None
    reports: Path | None


def paths_from_config(config: str | Path) -> AdminPaths:
    """The kill file, held list and report file named by a config file."""
    path = Path(config)
    try:
        data = tomllib.loads(path.read_bytes().decode("utf-8"))
    except OSError as exc:
        raise AdminError(f"cannot read {path}: {exc.strerror}") from exc
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise AdminError(f"{path.name} is not valid TOML") from exc
    base = path.resolve().parent

    def find(section: str) -> Path | None:
        table = data.get(section)
        file = table.get("file") if isinstance(table, dict) else None
        if not isinstance(file, str) or not file:
            return None
        found = Path(file)
        return found if found.is_absolute() else base / found

    return AdminPaths(find("kill"), find("held"), find("reports"))


def _need(path: Path | None, section: str) -> Path:
    if path is None:
        raise AdminError(f"this config has no [{section}] section with a file")
    return path


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError) as exc:
        raise AdminError(f"cannot read {path.name}") from exc


def _write_lines(path: Path, lines: list[str]) -> None:
    """Replace a file in one step, so the gateway never reads half of it.

    The temporary file has a name nobody can guess and is private to its owner.
    """
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            dir=path.parent, prefix=f"{path.name}.", suffix=".tmp"
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write("".join(f"{line}\n" for line in lines))
        os.replace(temporary, path)
    except OSError as exc:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
        raise AdminError(f"cannot write {path.name}: {exc.strerror}") from exc


# --- the kill file -------------------------------------------------------------------------------

_LOCK_WAIT = 10.0
_LOCK_STALE = 30.0


@contextlib.contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """Let one command at a time change a file by reading it and writing it back.

    Two commands that read the file together would each write back only their own change, and
    one stop would be lost. The lock is a file made with a call that fails if it already exists.
    A lock left behind by a command that was killed is removed once it is old.
    """
    lock = path.with_name(path.name + ".lock")
    deadline = time.monotonic() + _LOCK_WAIT
    while True:
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            break
        except FileExistsError:
            with contextlib.suppress(OSError):
                if time.time() - lock.stat().st_mtime > _LOCK_STALE:
                    lock.unlink()
                    continue
            if time.monotonic() > deadline:
                raise AdminError(f"{path.name} is being changed by another command") from None
            time.sleep(0.05)
        except OSError as exc:
            raise AdminError(f"cannot lock {path.name}: {exc.strerror}") from exc
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            lock.unlink()


def _canonical(content: str) -> str:
    """A scope line the way the gateway reads it, so spelling does not matter."""
    words = content.split()
    if words == ["all"]:
        return "all"
    if len(words) == 2 and words[0] == "profile":
        return f"profile {words[1]}"
    if len(words) == 2 and words[0] == "onion":
        try:
            return f"onion {address_of(words[1])}"
        except InvalidOnionError:
            return content
    return content


def _scope_line(scope: str, value: str | None) -> str:
    if scope == "all":
        return "all"
    if scope == "profile":
        if not value or not value.isprintable() or any(c.isspace() or c == "#" for c in value):
            raise AdminError("a profile name is one word")
        return f"profile {value}"
    if scope == "onion":
        try:
            return f"onion {address_of(value or '')}"
        except InvalidOnionError as exc:
            raise AdminError("that is not a valid onion address") from exc
    raise AdminError("the scope must be all, profile or onion")


def _scopes_in(lines: list[str]) -> list[str]:
    return [_canonical(content) for line in lines if (content := line.split("#", 1)[0].strip())]


def kill_status(paths: AdminPaths) -> list[str]:
    """What the kill file says, in plain lines."""
    path = _need(paths.kill, "kill")
    if not path.exists():
        return ["not stopped: there is no kill file"]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ["the kill file cannot be read, which stops the whole gateway"]
    state = parse_kill_file(text)
    if state.broken:
        return ["the kill file has a line nobody understands, which stops the whole gateway"]
    scopes = _scopes_in(text.splitlines())
    if not scopes:
        return ["not stopped: the kill file is empty"]
    return ["stopped:", *[f"  {scope}" for scope in scopes]]


def kill_on(paths: AdminPaths, scope: str, value: str | None = None) -> str:
    """Add a scope to the kill file. Returns what happened."""
    path = _need(paths.kill, "kill")
    wanted = _scope_line(scope, value)
    with _exclusive(path):
        lines = _read_lines(path)
        if wanted in _scopes_in(lines):
            return f"already stopped: {wanted}"
        _write_lines(path, [*lines, wanted])
    return f"stopped: {wanted}"


def kill_off(paths: AdminPaths, scope: str | None = None, value: str | None = None) -> str:
    """Take a scope out of the kill file, or with no scope remove the file and resume everything.

    A scope is matched the way the gateway reads it, so a line written by hand with different
    capitals or spacing is found too.
    """
    path = _need(paths.kill, "kill")
    if scope is None:
        try:
            path.unlink()
        except FileNotFoundError:
            return "nothing to resume: there is no kill file"
        except OSError as exc:
            raise AdminError(f"cannot remove {path.name}: {exc.strerror}") from exc
        return "resumed: the kill file is removed"
    wanted = _scope_line(scope, value)
    with _exclusive(path):
        lines = _read_lines(path)
        kept = [line for line in lines if _canonical(line.split("#", 1)[0].strip()) != wanted]
        if len(kept) == len(lines):
            return f"was not stopped: {wanted}"
        _write_lines(path, kept)
    return f"resumed: {wanted}"


# --- the held list -------------------------------------------------------------------------------


def _currently_held(lines: list[str]) -> dict[str, str]:
    """The sites a held file holds now, each with the line that held it, oldest first."""
    held: dict[str, str] = {}
    for line in lines:
        try:
            parsed = parse_line(line)
        except InvalidOnionError:
            continue  # a line nobody can read says nothing
        if parsed is None:
            continue
        action, address = parsed
        held.pop(address, None)
        if action != RELEASE:
            held[address] = line.strip()
    return held


def held_list(paths: AdminPaths) -> list[str]:
    """The held sites, one line each: the address, when it was held and why."""
    held = _currently_held(_read_lines(_need(paths.held, "held")))
    return list(held.values()) or ["no sites are held"]


def _checked_address(address: str) -> str:
    try:
        return address_of(address)
    except InvalidOnionError as exc:
        raise AdminError("that is not a valid onion address") from exc


def _append(path: Path, line: str) -> None:
    try:
        append_line(path, line, is_held_line)
    except OSError as exc:
        raise AdminError(f"cannot write {path.name}: {exc.strerror}") from exc


def held_add(paths: AdminPaths, address: str, reason: str = "by an operator") -> str:
    path = _need(paths.held, "held")
    found = _checked_address(address)
    if found in _currently_held(_read_lines(path)):
        return f"already held: {found}"
    _append(path, hold_line(found, reason or "by an operator"))
    return f"held: {found}"


def held_release(paths: AdminPaths, address: str) -> str:
    """Let a site be served again, by adding a line that says so. Nothing is rewritten."""
    path = _need(paths.held, "held")
    found = _checked_address(address)
    if found not in _currently_held(_read_lines(path)):
        return f"was not held: {found}"
    _append(path, release_line(found))
    return f"released: {found}"


# --- the reports ---------------------------------------------------------------------------------


def _torn_report(path: Path) -> bool:
    try:
        return tail_is_torn(path.read_bytes(), _looks_like_report)
    except OSError:
        return False


def _looks_like_report(line: str) -> bool:
    try:
        record = json.loads(line)
        return "address" in record and "subject" in record and "category" in record
    except (ValueError, TypeError):
        return False


def reports_summary(paths: AdminPaths, *, at_least: int = 1) -> list[str]:
    """Reported sites, most reported first, with how many visitors and why.

    The people who reported are not shown. The summary is for deciding what to look at.
    """
    path = _need(paths.reports, "reports")
    reporters: dict[str, set[str]] = {}
    reasons: dict[str, Counter[str]] = {}
    lines = _read_lines(path)
    if lines and _torn_report(path):
        lines = lines[:-1]  # a report cut off by a crash was never finished
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            address, subject = str(record["address"]), str(record["subject"])
            category = str(record["category"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AdminError(f"{path.name}: line {number} is not a report") from exc
        reporters.setdefault(address, set()).add(subject)
        reasons.setdefault(address, Counter())[category] += 1
    ranked = sorted(reporters, key=lambda a: (-len(reporters[a]), a))
    out = []
    for address in ranked:
        count = len(reporters[address])
        if count < at_least:
            continue
        counted = reasons[address]
        why = ", ".join(f"{name} {counted[name]}" for name in CATEGORIES if counted[name])
        out.append(f"{address}  {count} visitor{'s' if count != 1 else ''}  ({why})")
    return out or ["no reports"]
