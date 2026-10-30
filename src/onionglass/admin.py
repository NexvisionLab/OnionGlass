# SPDX-License-Identifier: AGPL-3.0-only
"""Operator commands that work on the files the gateway already watches.

Stopping the gateway, releasing a held site and reading the report queue are things an operator
does in a hurry. These commands do them without a web interface, which would be one more thing to
defend: they edit the same plain files the gateway reads, so a change takes effect on the
gateway's next look at the file, with no restart and no new way in.

They find the files through the same config file the gateway uses, and read only the three paths
they need from it. They can be run from inside the gateway's container.
"""

from __future__ import annotations

import json
import os
import tomllib
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

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
    """Replace a file in one step, so the gateway never reads half of it."""
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        raise AdminError(f"cannot write {path.name}: {exc.strerror}") from exc


# --- the kill file -------------------------------------------------------------------------------


def _scope_line(scope: str, value: str | None) -> str:
    if scope == "all":
        return "all"
    if scope == "profile":
        if not value or " " in value or "#" in value:
            raise AdminError("a profile name is one word")
        return f"profile {value}"
    if scope == "onion":
        try:
            return f"onion {address_of(value or '')}"
        except InvalidOnionError as exc:
            raise AdminError("that is not a valid onion address") from exc
    raise AdminError("the scope must be all, profile or onion")


def _scopes_in(lines: list[str]) -> list[str]:
    return [content for line in lines if (content := line.split("#", 1)[0].strip())]


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
    lines = _read_lines(path)
    if wanted in _scopes_in(lines):
        return f"already stopped: {wanted}"
    _write_lines(path, [*lines, wanted])
    return f"stopped: {wanted}"


def kill_off(paths: AdminPaths, scope: str | None = None, value: str | None = None) -> str:
    """Take a scope out of the kill file, or with no scope remove the file and resume everything."""
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
    lines = _read_lines(path)
    kept = [line for line in lines if line.split("#", 1)[0].strip() != wanted]
    if len(kept) == len(lines):
        return f"was not stopped: {wanted}"
    _write_lines(path, kept)
    return f"resumed: {wanted}"


# --- the held list -------------------------------------------------------------------------------


def _held_address(line: str) -> str | None:
    content = line.split("#", 1)[0].strip()
    if not content:
        return None
    try:
        return address_of(content.split(None, 1)[0])
    except InvalidOnionError:
        return None


def held_list(paths: AdminPaths) -> list[str]:
    """The held sites, one line each: the address, when it was held and why."""
    lines = _read_lines(_need(paths.held, "held"))
    held = [line.strip() for line in lines if _held_address(line) is not None]
    return held or ["no sites are held"]


def held_add(paths: AdminPaths, address: str, reason: str = "by an operator") -> str:
    path = _need(paths.held, "held")
    try:
        found = address_of(address)
    except InvalidOnionError as exc:
        raise AdminError("that is not a valid onion address") from exc
    lines = _read_lines(path)
    if any(_held_address(line) == found for line in lines):
        return f"already held: {found}"
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    clean = " ".join(reason.split())[:200] or "by an operator"
    _write_lines(path, [*lines, f"{found} {stamp} {clean}"])
    return f"held: {found}"


def held_release(paths: AdminPaths, address: str) -> str:
    """Let a site be served again. Comments and other sites are left as they were."""
    path = _need(paths.held, "held")
    try:
        found = address_of(address)
    except InvalidOnionError as exc:
        raise AdminError("that is not a valid onion address") from exc
    lines = _read_lines(path)
    kept = [line for line in lines if _held_address(line) != found]
    if len(kept) == len(lines):
        return f"was not held: {found}"
    _write_lines(path, kept)
    return f"released: {found}"


# --- the reports ---------------------------------------------------------------------------------


def reports_summary(paths: AdminPaths, *, at_least: int = 1) -> list[str]:
    """Reported sites, most reported first, with how many visitors and why.

    The people who reported are not shown. The summary is for deciding what to look at.
    """
    path = _need(paths.reports, "reports")
    reporters: dict[str, set[str]] = {}
    reasons: dict[str, Counter[str]] = {}
    for number, line in enumerate(_read_lines(path), start=1):
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
        why = ", ".join(
            f"{name} {reasons[address][name]}" for name in CATEGORIES if reasons[address][name]
        )
        out.append(f"{address}  {count} visitor{'s' if count != 1 else ''}  ({why})")
    return out or ["no reports"]
