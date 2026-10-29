# SPDX-License-Identifier: AGPL-3.0-only
"""Basic checks on the package itself."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import onionglass

ROOT = Path(__file__).resolve().parent.parent
SPDX_LINE = "# SPDX-License-Identifier: AGPL-3.0-only"


def test_version_is_a_semantic_version() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", onionglass.__version__)


def test_version_matches_pyproject() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["version"] == onionglass.__version__


def test_package_ships_type_information() -> None:
    assert (Path(onionglass.__file__).parent / "py.typed").exists()


def test_licence_is_agpl_everywhere() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["license"] == "AGPL-3.0-only"
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_every_python_file_carries_the_licence_identifier() -> None:
    files = [*(ROOT / "src").rglob("*.py"), *(ROOT / "tests").rglob("*.py")]
    assert files
    for path in files:
        first = path.read_text(encoding="utf-8").splitlines()[0]
        assert first == SPDX_LINE, f"missing licence identifier in {path}"
