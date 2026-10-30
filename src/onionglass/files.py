# SPDX-License-Identifier: AGPL-3.0-only
"""Appending to the gateway's record files without making one crash into a permanent problem.

The quota journal, the report queue and the held list are plain files with one record per line,
and the gateway only ever adds to them. A crash or a full disk in the middle of an append leaves
a half line at the end. Two things must then be true. Reading must not refuse to start because of
it, and the next append must not stick onto the half line and turn it into a bad line in the
middle of the file, which would break the next start.

``append_line`` makes the second true, and ``tail_is_torn`` the first.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

_WINDOW = 65_536


def tail_is_torn(data: bytes, is_valid: Callable[[str], bool]) -> bool:
    """True if the last line has no line break after it and is not a whole record."""
    if not data or data.endswith(b"\n"):
        return False
    last = data.rsplit(b"\n", 1)[-1].decode("utf-8", errors="replace")
    return not is_valid(last)


def append_line(path: Path, line: str, is_valid: Callable[[str], bool]) -> None:
    """Add one line to a file, first making sure the file ends on a line break.

    If the last line is cut off, it is dropped, because a record that was never finished was never
    in force. If it is whole but only lacks its line break, for example when someone edited the
    file by hand, it is kept and the break is added.
    """
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        size = os.fstat(descriptor).st_size
        prefix = b""
        if size:
            window = min(size, _WINDOW)
            os.lseek(descriptor, size - window, os.SEEK_SET)
            tail = os.read(descriptor, window)
            if not tail.endswith(b"\n"):
                cut = tail.rfind(b"\n") + 1
                partial = tail[cut:].decode("utf-8", errors="replace")
                if is_valid(partial):
                    prefix = b"\n"
                elif cut or window == size:
                    os.ftruncate(descriptor, size - window + cut)
                else:
                    prefix = b"\n"  # a line over the window is not a record, but is not ours to cut
        os.write(descriptor, prefix + line.encode("utf-8") + b"\n")
    finally:
        os.close(descriptor)
