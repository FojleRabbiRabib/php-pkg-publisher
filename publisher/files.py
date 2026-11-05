# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""File-system helpers shared by the cache, the verifier, the state store and the run lock.

POSIX only: directories must belong to the current user and be closed to everyone else, and
files are replaced atomically so a reader or a killed run never sees a half-written file.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Final

TEMPORARY_PREFIX: Final = "tmp-"


class FileError(Exception):
    """A directory is not private to the current user, or the disk cannot be used."""


def require_private_directory(path: Path) -> None:
    """Accept only a real directory owned by the current user and closed to group and others."""
    try:
        info = path.lstat()
    except OSError as error:
        raise FileError(f"{path}: cannot inspect: {error.strerror or error}") from error
    if not stat.S_ISDIR(info.st_mode):
        raise FileError(f"{path}: not a directory")
    if info.st_uid != os.geteuid():
        raise FileError(f"{path}: must be owned by the current user")
    if info.st_mode & 0o077:
        raise FileError(f"{path}: must not be accessible by group or others")


def require_free_space(path: Path, minimum: int) -> None:
    """Fail when the file system holding `path` has less than `minimum` bytes available."""
    try:
        free = shutil.disk_usage(path).free
    except OSError as error:
        raise FileError(f"{path}: cannot check free space: {error.strerror or error}") from error
    if free < minimum:
        raise FileError(f"{path}: only {free} bytes free, at least {minimum} are needed")


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_atomic(
    path: Path,
    data: bytes,
    *,
    prefix: str = TEMPORARY_PREFIX,
    mtime: float | None = None,
    mode: int = 0o600,
) -> None:
    """Replace `path` with `data`: temporary file, fsync, rename, then fsync of the directory.

    `mtime` sets the modification time before the rename, for files whose age is data. `mode` is
    the file mode, private by default; published files pass 0o644. Raises OSError; the temporary
    file is removed on failure.
    """
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=prefix)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        if mtime is not None:
            os.utime(temporary, (mtime, mtime))
        temporary.replace(path)
        sync_directory(path.parent)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def sweep_temporary(directory: Path, prefix: str, *, older_than: float) -> None:
    """Remove leftovers named `prefix*` whose modification time is before `older_than`.

    Raises OSError. Callers pick `older_than` so no live writer can still own the file.
    """
    for entry in directory.glob(f"{prefix}*"):
        if entry.lstat().st_mtime < older_than:
            entry.unlink(missing_ok=True)
