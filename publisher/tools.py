# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Locate and run the external programs the publisher depends on.

Programs run as argument arrays, never through a shell, with no standard input, a timeout, a
bounded copy of their output and a minimal environment, so nothing inherited from the caller
(COSIGN_*, SIGSTORE_*, TUF_*, GNUPGHOME, proxy settings) can change what a check means.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

SEARCH_PATH: Final = "/usr/local/bin:/usr/bin:/bin"
CHILD_PATH: Final = "/usr/bin:/bin"
MAX_OUTPUT_BYTES: Final = 64 * 1024
DEFAULT_TIMEOUT_SECONDS: Final = 60.0
POLL_SECONDS: Final = 0.01


class ToolError(Exception):
    """A program is missing or unusable; this affects the whole run, not one release."""


class ToolTimeout(ToolError):
    """A program ran past its time limit."""


class ToolOutputLimit(ToolError):
    """A program wrote more output than allowed and was stopped."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Tools:
    """Absolute paths of the programs the verifier runs."""

    apt_ftparchive: Path
    cosign: Path
    createrepo_c: Path
    dpkg_deb: Path
    gpg: Path
    rpm: Path
    rpmkeys: Path

    @classmethod
    def locate(cls, search_path: str = SEARCH_PATH) -> Tools:
        """Find each program in `search_path`, by default the fixed system directories."""
        found: dict[str, Path] = {}
        for field, program in (
            ("apt_ftparchive", "apt-ftparchive"),
            ("cosign", "cosign"),
            ("createrepo_c", "createrepo_c"),
            ("dpkg_deb", "dpkg-deb"),
            ("gpg", "gpg"),
            ("rpm", "rpm"),
            ("rpmkeys", "rpmkeys"),
        ):
            path = shutil.which(program, path=search_path)
            if path is None:
                raise ToolError(f"{program} is not installed in {search_path}")
            found[field] = Path(path)
        return cls(**found)


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    code: int
    stdout: str
    stderr: str


def _read(handle: IO[bytes]) -> str:
    handle.seek(0)
    return handle.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")


def _flooded(*handles: IO[bytes]) -> bool:
    return any(os.fstat(handle.fileno()).st_size > MAX_OUTPUT_BYTES for handle in handles)


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    """Kill every process the program started: it leads its own process group."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _stop(process: subprocess.Popen[bytes]) -> None:
    _kill_group(process)
    process.wait()


def run(
    args: Sequence[str | Path],
    *,
    home: Path,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    env: Mapping[str, str] | None = None,
) -> Result:
    """Run one program; stop it if it runs too long or writes more than MAX_OUTPUT_BYTES.

    Output goes to unnamed temporary files that are checked every few milliseconds, so a
    program that floods its output is killed after a bounded amount, not after filling memory.
    The program runs in its own process group, and the whole group is killed when it ends or
    is stopped, so nothing it started keeps running or writing.
    """
    command = [os.fspath(argument) for argument in args]
    name = Path(command[0]).name
    environment = {"PATH": CHILD_PATH, "LC_ALL": "C", "HOME": os.fspath(home), **(env or {})}
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(  # noqa: S603
                command,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                env=environment,
                start_new_session=True,
            )
        except OSError as error:
            raise ToolError(f"cannot run {command[0]}: {error.strerror or error}") from error
        while True:
            try:
                code = process.wait(timeout=POLL_SECONDS)
                _kill_group(process)
                break
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() > deadline:
                _stop(process)
                raise ToolTimeout(f"{name} took longer than {timeout:g}s")
            if _flooded(out, err):
                _stop(process)
                raise ToolOutputLimit(f"{name} wrote more output than allowed")
        if _flooded(out, err):
            raise ToolOutputLimit(f"{name} wrote more output than allowed")
        return Result(code=code, stdout=_read(out), stderr=_read(err))
