# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The exclusive run lock and the nudge file.

One run at a time holds the lock, so a webhook run and a reconcile run never overlap. A starter
that finds the lock held waits for it (up to a deadline) instead of leaving: leaving could drop
a nudge that arrives between the holder's last check and its release. The nudge file is how
the webhook receiver asks for a run; it is consumed before a pass reads anything, so a nudge
that arrives during a pass is still there afterwards and earns one more pass.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Final, TypeVar

from publisher import files

LOCK_FILE: Final = "run.lock"
WAIT_SECONDS: Final = 900.0
POLL_SECONDS: Final = 0.05
MAX_PASSES: Final = 5

T = TypeVar("T")


class LockError(Exception):
    """The lock or the nudge file cannot be used."""


class LockBusy(LockError):
    """Another run still holds the lock after the wait deadline."""


class RunLock:
    """Holds `flock` on a file in a private directory; use it as a context manager.

    The file is never removed: removing it would let a second run lock a new file while the
    first still holds the old one. It is opened close-on-exec, so tools the run starts do not
    inherit the lock.
    """

    def __init__(
        self,
        directory: Path,
        *,
        wait_seconds: float = WAIT_SECONDS,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        self._directory = directory
        self._wait = wait_seconds
        self._poll = poll_seconds
        self._descriptor: int | None = None

    @property
    def held(self) -> bool:
        return self._descriptor is not None

    def require_held(self) -> None:
        if self._descriptor is None:
            raise LockError("the run lock is not held")

    def __enter__(self) -> RunLock:
        self.acquire()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self.release()

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise LockError("the run lock is already held")
        if os.name != "posix":
            raise LockError("the run lock needs a POSIX system")
        try:
            files.require_private_directory(self._directory)
        except files.FileError as error:
            raise LockError(str(error)) from error
        path = self._directory / LOCK_FILE
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as error:
            raise LockError(f"{path}: cannot open: {error.strerror or error}") from error
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise LockError(f"{path}: must be a regular file private to the current user")
            self._wait_for(descriptor, path)
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def _wait_for(self, descriptor: int, path: Path) -> None:
        deadline = time.monotonic() + self._wait
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockBusy(f"{path}: another run still holds the lock") from None
                time.sleep(self._poll)
            except OSError as error:
                raise LockError(f"{path}: cannot lock: {error.strerror or error}") from error
            else:
                return

    def release(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            os.close(descriptor)


def busy(directory: Path) -> bool | None:
    """Whether something holds the lock (a run, or a `rollback`, `clear-pin` or `requeue`), asked
    without waiting and without creating anything.

    A lock file that does not exist yet means no run has ever held it. None means the answer
    cannot be had (the file cannot be opened or locked, for example by another user).
    """
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(directory / LOCK_FILE, flags)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    try:
        # shared, so two views never block each other; a run holds it exclusively
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return False


def take_nudge(path: Path, *, log: Callable[[str], None]) -> bool:
    """Consume the nudge file; True when a nudge was there.

    The web server's group may create entries in the nudge directory, so the nudge can be a
    directory. It is set aside under another name (it is still a request for a run, so True):
    leaving it would keep the path unit starting the service, and failing on it would stop
    every run.
    """
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except IsADirectoryError:
        _set_aside(path, log)
    except OSError as error:
        raise LockError(f"{path}: cannot consume the nudge: {error.strerror or error}") from error
    return True


def _set_aside(path: Path, log: Callable[[str], None]) -> None:
    target = path.with_name(f"{path.name}.rejected-{time.time_ns()}")
    try:
        path.rename(target)
    except OSError as error:
        raise LockError(f"{path}: cannot set the nudge aside: {error.strerror or error}") from error
    log(f"error: the nudge was a directory; set aside as {target.name}")


def pending(path: Path) -> bool:
    """Whether the nudge file is there, which means a run was asked for and has not started."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise LockError(f"{path}: cannot check the nudge: {error.strerror or error}") from error
    return True


def run_passes(
    lock: RunLock,
    nudge: Path,
    one_pass: Callable[[], T],
    *,
    log: Callable[[str], None],
    max_passes: int = MAX_PASSES,
) -> list[T]:
    """Run `one_pass` at least once, and again while a new nudge arrived during the last pass.

    The cap keeps a flood of nudges from holding the lock for ever; a nudge still waiting when
    the cap is reached stays in place for the next triggered run. A pass that raises, or a
    process that is told to stop (the command turns SIGTERM into `SystemExit`), puts back the
    nudge it consumed, so the request that started the run is not lost. A pass that returns,
    also one that reports a failure, has handled its request and does not.
    """
    lock.require_held()
    results: list[T] = []
    for _ in range(max_passes):
        consumed = take_nudge(nudge, log=log)
        try:
            results.append(one_pass())
        except BaseException:
            if consumed:
                _restore_nudge(nudge)
            raise
        if not pending(nudge):
            break
    return results


def _restore_nudge(path: Path) -> None:
    """Put a consumed nudge back after a crashed pass, so the request is not lost."""
    with contextlib.suppress(OSError):
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
