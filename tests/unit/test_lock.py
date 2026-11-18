# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from publisher.lock import LOCK_FILE, LockBusy, LockError, RunLock, run_passes, take_nudge

HOLDER = """
import sys, time
sys.path.insert(0, sys.argv[3])
from pathlib import Path
from publisher.lock import RunLock
with RunLock(Path(sys.argv[1])):
    print("held", flush=True)
    time.sleep(float(sys.argv[2]))
"""


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    path = tmp_path / "state"
    path.mkdir(mode=0o700)
    return path


def test_the_lock_is_held_inside_and_released_outside(directory: Path) -> None:
    lock = RunLock(directory)
    assert not lock.held
    with lock:
        assert lock.held
        lock.require_held()
    assert not lock.held
    with pytest.raises(LockError, match="not held"):
        lock.require_held()


def test_the_lock_file_is_private_and_kept(directory: Path) -> None:
    with RunLock(directory):
        pass
    path = directory / LOCK_FILE
    assert path.exists()
    assert path.stat().st_mode & 0o777 == 0o600


def test_a_second_holder_in_the_same_process_waits_then_gives_up(directory: Path) -> None:
    with RunLock(directory):
        started = time.monotonic()
        with pytest.raises(LockBusy, match="still holds the lock"):
            RunLock(directory, wait_seconds=0.3, poll_seconds=0.01).acquire()
        assert 0.25 <= time.monotonic() - started < 3


def test_a_waiting_starter_gets_the_lock_when_the_holder_leaves(directory: Path) -> None:
    holder = RunLock(directory)
    holder.acquire()
    threading.Timer(0.3, holder.release).start()
    with RunLock(directory, wait_seconds=10, poll_seconds=0.01) as waiter:
        assert waiter.held


def test_a_lock_cannot_be_taken_twice_by_one_object(directory: Path) -> None:
    with RunLock(directory) as lock, pytest.raises(LockError, match="already held"):
        lock.acquire()


def test_a_real_second_process_is_excluded(directory: Path) -> None:
    root = str(Path(__file__).resolve().parents[2])
    holder = subprocess.Popen(  # noqa: S603
        [sys.executable, "-I", "-c", HOLDER, str(directory), "1.5", root],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(LockBusy):
            RunLock(directory, wait_seconds=0.3, poll_seconds=0.01).acquire()
        started = time.monotonic()
        with RunLock(directory, wait_seconds=10, poll_seconds=0.01):
            assert time.monotonic() - started >= 0.5
    finally:
        holder.kill()
        holder.wait()


def test_a_child_started_while_locked_does_not_keep_the_lock(directory: Path) -> None:
    with RunLock(directory):
        child = subprocess.Popen(["/bin/sleep", "5"], close_fds=False)
    try:
        with RunLock(directory, wait_seconds=1, poll_seconds=0.01) as lock:
            assert lock.held
    finally:
        child.kill()
        child.wait()


def test_a_directory_open_to_others_is_refused(tmp_path: Path) -> None:
    open_directory = tmp_path / "open"
    open_directory.mkdir()
    open_directory.chmod(0o755)
    with pytest.raises(LockError, match="must not be accessible"):
        RunLock(open_directory).acquire()


def test_a_lock_file_open_to_others_is_refused(directory: Path) -> None:
    path = directory / LOCK_FILE
    path.write_text("", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(LockError, match="private to the current user"):
        RunLock(directory).acquire()


def test_a_lock_file_that_is_a_symlink_is_refused(directory: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("", encoding="utf-8")
    (directory / LOCK_FILE).symlink_to(target)
    with pytest.raises(LockError, match="cannot open"):
        RunLock(directory).acquire()


def test_take_nudge_consumes_the_file_once(tmp_path: Path) -> None:
    nudge = tmp_path / "nudge"
    nudge.write_text("", encoding="utf-8")
    assert take_nudge(nudge) is True
    assert take_nudge(nudge) is False


def test_a_nudge_that_cannot_be_consumed_is_an_error(tmp_path: Path) -> None:
    nudge = tmp_path / "nudge"
    nudge.mkdir()
    with pytest.raises(LockError, match="cannot consume the nudge"):
        take_nudge(nudge)


def test_run_passes_needs_the_lock(directory: Path, tmp_path: Path) -> None:
    with pytest.raises(LockError, match="not held"):
        run_passes(RunLock(directory), tmp_path / "nudge", lambda: 1)


def test_one_pass_runs_without_a_nudge(directory: Path, tmp_path: Path) -> None:
    with RunLock(directory) as lock:
        assert run_passes(lock, tmp_path / "nudge", lambda: "done") == ["done"]


def test_a_nudge_that_was_waiting_is_consumed_by_the_first_pass(
    directory: Path, tmp_path: Path
) -> None:
    nudge = tmp_path / "nudge"
    nudge.write_text("", encoding="utf-8")
    with RunLock(directory) as lock:
        assert len(run_passes(lock, nudge, lambda: 1)) == 1
    assert not nudge.exists()


def test_a_nudge_during_a_pass_earns_one_more_pass(directory: Path, tmp_path: Path) -> None:
    nudge = tmp_path / "nudge"
    calls: list[int] = []

    def one_pass() -> int:
        calls.append(len(calls))
        if len(calls) == 1:
            nudge.write_text("", encoding="utf-8")
        return len(calls)

    with RunLock(directory) as lock:
        assert run_passes(lock, nudge, one_pass) == [1, 2]
    assert not nudge.exists()


def test_a_pass_that_crashes_puts_the_consumed_nudge_back(directory: Path, tmp_path: Path) -> None:
    nudge = tmp_path / "nudge"
    nudge.write_text("", encoding="utf-8")

    def crashing() -> int:
        raise RuntimeError("boom")

    with RunLock(directory) as lock, pytest.raises(RuntimeError, match="boom"):
        run_passes(lock, nudge, crashing)
    assert nudge.exists()


def test_a_crash_without_a_nudge_does_not_invent_one(directory: Path, tmp_path: Path) -> None:
    nudge = tmp_path / "nudge"

    def crashing() -> int:
        raise RuntimeError("boom")

    with RunLock(directory) as lock, pytest.raises(RuntimeError, match="boom"):
        run_passes(lock, nudge, crashing)
    assert not nudge.exists()


def test_a_flood_of_nudges_is_capped_and_the_last_one_stays(
    directory: Path, tmp_path: Path
) -> None:
    nudge = tmp_path / "nudge"

    def one_pass() -> int:
        nudge.write_text("", encoding="utf-8")
        return 0

    with RunLock(directory) as lock:
        assert len(run_passes(lock, nudge, one_pass, max_passes=3)) == 3
    assert nudge.exists()
