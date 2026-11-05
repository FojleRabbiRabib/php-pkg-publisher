# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from publisher import files
from publisher.files import FileError


def test_a_private_directory_is_accepted(tmp_path: Path) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    files.require_private_directory(directory)


@pytest.mark.parametrize(("mode", "message"), [(0o755, "must not be accessible"), (0o770, "group")])
def test_a_directory_open_to_others_is_refused(tmp_path: Path, mode: int, message: str) -> None:
    directory = tmp_path / "open"
    directory.mkdir()
    directory.chmod(mode)
    with pytest.raises(FileError, match=message):
        files.require_private_directory(directory)


def test_a_missing_path_a_file_and_a_symlink_are_refused(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("x", encoding="utf-8")
    target = tmp_path / "real"
    target.mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(target)
    with pytest.raises(FileError, match="cannot inspect"):
        files.require_private_directory(tmp_path / "missing")
    with pytest.raises(FileError, match="not a directory"):
        files.require_private_directory(tmp_path / "file")
    with pytest.raises(FileError, match="not a directory"):
        files.require_private_directory(tmp_path / "link")


def test_a_directory_of_another_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    owner = directory.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    with pytest.raises(FileError, match="owned by the current user"):
        files.require_private_directory(directory)


def test_write_atomic_replaces_the_file_and_leaves_no_temporary(tmp_path: Path) -> None:
    target = tmp_path / "data"
    target.write_bytes(b"old")
    files.write_atomic(target, b"new")
    assert target.read_bytes() == b"new"
    assert [entry.name for entry in tmp_path.iterdir()] == ["data"]


def test_write_atomic_can_set_the_modification_time(tmp_path: Path) -> None:
    target = tmp_path / "data"
    files.write_atomic(target, b"x", mtime=1_700_000_000.0)
    assert target.stat().st_mtime == 1_700_000_000.0


def test_write_atomic_failure_keeps_the_old_file_and_removes_the_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data"
    target.write_bytes(b"old")

    def failing_sync(path: Path) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(files, "sync_directory", failing_sync)
    with pytest.raises(OSError, match="No space"):
        files.write_atomic(target, b"new")
    assert [entry.name for entry in tmp_path.iterdir() if entry.name != "data"] == []


def test_write_atomic_failure_before_the_rename_keeps_the_old_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data"
    target.write_bytes(b"old")

    def failing_fsync(descriptor: int) -> None:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError, match="Input/output"):
        files.write_atomic(target, b"new")
    assert target.read_bytes() == b"old"
    assert [entry.name for entry in tmp_path.iterdir()] == ["data"]


def test_sweep_removes_only_old_files_with_the_prefix(tmp_path: Path) -> None:
    for name, mtime in (("tmp-old", 100.0), ("tmp-new", 900.0), ("other-old", 100.0)):
        path = tmp_path / name
        path.write_bytes(b"x")
        os.utime(path, (mtime, mtime))
    files.sweep_temporary(tmp_path, "tmp-", older_than=500.0)
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["other-old", "tmp-new"]


def test_free_space_is_checked_on_both_sides_of_the_minimum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    usage = shutil._ntuple_diskusage(total=100, used=50, free=50)
    monkeypatch.setattr(shutil, "disk_usage", lambda path: usage)
    files.require_free_space(tmp_path, 50)
    with pytest.raises(FileError, match="only 50 bytes free"):
        files.require_free_space(tmp_path, 51)


def test_an_unreadable_path_fails_the_free_space_check(tmp_path: Path) -> None:
    with pytest.raises(FileError, match="cannot check free space"):
        files.require_free_space(tmp_path / "missing", 1)
