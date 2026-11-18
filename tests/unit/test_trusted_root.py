# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from publisher import verify
from publisher.tools import ToolError, Tools
from publisher.verify import obtain_trusted_root

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sigstore" / "trusted_root.json"
NOW = 1_800_000_000.0
DAY = 24 * 3600.0
TARGET = "$TUF_ROOT/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json"
MAKE_TARGET_DIRECTORY = 'mkdir -p "$(dirname "' + TARGET + '")"\n'
COPY_FIXTURE = MAKE_TARGET_DIRECTORY + f'cp {FIXTURE} "{TARGET}"\n'
WRITE_EMPTY_OBJECT = MAKE_TARGET_DIRECTORY + f'echo "{{}}" > "{TARGET}"\n'
WRITE_INVALID_JSON = MAKE_TARGET_DIRECTORY + f'printf "not json" > "{TARGET}"\n'


@pytest.fixture(scope="module")
def real_tools() -> Tools:
    return Tools.locate(os.environ["PATH"])


class Setup:
    """A private trust directory and a cosign stand-in whose behaviour is a shell snippet."""

    def __init__(self, tmp_path: Path, tools: Tools) -> None:
        self.directory = tmp_path / "trust"
        self.directory.mkdir(mode=0o700)
        self.log = tmp_path / "cosign.log"
        self._tmp = tmp_path
        self._tools = tools

    def cosign(self, body: str) -> Tools:
        script = self._tmp / "cosign"
        script.write_text(
            f'#!/bin/sh\nprintf "%s\\n" "$@" > {self.log}\n'
            f'printf "TUF_ROOT=%s\\n" "$TUF_ROOT" >> {self.log}\n{body}',
            encoding="utf-8",
        )
        script.chmod(0o755)
        return dataclasses.replace(self._tools, cosign=script)

    def copy(self, age: float, content: bytes | None = None) -> Path:
        path = self.directory / "trusted_root.json"
        path.write_bytes(FIXTURE.read_bytes() if content is None else content)
        os.utime(path, (NOW - age, NOW - age))
        return path

    def obtain(self, body: str) -> verify.TrustedRoot:
        return obtain_trusted_root(self.cosign(body), self.directory, now=NOW)


@pytest.fixture
def setup(tmp_path: Path, real_tools: Tools) -> Setup:
    return Setup(tmp_path, real_tools)


def test_a_successful_refresh_stores_a_fresh_validated_copy(setup: Setup) -> None:
    root = setup.obtain(COPY_FIXTURE)
    assert root == verify.TrustedRoot(
        path=setup.directory / "trusted_root.json", age_seconds=0.0, refreshed=True
    )
    assert root.path.read_bytes() == FIXTURE.read_bytes()
    assert root.path.stat().st_mtime == NOW


def test_the_refresh_runs_only_initialize_in_the_persistent_tuf_directory(setup: Setup) -> None:
    setup.obtain(COPY_FIXTURE)
    assert setup.log.read_text(encoding="utf-8").splitlines() == [
        "initialize",
        f"TUF_ROOT={setup.directory / 'tuf'}",
    ]
    assert oct((setup.directory / "tuf").stat().st_mode & 0o777) == "0o700"


def test_a_second_refresh_reuses_the_same_tuf_directory(setup: Setup) -> None:
    (setup.directory / "tuf").mkdir(mode=0o700)
    (setup.directory / "tuf" / "kept").write_text("x", encoding="utf-8")
    setup.obtain(COPY_FIXTURE)
    assert (setup.directory / "tuf" / "kept").exists()


def test_a_failed_refresh_uses_a_recent_copy_and_says_so(setup: Setup) -> None:
    setup.copy(age=3 * DAY)
    root = setup.obtain("exit 1\n")
    assert root.refreshed is False
    assert root.age_seconds == 3 * DAY
    assert root.path.stat().st_mtime == NOW - 3 * DAY


def test_a_copy_exactly_seven_days_old_is_still_used(setup: Setup) -> None:
    setup.copy(age=7 * DAY)
    assert setup.obtain("exit 1\n").age_seconds == 7 * DAY


def test_a_copy_one_second_past_seven_days_stops_the_run(setup: Setup) -> None:
    setup.copy(age=7 * DAY + 1)
    with pytest.raises(ToolError, match="unusable"):
        setup.obtain("exit 1\n")


def test_a_failed_refresh_without_a_copy_stops_the_run(setup: Setup) -> None:
    with pytest.raises(ToolError, match="no trusted root"):
        setup.obtain("exit 1\n")


def test_a_copy_dated_in_the_future_stops_the_run(setup: Setup) -> None:
    setup.copy(age=-1)
    with pytest.raises(ToolError, match="unusable"):
        setup.obtain("exit 1\n")


def test_a_copy_that_is_a_symlink_stops_the_run(setup: Setup) -> None:
    link = setup.directory / "trusted_root.json"
    link.symlink_to(FIXTURE)
    os.utime(link, (NOW - DAY, NOW - DAY), follow_symlinks=False)
    with pytest.raises(ToolError, match="unusable"):
        setup.obtain("exit 1\n")


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_a_copy_that_is_not_a_regular_file_stops_the_run(setup: Setup, kind: str) -> None:
    path = setup.directory / "trusted_root.json"
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    os.utime(path, (NOW - DAY, NOW - DAY))
    with pytest.raises(ToolError, match="unusable"):
        setup.obtain("exit 1\n")


def test_a_target_left_by_an_earlier_run_is_not_a_fresh_fetch(setup: Setup) -> None:
    (setup.directory / "tuf").mkdir(mode=0o700)
    left = setup.directory / "tuf" / "tuf-repo-cdn.sigstore.dev" / "targets" / "trusted_root.json"
    left.parent.mkdir(parents=True)
    left.write_bytes(FIXTURE.read_bytes())
    setup.copy(age=7 * DAY)
    root = setup.obtain("exit 0\n")
    assert root.refreshed is False
    assert root.age_seconds == 7 * DAY
    assert not left.exists()


def test_a_damaged_copy_stops_the_run(setup: Setup) -> None:
    setup.copy(age=DAY, content=b"{}")
    with pytest.raises(ToolError, match="not a Sigstore trusted root"):
        setup.obtain("exit 1\n")


def test_exit_zero_without_the_file_is_a_failed_refresh(setup: Setup) -> None:
    setup.copy(age=2 * DAY)
    root = setup.obtain("exit 0\n")
    assert root.refreshed is False
    assert root.age_seconds == 2 * DAY


def test_exit_zero_without_the_file_and_without_a_copy_stops_the_run(setup: Setup) -> None:
    with pytest.raises(ToolError, match="no trusted root"):
        setup.obtain("exit 0\n")


def test_a_refresh_that_writes_something_else_keeps_the_good_copy(setup: Setup) -> None:
    good = setup.copy(age=2 * DAY)
    before = good.read_bytes()
    root = setup.obtain(WRITE_EMPTY_OBJECT)
    assert root.refreshed is False
    assert good.read_bytes() == before
    assert good.stat().st_mtime == NOW - 2 * DAY


def test_a_refresh_that_writes_invalid_json_keeps_the_good_copy(setup: Setup) -> None:
    good = setup.copy(age=DAY)
    before = good.read_bytes()
    assert setup.obtain(WRITE_INVALID_JSON).refreshed is False
    assert good.read_bytes() == before


def test_a_hanging_refresh_falls_back(setup: Setup, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verify, "INITIALIZE_TIMEOUT_SECONDS", 0.3)
    setup.copy(age=DAY)
    assert setup.obtain("sleep 30\n").refreshed is False


def test_a_hanging_refresh_without_a_copy_stops_the_run(
    setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(verify, "INITIALIZE_TIMEOUT_SECONDS", 0.3)
    with pytest.raises(ToolError, match="no trusted root"):
        setup.obtain("sleep 30\n")


def test_a_flooding_refresh_falls_back(setup: Setup) -> None:
    setup.copy(age=DAY)
    assert setup.obtain("head -c 1000000 /dev/zero >&2\n").refreshed is False


def test_a_trust_directory_open_to_others_is_refused(setup: Setup) -> None:
    setup.directory.chmod(0o755)
    with pytest.raises(ToolError, match="must not be accessible"):
        setup.obtain(COPY_FIXTURE)


def test_a_tuf_directory_open_to_others_is_refused(setup: Setup) -> None:
    (setup.directory / "tuf").mkdir(mode=0o755)
    (setup.directory / "tuf").chmod(0o755)
    setup.copy(age=DAY)
    with pytest.raises(ToolError, match="must not be accessible"):
        setup.obtain(COPY_FIXTURE)


def test_a_temporary_file_of_a_killed_run_is_removed_when_old_enough(setup: Setup) -> None:
    old = setup.directory / "root-old"
    recent = setup.directory / "root-recent"
    for path, age in ((old, verify.INITIALIZE_TIMEOUT_SECONDS + 1), (recent, 1.0)):
        path.write_bytes(b"x")
        os.utime(path, (NOW - age, NOW - age))
    setup.obtain(COPY_FIXTURE)
    assert not old.exists()
    assert recent.exists()
