# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import os
import signal
import time
from pathlib import Path

import pytest

from publisher import tools
from publisher.tools import ToolError, Tools, ToolTimeout, run

ENV = Path("/usr/bin/env")


def test_locate_finds_every_program_by_absolute_path() -> None:
    found = Tools.locate(os.environ["PATH"])
    programs = (
        found.apt_ftparchive,
        found.cosign,
        found.createrepo_c,
        found.dpkg_deb,
        found.gpg,
        found.gpgconf,
        found.rpm,
        found.rpmkeys,
    )
    for path in programs:
        assert path.is_absolute()
        assert path.exists()


def test_locate_fails_when_a_program_is_missing(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="apt-ftparchive is not installed"):
        Tools.locate(str(tmp_path))


def test_locate_ignores_the_callers_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "apt-ftparchive"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ToolError, match="apt-ftparchive is not installed"):
        Tools.locate(str(tmp_path / "nowhere"))


def test_run_gives_a_minimal_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("COSIGN_REPOSITORY", "SIGSTORE_X", "TUF_ROOT", "GNUPGHOME", "https_proxy"):
        monkeypatch.setenv(name, "inherited")
    result = run([ENV], home=tmp_path)
    assert result.code == 0
    assert sorted(result.stdout.splitlines()) == sorted(
        [f"HOME={tmp_path}", "LC_ALL=C", "PATH=/usr/bin:/bin"]
    )


def test_run_adds_only_the_requested_variables(tmp_path: Path) -> None:
    result = run([ENV], home=tmp_path, env={"GNUPGHOME": "/x"})
    assert "GNUPGHOME=/x" in result.stdout.splitlines()


def test_run_closes_standard_input(tmp_path: Path) -> None:
    assert run([Path("/bin/cat")], home=tmp_path, timeout=5).stdout == ""


def test_run_returns_the_exit_code_and_stderr(tmp_path: Path) -> None:
    result = run([Path("/bin/sh"), "-c", "echo oops >&2; exit 3"], home=tmp_path)
    assert (result.code, result.stdout, result.stderr) == (3, "", "oops\n")


def test_run_accepts_output_up_to_the_limit(tmp_path: Path) -> None:
    command = f"head -c {tools.MAX_OUTPUT_BYTES} /dev/zero"
    result = run([Path("/bin/sh"), "-c", command], home=tmp_path)
    assert len(result.stdout) == tools.MAX_OUTPUT_BYTES


@pytest.mark.parametrize("stream", ["1", "2"])
def test_run_kills_a_program_that_floods_its_output(tmp_path: Path, stream: str) -> None:
    flood = f"head -c 20000000 /dev/zero >&{stream}"
    started = time.monotonic()
    with pytest.raises(ToolError, match="more output than allowed"):
        run([Path("/bin/sh"), "-c", flood], home=tmp_path, timeout=20)
    assert time.monotonic() - started < 10


def test_run_stops_what_a_timed_out_program_started(tmp_path: Path) -> None:
    marker = tmp_path / "survived"
    script = f"(sleep 1; touch {marker}) & sleep 30"
    with pytest.raises(ToolTimeout):
        run([Path("/bin/sh"), "-c", script], home=tmp_path, timeout=0.2)
    time.sleep(1.5)
    assert not marker.exists()


def test_run_stops_what_a_flooding_program_started(tmp_path: Path) -> None:
    marker = tmp_path / "survived"
    script = f"(sleep 1; touch {marker}) & head -c 20000000 /dev/zero; sleep 30"
    with pytest.raises(ToolError, match="more output than allowed"):
        run([Path("/bin/sh"), "-c", script], home=tmp_path, timeout=20)
    time.sleep(1.5)
    assert not marker.exists()


def test_run_stops_what_a_finished_program_left_behind(tmp_path: Path) -> None:
    marker = tmp_path / "survived"
    run([Path("/bin/sh"), "-c", f"(sleep 1; touch {marker}) &"], home=tmp_path)
    time.sleep(1.5)
    assert not marker.exists()


def test_run_kills_the_group_of_a_finished_program_before_reaping_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After the program is reaped its process id is free for any other process to take."""
    states: list[str] = []
    killpg = os.killpg

    def spy(group: int, number: int) -> None:
        try:
            stat = Path(f"/proc/{group}/stat").read_text(encoding="ascii")
            states.append(stat.rsplit(")", 1)[1].split()[0])
        except OSError:
            states.append("gone")
        killpg(group, number)

    monkeypatch.setattr(os, "killpg", spy)
    assert run([Path("/bin/true")], home=tmp_path).code == 0
    assert states == ["Z"]


def test_run_fails_when_the_exit_status_was_lost(tmp_path: Path) -> None:
    """With SIGCHLD ignored the kernel reaps the program, so its exit code cannot be known."""
    before = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    try:
        with pytest.raises(ToolError, match="exit status of the program was lost"):
            run([Path("/bin/false")], home=tmp_path)
    finally:
        signal.signal(signal.SIGCHLD, before)


def test_run_polls_quickly_at_first_and_backs_off_to_the_poll_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pauses: list[float] = []
    sleep = time.sleep

    def spy(seconds: float) -> None:
        pauses.append(seconds)
        sleep(seconds)

    monkeypatch.setattr(time, "sleep", spy)
    run([Path("/bin/sleep"), "0.1"], home=tmp_path)
    assert pauses[:6] == [0.0005, 0.001, 0.002, 0.004, 0.008, 0.01]
    assert set(pauses[5:]) == {tools.POLL_SECONDS}


def test_run_stops_a_timed_out_program(tmp_path: Path) -> None:
    marker = tmp_path / "survived"
    with pytest.raises(ToolTimeout):
        run([Path("/bin/sh"), "-c", f"sleep 1; touch {marker}"], home=tmp_path, timeout=0.2)
    time.sleep(1.5)
    assert not marker.exists()


def test_run_times_out(tmp_path: Path) -> None:
    with pytest.raises(ToolTimeout, match=r"took longer than 0\.2s"):
        run([Path("/bin/sleep"), "5"], home=tmp_path, timeout=0.2)


def test_run_reports_a_program_that_cannot_start(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="cannot run"):
        run([tmp_path / "missing"], home=tmp_path)


def test_run_does_not_use_a_shell(tmp_path: Path) -> None:
    result = run([Path("/bin/echo"), "$(id)", ";", "x"], home=tmp_path)
    assert result.stdout == "$(id) ; x\n"


def test_a_timeout_is_a_tool_error() -> None:
    assert issubclass(ToolTimeout, ToolError)
