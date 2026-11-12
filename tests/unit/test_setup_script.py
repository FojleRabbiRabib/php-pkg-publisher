# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`setup.sh` as text, and its refusals that need no package manager.

The behaviour with a real apt and dnf is the container layer's (`tests/container/test_setup.py`).
Nothing here runs the script's `main` as root: the whole-script tests skip under root, and the
truncation tests only run prefixes that stop before the last line.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Final

import pytest

SCRIPT: Final = Path(__file__).resolve().parents[2] / "setup.sh"
TEXT: Final = SCRIPT.read_text(encoding="utf-8")
LINES: Final = TEXT.splitlines()
# What may stand at the left margin outside a function: its head and end, settings, assignments.
TOP_LEVEL: Final = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*\(\) \{|\}|[A-Z][A-Z_]*=('[^']*'|[A-Za-z0-9_/:.]+)"
    r"|set -eu|umask [0-7]+|export [A-Z][A-Z_]*"
)
NOT_ROOT: Final = pytest.mark.skipif(os.geteuid() == 0, reason="would run the script for real")


def _shell(name: str) -> str:
    found = shutil.which(name)
    assert found is not None, f"{name} must be installed to run these tests"
    return found


def _run(shell: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [_shell(shell), str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.mark.parametrize("shell", ["dash", "bash"])
def test_the_script_parses_under_dash_and_bash(shell: str) -> None:
    done = subprocess.run(  # noqa: S603
        [_shell(shell), "-n", str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr


def test_the_script_is_posix_sh_with_the_licence_header_and_one_base_line() -> None:
    assert LINES[0] == "#!/bin/sh"
    assert LINES[1] == "# SPDX-License-Identifier: Apache-2.0"
    assert LINES[2].startswith("# Copyright 2026 ")
    assert "set -eu" in LINES
    assert TEXT.count("BASE='https://pkg.rabib.me'") == 1
    assert not re.search(r"\beval\b", TEXT)
    assert not [line for line in LINES if line.startswith(" ")], "indent with tabs"


def test_nothing_runs_before_the_last_line() -> None:
    """Outside functions there are only settings and assignments, so a cut download runs nothing."""
    assert LINES[-1] == 'main "$@"'
    for number, line in enumerate(LINES[:-1], start=1):
        if line and not line.startswith(("#", "\t", " ")):
            assert TOP_LEVEL.fullmatch(line), f"line {number} runs at the top level: {line}"


def test_a_script_cut_short_runs_nothing() -> None:
    """Piped to a shell like `curl | sh`, every prefix that stops before `main` is silent."""
    cuts = [number for number, line in enumerate(LINES[:-1], start=1) if line == "}"]
    assert len(cuts) > 10
    for number in cuts:
        prefix = "\n".join(LINES[:number]) + "\n"
        done = subprocess.run(  # noqa: S603
            [_shell("dash")], input=prefix, capture_output=True, text=True, check=False
        )
        assert (done.returncode, done.stdout, done.stderr) == (0, "", ""), number
    # a cut inside a function is a syntax error before anything runs
    for number in (cuts[0] + 3, cuts[3] + 2, cuts[-1] - 3):
        prefix = "\n".join(LINES[:number]) + "\n"
        done = subprocess.run(  # noqa: S603
            [_shell("dash")], input=prefix, capture_output=True, text=True, check=False
        )
        assert done.stdout == ""
        assert "setup.sh:" not in done.stderr


def _call(
    tmp_path: Path, body: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run `body` in dash after the script's definitions, without its `main`."""
    program = "\n".join(LINES[:-1]) + f"\nTMP={tmp_path}\n{body}\n"
    return subprocess.run(  # noqa: S603
        [_shell("dash")],
        input=program,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env=env,
    )


class _Redirect(BaseHTTPRequestHandler):
    """Answers every request with a redirect to `/final`, which holds the body `FINAL`."""

    def do_GET(self) -> None:
        if self.path == "/final":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"FINAL")
        else:
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.mark.parametrize(
    "setting",
    [
        *("enabled=1", "enabled = 1", "enabled=true", "enabled=YES", "enabled=on", "enabled=1 "),
        *("enabled  =  1", "ENABLED=1", "enabled\t=\t1"),
    ],
)
def test_every_spelling_of_enabled_keeps_a_section_enabled(tmp_path: Path, setting: str) -> None:
    repo = tmp_path / "rabib.repo"
    repo.write_text(
        f"[rabib-php83]\nenabled=0\n\n[rabib-php84]\n{setting}\r\n\n[rabib-php85]\nenabled=false\n"
    )
    done = _call(tmp_path, f"DNF_REPO={repo}\nDNF_OVERRIDES={tmp_path}/none\nenabled_php")
    assert (done.returncode, done.stdout.split()) == (0, ["8.4"]), done.stderr


def test_an_override_file_enables_a_section_and_wins_over_the_repository_file(
    tmp_path: Path,
) -> None:
    """dnf5's config-manager writes `enabled` into an override file, not into the repo file."""
    repo = tmp_path / "rabib.repo"
    repo.write_text(
        "[rabib-php83]\nenabled=0\n\n[rabib-php84]\nenabled=1\n\n[rabib-php85]\nenabled=0\n"
    )
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (overrides / "99-config_manager.repo").write_text(
        "# Generated by libdnf5.\n[rabib-php83]\nenabled=1\n[rabib-php84]\nenabled=0\n"
        "[other]\nenabled=1\n"
    )
    done = _call(
        tmp_path, f"DNF_REPO={repo}\nDNF_OVERRIDES={overrides}\nTMP={tmp_path}\nenabled_php"
    )
    assert (done.returncode, done.stdout.split()) == (0, ["8.3"]), done.stderr


def test_a_symbolic_link_stays_a_link_through_a_write_and_a_roll_back(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text("old\n")
    link = tmp_path / "link"
    link.symlink_to(real)
    work = tmp_path / "work"
    work.mkdir()
    body = (
        f"TMP={work}\nremember {link}\nROLLBACK={link}\nwrite_file {link} new\n"
        f"cat {real} >&2\ncleanup"
    )
    done = _call(tmp_path, body)
    assert done.returncode == 0, done.stderr
    assert done.stderr == "new\n"  # the target had the new text before the roll back
    assert link.is_symlink()
    assert real.read_text() == "old\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["link", "real"]


def test_a_dangling_symbolic_link_stops_the_script_and_is_left_alone(tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "missing")
    work = tmp_path / "work"
    work.mkdir()
    body = (
        f"TMP={work}\ntrap cleanup EXIT\nremember {link}\nROLLBACK={link}\nwrite_file {link} text"
    )
    done = _call(tmp_path, body)
    assert done.returncode == 1
    assert "dangling symbolic link" in done.stderr
    assert link.is_symlink()
    assert not (tmp_path / "missing").exists()


def test_a_directory_is_not_a_place_to_write_the_file(tmp_path: Path) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()
    link = tmp_path / "link"
    link.symlink_to(directory)
    for target in (directory, link):
        done = _call(tmp_path, f"write_file {target} text")
        assert done.returncode == 1
        assert "is a directory" in done.stderr
        assert list(directory.iterdir()) == []


def _repo_with_extras(tmp_path: Path) -> Path:
    repo = tmp_path / "rabib.repo"
    repo.write_text(
        "[rabib-php83]\nname=x\nenabled=0\nbaseurl=http://elsewhere/\n\n"
        "[rabib-php84]\nname=x\nenabled=1\nPriority = 50\n# a note\n\ngpgcheck = 0\n"
        "REPO_GPGCHECK=0\npkg_gpgcheck=0\nlocalpkg_gpgcheck=0\nmirrorlist=http://m/\n"
        "  http://m/more\nmetalink=http://m/\ngpgkey=file:///other\n  https://evil.example/KEY\n"
        "gpgcheck:0\nrepo_gpgcheck : 0\nexclude=a\n  b\nsslverify=0\n[other]\npriority=1\n"
    )
    return repo


def test_hand_added_keys_of_a_section_are_kept_and_the_trust_keys_are_not(
    tmp_path: Path,
) -> None:
    repo = _repo_with_extras(tmp_path)
    done = _call(tmp_path, f"DNF_REPO={repo}\nBASE=https://x\nRPM_KEY=/k\nrepo_text '8.4 '")
    assert done.returncode == 0, done.stderr
    sections = done.stdout.split("\n\n")
    assert sections[0] == (
        "[rabib-php83]\nname=Rabib PHP extensions for PHP 8.3\nbaseurl=https://x/rpm/8.3/$basearch\n"
        "enabled=0\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///k"
    )
    assert sections[1] == (
        "[rabib-php84]\nname=Rabib PHP extensions for PHP 8.4\nbaseurl=https://x/rpm/8.4/$basearch\n"
        "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///k\n"
        "Priority = 50\n# a note\nexclude=a\n  b\nsslverify=0"
    )
    assert "[other]" not in done.stdout
    for dropped in ("pkg_gpgcheck=0", "localpkg_gpgcheck=0", "mirrorlist=", "metalink="):
        assert f'dropped "{dropped}' in done.stderr, done.stderr
    for dropped in ("gpgcheck:0", "repo_gpgcheck : 0"):
        assert f'dropped "{dropped}" from [rabib-php84]: it is not a key=value' in done.stderr
    assert "gpgcheck = 0" not in done.stdout and "REPO_GPGCHECK=0" not in done.stdout
    # the continuation lines of a key that is rewritten or dropped go with it
    assert "evil.example" not in done.stdout and "m/more" not in done.stdout


def test_a_rewrite_keeps_the_hand_added_keys_byte_for_byte_across_runs(tmp_path: Path) -> None:
    repo = _repo_with_extras(tmp_path)
    body = (
        f"DNF_REPO={repo}\nBASE=https://x\nRPM_KEY=/k\nwrite_file {repo} \"$(repo_text '8.4 ')\"\n"
    )
    assert _call(tmp_path, body).returncode == 0
    first = repo.read_bytes()
    assert _call(tmp_path, body).returncode == 0
    assert repo.read_bytes() == first
    assert b"Priority = 50\n# a note\nexclude=a\n  b\nsslverify=0\n" in first


def test_a_section_an_override_turns_off_is_not_turned_on_by_a_detected_php(
    tmp_path: Path,
) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (overrides / "10-a.repo").write_text("[rabib-php84]\nenabled=0\n[rabib-php85]\nenabled=0\n")
    (overrides / "20-b.repo").write_text("[rabib-php85]\nenabled=1\n")
    setup = f"DNF_REPO={tmp_path}/none.repo\nDNF_OVERRIDES={overrides}\n"
    off = _call(tmp_path, setup + "override_off")
    assert (off.returncode, off.stdout.split()) == (0, ["8.4"]), off.stderr
    kept = _call(tmp_path, setup + 'without_versions "8.3 8.4 8.5 " "$(override_off)"')
    assert (kept.returncode, kept.stdout.split()) == (0, ["8.3", "8.5"]), kept.stderr


@pytest.mark.parametrize("existed", [True, False])
def test_an_unconfirmed_definition_is_put_back_or_removed_when_the_script_exits(
    tmp_path: Path, existed: bool
) -> None:
    """`cleanup` runs on every exit: the file returns to its old content, or goes."""
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    if existed:
        target.write_text("old\n")
    lists = tmp_path / "lists"
    lists.mkdir()
    index = lists / "h_apt_dists_stable_InRelease"
    index.write_text("old index")
    body = (
        f"TMP={work}\nAPT_LISTS={lists}\nBASE=http://h\nremember {target}\nROLLBACK={target}\n"
        f"printf 'new\\n' > {target}\nset_index_aside\nprintf 'half' > {index}\ncleanup"
    )
    done = _call(tmp_path, body)
    assert done.returncode == 0, done.stderr
    assert (target.read_text() if existed else None) == ("old\n" if existed else None)
    assert target.exists() is existed
    assert index.read_text() == "old index"
    assert not work.exists()


def test_a_confirmed_definition_is_left_alone_by_cleanup(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "target"
    target.write_text("new\n")
    done = _call(tmp_path, f"TMP={work}\nROLLBACK=''\ncleanup")
    assert done.returncode == 0, done.stderr
    assert target.read_text() == "new\n"


def test_a_section_header_in_a_crlf_file_still_counts(tmp_path: Path) -> None:
    repo = tmp_path / "rabib.repo"
    repo.write_bytes(b"[rabib-php83]\r\nenabled=1\r\n[rabib-php84] \r\nenabled=1\r\n")
    done = _call(tmp_path, f"DNF_REPO={repo}\nDNF_OVERRIDES={tmp_path}/none\nenabled_php")
    assert (done.returncode, done.stdout.split()) == (0, ["8.3", "8.4"]), done.stderr


def test_write_file_writes_the_text_and_a_newline_and_leaves_no_temporary_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "out"
    done = _call(tmp_path, f'write_file {target} "$(printf "a\\nb\\n")"')
    assert done.returncode == 0, done.stderr
    assert target.read_text() == "a\nb\n"
    assert oct(target.stat().st_mode & 0o777) == "0o644"
    assert [path.name for path in tmp_path.iterdir()] == ["out"]


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is needed")
def test_a_key_file_that_gpg_cannot_read_stops_the_script_with_no_fingerprint(
    tmp_path: Path,
) -> None:
    bad = tmp_path / "bad.gpg"
    bad.write_text("not a key\n")
    done = _call(tmp_path, f"print_key {bad}\necho still-running")
    assert done.returncode == 1
    assert "gpg cannot read" in done.stderr
    assert "still-running" not in done.stdout


def test_the_apt_index_is_looked_for_in_the_lists_directory(tmp_path: Path) -> None:
    lists = tmp_path / "lists"
    lists.mkdir()
    # another host's index, and an empty one of ours, do not count
    (lists / "other.example_apt_dists_stable_InRelease").write_text("x")
    (lists / "pkg.example:8080_apt_dists_stable_InRelease").write_text("")
    body = f"APT_LISTS={lists}\nBASE=http://pkg.example:8080\nindex_fetched"
    done = _call(tmp_path, body)
    assert (done.returncode, done.stdout) == (1, ""), done.stderr
    (lists / "pkg.example:8080_apt_dists_stable_InRelease").write_text("signed")
    done = _call(tmp_path, body)
    assert done.returncode == 0, done.stderr


def test_a_failed_write_leaves_no_temporary_file(tmp_path: Path) -> None:
    directory = tmp_path / "etc"
    directory.mkdir()
    # chmod fails after the temporary file exists; TMP is emptied so cleanup keeps tmp_path
    body = f"TMP=''\ntrap cleanup EXIT\nchmod() {{ return 1; }}\nwrite_file {directory}/out text"
    done = _call(tmp_path, body)
    assert done.returncode != 0
    assert list(directory.iterdir()) == []


def test_the_download_ignores_a_curlrc_that_follows_redirects(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".curlrc").write_text("location\n")
    server = HTTPServer(("127.0.0.1", 0), _Redirect)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        target = tmp_path / "got"
        env = {"HOME": str(home), "PATH": os.environ["PATH"]}
        done = _call(tmp_path, f"BASE={base}\nfetch x.deb {target}", env)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert done.returncode == 0, done.stderr
    assert b"FINAL" not in target.read_bytes()


@NOT_ROOT
@pytest.mark.parametrize("shell", ["dash", "bash"])
def test_a_user_who_is_not_root_is_refused_and_nothing_is_written(shell: str) -> None:
    done = _run(shell)
    assert done.returncode == 1
    assert done.stdout == ""
    assert "it must run as root" in done.stderr


@NOT_ROOT
def test_arguments_are_refused() -> None:
    done = _run("dash", "--help")
    assert done.returncode == 1
    assert "takes no arguments" in done.stderr
