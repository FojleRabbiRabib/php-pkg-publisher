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
    done = _call(tmp_path, f"print_key {bad} label\necho still-running")
    assert done.returncode == 1
    assert "gpg cannot read" in done.stderr
    assert "still-running" not in done.stdout


FINGERPRINT: Final = "0123456789ABCDEF0123456789ABCDEF01234567"


@pytest.mark.parametrize(
    "given",
    [FINGERPRINT, FINGERPRINT.lower(), " ".join(FINGERPRINT[i : i + 4] for i in range(0, 40, 4))],
)
def test_the_fingerprint_option_takes_forty_digits_in_any_case_with_or_without_spaces(
    tmp_path: Path, given: str
) -> None:
    done = _call(tmp_path, f"parse_arguments --fingerprint '{given}'\necho \"[$FINGERPRINT]\"")
    assert (done.returncode, done.stdout) == (0, f"[{FINGERPRINT}]\n"), done.stderr


def test_without_arguments_no_fingerprint_is_required(tmp_path: Path) -> None:
    done = _call(tmp_path, 'parse_arguments\necho "[$FINGERPRINT]"')
    assert (done.returncode, done.stdout) == (0, "[]\n"), done.stderr


@pytest.mark.parametrize(
    "arguments",
    [
        ["--help"],
        ["--fingerprint"],
        [FINGERPRINT],
        ["--fingerprint", FINGERPRINT, "extra"],
        ["--other", FINGERPRINT],
        ["--fingerprint", FINGERPRINT[:39]],
        ["--fingerprint", FINGERPRINT + "0"],
        ["--fingerprint", "G" * 40],
        ["--fingerprint", ""],
    ],
)
def test_anything_but_the_fingerprint_option_with_a_fingerprint_is_refused(
    tmp_path: Path, arguments: list[str]
) -> None:
    words = " ".join(f"'{word}'" for word in arguments)
    done = _call(tmp_path, f"parse_arguments {words}\necho still-running")
    assert done.returncode == 1
    assert done.stderr.startswith("setup.sh: ")
    assert "still-running" not in done.stdout


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is needed")
def test_print_key_remembers_the_primary_key_and_not_a_subkey(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback"]
    gpg += ["--passphrase", ""]
    subprocess.run(  # noqa: S603
        [*gpg, "--quick-gen-key", "Probe <probe@example.invalid>", "rsa2048", "sign", "1d"],
        check=True,
        capture_output=True,
    )
    listing = subprocess.run(  # noqa: S603
        [*gpg, "--with-colons", "--list-keys"], check=True, capture_output=True, text=True
    ).stdout
    primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr"))
    subprocess.run(  # noqa: S603
        [*gpg, "--quick-add-key", primary, "rsa2048", "sign", "1d"],
        check=True,
        capture_output=True,
    )
    key = tmp_path / "key.gpg"
    key.write_bytes(
        subprocess.run([*gpg, "--export"], check=True, capture_output=True).stdout  # noqa: S603
    )
    subprocess.run(  # noqa: S603
        [_shell("gpgconf"), "--homedir", str(home), "--kill", "all"], check=False
    )
    body = f'print_key {key} "in the test"\necho "[$PRIMARY] [$PRIMARIES] [$ALL_PRIMARIES]"'
    done = _call(tmp_path, body)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[0] == "Key in the test:"
    assert lines[1].startswith(f"  primary key {primary}, expires ")
    assert lines[2].startswith("  signing subkey ")
    assert lines[2].split()[2].rstrip(",") != primary
    # a subkey is neither the primary key nor one of the primary keys
    assert lines[-1] == f"[{primary}] [1] [{primary} ]"


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is needed")
def test_a_file_with_two_primary_keys_is_counted_and_the_first_is_the_one_remembered(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback"]
    gpg += ["--passphrase", ""]
    for name in ("one", "two"):
        subprocess.run(  # noqa: S603
            [*gpg, "--quick-gen-key", f"{name} <{name}@example.invalid>", "rsa2048", "sign", "1d"],
            check=True,
            capture_output=True,
        )
    key = tmp_path / "keys.gpg"
    key.write_bytes(
        subprocess.run([*gpg, "--export"], check=True, capture_output=True).stdout  # noqa: S603
    )
    subprocess.run(  # noqa: S603
        [_shell("gpgconf"), "--homedir", str(home), "--kill", "all"], check=False
    )
    done = _call(tmp_path, f'print_key {key} x\necho "[$PRIMARY] [$PRIMARIES] [$ALL_PRIMARIES]"')
    assert done.returncode == 0, done.stderr
    shown = [
        line.split()[2].rstrip(",") for line in done.stdout.splitlines() if "primary key" in line
    ]
    assert len(shown) == 2
    assert done.stdout.splitlines()[-1] == f"[{shown[0]}] [2] [{shown[0]} {shown[1]} ]"


@pytest.mark.parametrize(
    ("given", "primaries", "primary", "refusal"),
    [
        # no fingerprint given: trust on first use, nothing is compared, whatever the file holds
        ("", 1, "AAAA", ""),
        ("", 2, "AAAA", ""),
        (FINGERPRINT, 1, FINGERPRINT, ""),
        (FINGERPRINT, 1, "AAAA", "is not the fingerprint you gave; nothing was installed"),
        (FINGERPRINT, 2, FINGERPRINT, "must hold exactly one primary key; nothing was installed"),
        (FINGERPRINT, 0, "", "must hold exactly one primary key; nothing was installed"),
    ],
)
def test_with_a_fingerprint_the_key_file_must_hold_that_one_primary_key_and_no_other(
    tmp_path: Path, given: str, primaries: int, primary: str, refusal: str
) -> None:
    body = (
        f"FINGERPRINT='{given}'\nPRIMARIES={primaries}\nPRIMARY='{primary}'\ncheck_key\necho passed"
    )
    done = _call(tmp_path, body)
    if refusal:
        assert done.returncode == 1
        assert refusal in done.stderr
        assert "passed" not in done.stdout
    else:
        assert (done.returncode, done.stdout) == (0, "passed\n"), done.stderr


def test_a_key_file_that_is_not_the_one_shown_is_refused(tmp_path: Path) -> None:
    shown = tmp_path / "shown"
    shown.write_bytes(b"key A")
    same = tmp_path / "same"
    same.write_bytes(b"key A")
    other = tmp_path / "other"
    other.write_bytes(b"key B")
    work = f"TMP={tmp_path}\ncp {shown} {tmp_path}/key.pub\n"
    assert _call(tmp_path, f"{work}confirm_key {same}").returncode == 0
    for target in (other, tmp_path / "missing"):
        done = _call(tmp_path, f"{work}confirm_key {target}\necho still-running")
        assert done.returncode == 1
        assert "still-running" not in done.stdout
    assert "is not the key that was shown" in _call(tmp_path, f"{work}confirm_key {other}").stderr
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    assert "did not install" in _call(tmp_path, f"{work}confirm_key {empty}").stderr


SECOND: Final = "89ABCDEF" * 5


def _rpm_stub(tmp_path: Path, before: str, adds: str) -> str:
    """A shell `rpm` over a key store in a file: `--import` adds the `adds` not yet there."""
    store = tmp_path / "store"
    store.write_text(before)
    return (
        f"rpm() {{\n"
        f'\tcase "$1" in\n'
        f"\t-qa) cat {store} ;;\n"
        f'\t--import) for v in {adds}; do case " $(cat {store}) " in *" $v "*) ;; '
        f"*) printf '%s ' \"$v\" >> {store} ;; esac; done ;;\n"
        f"\t-e) printf '%s\\n' \"$*\" >> {tmp_path}/erased ;;\n"
        f"\tesac\n}}\n"
    )


@pytest.mark.parametrize(
    ("before", "adds", "expected"),
    [
        ("11111111 ", "01234567", ["01234567"]),  # rpm 4: the end of the fingerprint, 8 digits
        ("11111111 ", FINGERPRINT.lower(), [FINGERPRINT.lower()]),  # rpm 6: all forty digits
        ("01234567 ", "01234567", []),  # already in the store: not ours to take out again
        ("", "99999999", []),  # a key of some other fingerprint is not the one imported
        ("", "01234567 89abcdef", ["01234567", "89abcdef"]),  # every primary key of the file
        ("89abcdef ", "01234567 89abcdef", ["01234567"]),  # only the one that was not there
    ],
)
def test_only_the_keys_this_run_added_to_the_store_are_remembered_for_the_roll_back(
    tmp_path: Path, before: str, adds: str, expected: list[str]
) -> None:
    body = (
        _rpm_stub(tmp_path, before, adds)
        + f'ALL_PRIMARIES="{FINGERPRINT} {SECOND} "\nimport_key /key\necho "[$IMPORTED]"'
    )
    done = _call(tmp_path, body)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip("[]\n").split() == expected, done.stdout


def test_cleanup_takes_every_imported_key_out_and_only_those(tmp_path: Path) -> None:
    stub = _rpm_stub(tmp_path, "", "x")
    work = tmp_path / "work"
    work.mkdir()
    done = _call(tmp_path, f"{stub}TMP={work}\nIMPORTED='01234567 89abcdef '\ncleanup")
    assert done.returncode == 0, done.stderr
    assert (tmp_path / "erased").read_text() == ("-e gpg-pubkey-01234567\n-e gpg-pubkey-89abcdef\n")
    (tmp_path / "erased").unlink()
    work.mkdir()
    done = _call(tmp_path, f"{stub}TMP={work}\nIMPORTED=''\ncleanup")
    assert done.returncode == 0, done.stderr
    assert not (tmp_path / "erased").exists()


def test_a_failed_removal_of_the_key_does_not_stop_the_clean_up(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    body = f"TMP={work}\nrpm() {{ return 1; }}\nIMPORTED=01234567\ncleanup\necho done"
    done = _call(tmp_path, body)
    assert (done.returncode, done.stdout) == (0, "done\n"), done.stderr
    assert not work.exists()


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


def test_an_argument_other_than_the_fingerprint_option_is_refused_before_anything_else() -> None:
    done = _run("dash", "--help")
    assert done.returncode == 1
    assert done.stdout == ""
    assert "the only option is --fingerprint" in done.stderr
