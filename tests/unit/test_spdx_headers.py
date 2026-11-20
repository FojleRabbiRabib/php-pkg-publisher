# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Every tracked file carries the licence header, except the files that cannot or must not."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
from repofiles import ROOT, tracked_files

SPDX: Final = "SPDX-License-Identifier: Apache-2.0"
COPYRIGHT: Final = "Copyright 2026 Fojle Rabbi (Rabib)"
HEADER_LINES: Final = 6

# Files and folders without a header, each for a reason.
EXEMPT_FILES: Final = {
    "LICENSE": "the licence text itself",
    "NOTICE": "the notice every redistribution preserves",
    "keyring/copyright": "a Debian machine-readable copyright file, with its own licence fields",
    "composer.json": "JSON has no comments",
    "composer.lock": "JSON has no comments, and composer writes it",
    "requirements-dev.txt": "written by pip-compile, which would drop a header",
    "deploy/primary-fingerprint.txt": "one value that is read back as is",
}
EXEMPT_SUFFIXES: Final = {".md": "documentation, not source"}
EXEMPT_FOLDERS: Final = {"tests/fixtures/": "signed bytes and recorded data, kept exactly"}


def _exempt(name: str) -> bool:
    return (
        name in EXEMPT_FILES
        or Path(name).suffix in EXEMPT_SUFFIXES
        or any(name.startswith(folder) for folder in EXEMPT_FOLDERS)
    )


def _has_header(path: Path) -> bool:
    head = path.read_text(encoding="utf-8").splitlines()[:HEADER_LINES]
    return any(SPDX in line for line in head) and any(COPYRIGHT in line for line in head)


def test_every_tracked_file_that_can_carry_a_header_has_one() -> None:
    missing = [
        name for name in tracked_files() if not _exempt(name) and not _has_header(ROOT / name)
    ]
    assert missing == []


def test_a_header_needs_both_lines_near_the_top(tmp_path: Path) -> None:
    both = f"# {SPDX}\n# {COPYRIGHT}\nx = 1\n"
    cases = {
        "both.txt": (both, True),
        "late.txt": ("\n" * HEADER_LINES + both, False),
        "licence-only.txt": (f"# {SPDX}\nx = 1\n", False),
        "copyright-only.txt": (f"# {COPYRIGHT}\nx = 1\n", False),
        "other-licence.txt": ("# SPDX-License-Identifier: MIT\n# " + COPYRIGHT + "\n", False),
        "empty.txt": ("", False),
    }
    for name, (body, expected) in cases.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
        assert _has_header(tmp_path / name) is expected, name


@pytest.mark.parametrize(
    ("name", "exempt"),
    [
        ("LICENSE", True),
        ("README.md", True),
        ("docs/runbook.md", True),
        ("tests/fixtures/sigstore/trusted_root.json", True),
        ("deploy/primary-fingerprint.txt", True),
        ("setup.sh", False),
        ("products.yml", False),
        ("tests/unit/test_config.py", False),
        ("tests/fixturesx/a.py", False),
        ("deploy/other.txt", False),
    ],
)
def test_only_the_named_files_suffixes_and_folders_are_exempt(name: str, exempt: bool) -> None:
    assert _exempt(name) is exempt


def test_every_exemption_still_names_a_tracked_file_or_folder() -> None:
    tracked = tracked_files()
    for name in EXEMPT_FILES:
        assert name in tracked, name
    for suffix in EXEMPT_SUFFIXES:
        assert any(Path(name).suffix == suffix for name in tracked), suffix
    for folder in EXEMPT_FOLDERS:
        assert any(name.startswith(folder) for name in tracked), folder
