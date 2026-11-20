# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The repository root and the files git tracks, for tests that check the repository itself."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]


def tracked_files() -> list[str]:
    """Every tracked path, sorted; a checkout without git fails the test that asks."""
    git = shutil.which("git")
    assert git is not None, "git is needed to list the tracked files"
    assert (ROOT / ".git").exists(), "the tracked files are listed from a git checkout"
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [git, "-C", str(ROOT), "ls-files", "-z"], check=True, capture_output=True, text=True
    )
    return sorted(name for name in done.stdout.split("\0") if name)
