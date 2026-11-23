# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Signed release tags for the deploy script's tests: real git, real `ssh-keygen`, throwaway keys.

Shared by the unit tests, which give the script a fake host, and the container test, which runs
the installed file behind a real sshd and sudo.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Final

GIT: Final = "/usr/bin/git"
SSH_KEYGEN: Final = "/usr/bin/ssh-keygen"
ENVIRONMENT: Final = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}


def run(arguments: list[str], cwd: Path | None = None) -> str:
    done = subprocess.run(  # noqa: S603
        arguments, cwd=cwd, env=ENVIRONMENT, capture_output=True, check=True, text=True
    )
    return done.stdout


def generate_key(path: Path) -> None:
    run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", os.fspath(path)])


def signed_bundle(
    folder: Path,
    keys: dict[str, Path],
    files: dict[str, bytes],
    tag: str,
    *,
    signer: str | None = "release",
) -> bytes:
    """A bundle of one tag over a commit holding `files`, signed by the named key."""
    repo = folder / f"repo-{tag}-{signer}"
    repo.mkdir()
    base = ["-c", "gpg.format=ssh", "-c", "user.name=T", "-c", "user.email=t@example.invalid"]
    run([GIT, "init", "-q", "-b", "main"], repo)
    for name, data in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    run([GIT, "add", "-A"], repo)
    run([GIT, *base, "commit", "-q", "-m", "x"], repo)
    if signer is None:
        run([GIT, *base, "tag", "-a", tag, "-m", f"Release {tag}"], repo)
    else:
        key = ["-c", f"user.signingkey={keys[signer]}"]
        run([GIT, *base, *key, "tag", "-s", tag, "-m", f"Release {tag}"], repo)
    done = subprocess.run(  # noqa: S603
        [GIT, "bundle", "create", "-", tag],
        cwd=repo,
        env=ENVIRONMENT,
        capture_output=True,
        check=True,
    )
    return done.stdout
