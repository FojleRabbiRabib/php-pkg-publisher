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
GPG: Final = "/usr/bin/gpg"
GPGCONF: Final = "/usr/bin/gpgconf"
SSH_KEYGEN: Final = "/usr/bin/ssh-keygen"
_IDENTITY: Final = ["-c", "user.name=T", "-c", "user.email=t@example.invalid"]
_OPENPGP_USER: Final = "openpgp@example.invalid"
ENVIRONMENT: Final = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}


def run(
    arguments: list[str], cwd: Path | None = None, *, environment: dict[str, str] | None = None
) -> str:
    done = subprocess.run(  # noqa: S603
        arguments,
        cwd=cwd,
        env={**ENVIRONMENT, **(environment or {})},
        capture_output=True,
        check=True,
        text=True,
    )
    return done.stdout


def generate_key(path: Path) -> None:
    run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", os.fspath(path)])


def _commit(folder: Path, files: dict[str, bytes], label: str) -> Path:
    """A repository with one commit holding `files`."""
    repo = folder / f"repo-{label}"
    repo.mkdir()
    run([GIT, "init", "-q", "-b", "main"], repo)
    for name, data in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    run([GIT, "add", "-A"], repo)
    run([GIT, *_IDENTITY, "commit", "-q", "-m", "x"], repo)
    return repo


def _bundle(repo: Path, tag: str) -> bytes:
    done = subprocess.run(  # noqa: S603
        [GIT, "bundle", "create", "-", tag],
        cwd=repo,
        env=ENVIRONMENT,
        capture_output=True,
        check=True,
    )
    return done.stdout


def signed_bundle(
    folder: Path,
    keys: dict[str, Path],
    files: dict[str, bytes],
    tag: str,
    *,
    signer: str | None = "release",
) -> bytes:
    """A bundle of one tag over a commit holding `files`, signed by the named key."""
    repo = _commit(folder, files, f"{tag}-{signer}")
    base = ["-c", "gpg.format=ssh", *_IDENTITY]
    if signer is None:
        run([GIT, *base, "tag", "-a", tag, "-m", f"Release {tag}"], repo)
    else:
        key = ["-c", f"user.signingkey={keys[signer]}"]
        run([GIT, *base, *key, "tag", "-s", tag, "-m", f"Release {tag}"], repo)
    return _bundle(repo, tag)


def openpgp_bundle(folder: Path, files: dict[str, bytes], tag: str) -> tuple[bytes, bytes]:
    """A bundle of one tag signed with OpenPGP, and the armored public key that verifies it."""
    home = folder / f"gnupg-{tag}"
    home.mkdir(mode=0o700)
    environment = {"GNUPGHOME": os.fspath(home)}
    gpg = [GPG, "--batch", "--no-tty"]
    run(
        [
            *gpg,
            "--passphrase",
            "",
            "--quick-generate-key",
            _OPENPGP_USER,
            "ed25519",
            "sign",
            "never",
        ],
        environment=environment,
    )
    try:
        repo = _commit(folder, files, f"{tag}-openpgp")
        base = ["-c", "gpg.format=openpgp", "-c", f"gpg.program={GPG}", *_IDENTITY]
        key = ["-c", f"user.signingkey={_OPENPGP_USER}"]
        run(
            [GIT, *base, *key, "tag", "-s", tag, "-m", f"Release {tag}"],
            repo,
            environment=environment,
        )
        public = run([*gpg, "--armor", "--export", _OPENPGP_USER], environment=environment)
    finally:
        # the agent the key generation started would keep the folder busy
        run([GPGCONF, "--kill", "all"], environment=environment)
    return _bundle(repo, tag), public.encode()
