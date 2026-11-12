# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""One distribution container with a real `apt` or `dnf` in it, driven command by command.

The container shares the host's network so it reaches the loopback `Mirror`; the only host
directory it sees is `kit`, read-only: the two public keys and the client configuration. Every
command is an argument array handed to `docker exec`, never a shell string.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import TracebackType
from typing import Final, NamedTuple

from images import Image

from publisher.admit import MIN_FREE_BYTES

DOCKER: Final = "docker"
START_TIMEOUT: Final = 120.0
COMMAND_TIMEOUT: Final = 600.0
# The admit stage refuses a release below `MIN_FREE_BYTES`, so a run needs headroom above it.
FREE_DISK_NEEDED: Final = MIN_FREE_BYTES * 3 // 2


class Done(NamedTuple):
    code: int
    output: str


def require_free_disk(directory: Path, minimum: int) -> None:
    """Fail with a named error when `directory` has less than `minimum` bytes free.

    Without it, a full disk shows up as a refused release in the middle of a test.
    """
    free = shutil.disk_usage(directory).free
    if free < minimum:
        raise OSError(
            f"the container layer needs {minimum >> 20} MiB free for {directory}, "
            f"only {free >> 20} MiB are free (the admit stage refuses below "
            f"{MIN_FREE_BYTES >> 20} MiB)"
        )


def docker_available() -> bool:
    try:
        done = subprocess.run(  # noqa: S603
            [DOCKER, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


class Box:
    def __init__(self, image: Image, kit: Path) -> None:
        self._image = image
        self._kit = kit
        self._id: str | None = None

    def __enter__(self) -> Box:
        started = subprocess.run(  # noqa: S603
            [
                DOCKER,
                "run",
                "--detach",
                "--rm",
                "--pull",
                "never",
                "--security-opt",
                "no-new-privileges",
                "--network",
                "host",
                "--volume",
                f"{self._kit}:/kit:ro",
                self._image.reference,
                "sleep",
                "infinity",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=START_TIMEOUT,
        )
        assert started.returncode == 0, started.stderr
        self._id = started.stdout.strip()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        if self._id is not None:
            subprocess.run(  # noqa: S603
                [DOCKER, "rm", "--force", self._id],
                capture_output=True,
                check=False,
                timeout=60,
            )

    def run(self, *command: str, user: str | None = None) -> Done:
        """Run a command in the container, as root unless `user` (a name or numeric id) is given."""
        assert self._id is not None
        who = ["--user", user] if user is not None else []
        done = subprocess.run(  # noqa: S603
            [
                DOCKER,
                "exec",
                *who,
                "--env",
                "DEBIAN_FRONTEND=noninteractive",
                self._id,
                *command,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT,
        )
        return Done(done.returncode, done.stdout + done.stderr)
