# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""One distribution container with a real `apt` or `dnf` in it, driven command by command.

The container shares the host's network so it reaches the loopback `Mirror`; the only host
directory it sees is `kit`, read-only: the two public keys and the client configuration. Every
command is an argument array handed to `docker exec`, never a shell string.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import TracebackType
from typing import Final, NamedTuple

from images import Image

DOCKER: Final = "docker"
START_TIMEOUT: Final = 120.0
COMMAND_TIMEOUT: Final = 600.0


class Done(NamedTuple):
    code: int
    output: str


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

    def run(self, *command: str) -> Done:
        assert self._id is not None
        done = subprocess.run(  # noqa: S603
            [DOCKER, "exec", "--env", "DEBIAN_FRONTEND=noninteractive", self._id, *command],
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT,
        )
        return Done(done.returncode, done.stdout + done.stderr)
