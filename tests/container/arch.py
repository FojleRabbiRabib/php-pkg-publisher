# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The one place that decides which architecture the container layer's clients run.

A container runs the architecture of the docker server, so CI's native arm runner tests `arm64`
(apt) and `aarch64` (dnf) and the other runner tests `amd64` and `x86_64`. To run the other
architecture under emulation, set `CONTAINER_ARCH` to `amd64` or `arm64`; the containers then
start with that `--platform`. It is a smoke run only: the native runner is the proof. The image
must already be stored for that platform (containers start with `--pull never`), and docker keeps
one platform per image digest, so pulling the other platform's copy of a pinned digest fails with
"cannot overwrite digest" until the stored copy is removed.
"""

from __future__ import annotations

import functools
import os
import subprocess
from typing import Final, NamedTuple


class Arch(NamedTuple):
    deb: str
    rpm: str


ARCHITECTURES: Final = {"amd64": Arch("amd64", "x86_64"), "arm64": Arch("arm64", "aarch64")}
ENVIRONMENT: Final = "CONTAINER_ARCH"


@functools.cache
def native() -> Arch:
    """The architecture the containers run: `CONTAINER_ARCH`, else the docker server's own."""
    name = os.environ.get(ENVIRONMENT)
    if not name:
        done = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Arch}}"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if done.returncode != 0:
            raise OSError(f"docker did not report its architecture: {done.stderr.strip()}")
        name = done.stdout.strip()
    if name not in ARCHITECTURES:
        raise OSError(f"no container tests for {name!r}; they cover {sorted(ARCHITECTURES)}")
    return ARCHITECTURES[name]
