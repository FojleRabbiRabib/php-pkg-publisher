# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The distributions the container layer installs from, each pinned to an image digest.

The packages are fakes with no PHP in them, so every distribution is exercised the same way.
Refresh a digest by pulling the tag and reading it back with
`docker image inspect --format '{{index .RepoDigests 0}}' <name>:<tag>`.
"""

from __future__ import annotations

from typing import Final, Literal, NamedTuple


class Image(NamedTuple):
    reference: str
    family: Literal["apt", "dnf"]


IMAGES: Final[dict[str, Image]] = {
    "ubuntu-22.04": Image(
        "ubuntu@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11", "apt"
    ),
    "ubuntu-24.04": Image(
        "ubuntu@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60", "apt"
    ),
    "ubuntu-26.04": Image(
        "ubuntu@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c", "apt"
    ),
    "debian-bookworm": Image(
        "debian@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880", "apt"
    ),
    "debian-trixie": Image(
        "debian@sha256:2dc419c6d7fe3dad0a2f9fd469c34cc90b0f9ba642d8fde837fe3d7d34a0e7f1", "apt"
    ),
    "almalinux-8": Image(
        "almalinux@sha256:2d0f2eb2a83cc09dbc2eb92fade4dbe8f709628149e81aa00aec70630406603b", "dnf"
    ),
    "almalinux-9": Image(
        "almalinux@sha256:245f8aab832fe800aa42bdab5fad75ebbd8e0b4c9f24820a83c638b177857ae2", "dnf"
    ),
    "almalinux-10": Image(
        "almalinux@sha256:5a4b41a427c9717be8f4ac2a32aa22efbae5f9124fbcb79a6765394f312acfe8", "dnf"
    ),
    "fedora-44": Image(
        "fedora@sha256:15da97ed9aa94dd3d92c3925eb89520f6c80e07ea7ee24cba848d1f8b6912b3e", "dnf"
    ),
}
