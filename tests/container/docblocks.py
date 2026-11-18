# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The runnable command blocks of the install guide.

A block is a fenced `sh` block whose info string is `{family=apt}` or `{family=dnf}`, with an
optional `phase=remove` for the blocks that undo the install. The container test runs them in
document order on a real client, so a command the guide documents is a command that was run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final, Literal, NamedTuple

GUIDE: Final = Path(__file__).resolve().parents[2] / "docs" / "installation.md"
SITE: Final = "https://pkg.rabib.me"
FENCE: Final = re.compile(
    r"^```sh \{family=(apt|dnf)(?: phase=(remove))?\}\n(.*?)\n```$", re.MULTILINE | re.DOTALL
)


class Block(NamedTuple):
    family: Literal["apt", "dnf"]
    remove: bool
    text: str


def blocks() -> list[Block]:
    text = GUIDE.read_text(encoding="utf-8")
    found = [
        Block("apt" if family == "apt" else "dnf", phase == "remove", body)
        for family, phase, body in FENCE.findall(text)
    ]
    assert found, "docs/installation.md has no runnable block"
    return found


def runnable(block: Block, *, site: str, extension: str) -> str:
    """The block as a root shell runs it against `site`: no `sudo`, the placeholder filled in."""
    return block.text.replace(SITE, site).replace("<extension>", extension)
