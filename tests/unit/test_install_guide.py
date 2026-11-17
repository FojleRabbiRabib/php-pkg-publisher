# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The install guide against the code: the files it tells a person to write are the files
`setup.sh` writes, and its placeholders are the only ones it uses. The commands themselves are
run on real clients by `tests/container/test_docs.py`.
"""

from __future__ import annotations

import re

from docblocks import GUIDE, SITE, blocks
from setupkit import repo, sources


def _block(family: str, *, containing: str) -> str:
    (found,) = [b.text for b in blocks() if b.family == family and containing in b.text]
    return found


def test_the_apt_sources_file_in_the_guide_is_the_one_setup_sh_writes() -> None:
    block = _block("apt", containing="Types: deb")
    written = block.split("<<'EOF'\n")[1].split("EOF\n")[0]
    assert written == sources(SITE)


def test_the_dnf_repository_file_in_the_guide_is_the_one_setup_sh_writes() -> None:
    block = _block("dnf", containing="[rabib-php83]")
    written = block.split("<<'EOF'\n")[1].split("\nEOF")[0] + "\n"
    assert written == repo(SITE, {"8.3"})


def test_the_guide_has_both_flows_and_removes_what_it_installs() -> None:
    found = blocks()
    for family in ("apt", "dnf"):
        assert any(b.family == family and not b.remove for b in found)
        assert any(b.family == family and b.remove for b in found)


def test_the_guide_uses_one_placeholder_for_the_extension_and_one_for_the_fingerprint() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    assert set(re.findall(r"<[a-z][a-z -]*>", text)) <= {
        "<extension>",
        "<fingerprint published with the key ceremony>",
    }
    assert not re.search(r"\b[0-9A-F]{40}\b", text), "a real fingerprint must not be in the guide"
