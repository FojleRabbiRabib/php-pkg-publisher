# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The published primary key fingerprint is one value in four places: the pin file the outside
watch reads, the README, and the install guide twice. Going live changes all four in one commit.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
PLACEHOLDER: Final = "<fingerprint published with the key ceremony>"
FENCE: Final = re.compile(r"```text\n(.*?)\n```", re.DOTALL)


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _pin() -> str:
    return _read("deploy/primary-fingerprint.txt").strip()


def _section(text: str, heading: str) -> str:
    (body,) = re.findall(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return str(body)


def test_the_pin_is_the_placeholder_or_forty_uppercase_hexadecimal_digits() -> None:
    assert _pin() == PLACEHOLDER or re.fullmatch(r"[0-9A-F]{40}", _pin())


def test_the_readme_publishes_the_pin() -> None:
    (shown,) = FENCE.findall(_section(_read("README.md"), "The key fingerprint"))
    assert shown == _pin()


def test_the_install_guide_shows_the_pin_in_its_block_and_in_the_setup_command() -> None:
    text = _read("docs/installation.md")
    (shown,) = FENCE.findall(_section(text, "Before you trust anything: the fingerprint"))
    assert shown == _pin()
    assert re.findall(r"sh setup\.sh --fingerprint (.+)", text) == [_pin()]


def test_the_readme_section_comes_before_the_description_of_how_it_works() -> None:
    text = _read("README.md")
    assert text.index("## The key fingerprint") < text.index("## How it will work")
