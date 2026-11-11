# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Read the docroot `.htaccess` for the tests: its rules, and its redirect as a function."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

FILE = Path(__file__).resolve().parents[2] / "web" / "docroot.htaccess"
OWNER = "https://github.com/FojleRabbiRabib/"


@dataclass(frozen=True)
class Rule:
    pattern: str
    target: str
    flags: str


def directive_lines() -> list[str]:
    return [
        line.strip()
        for line in FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def rewrite_rules() -> list[Rule]:
    found = []
    for line in directive_lines():
        if line.startswith("RewriteRule "):
            pattern, target, flags = line.split()[1:4]
            found.append(Rule(pattern, target, flags.strip("[]")))
    return found


REDIRECT = rewrite_rules()[2]
_STATUS = re.search(r"R=([0-9]{3})", REDIRECT.flags)
assert _STATUS is not None
REDIRECT_STATUS = int(_STATUS.group(1))


def redirect(path: str) -> str | None:
    """The Location a request path gets, or None when the rule does not match."""
    match = re.search(REDIRECT.pattern, path.removeprefix("/"))
    if match is None:
        return None
    return re.sub(r"\$([0-9])", lambda m: str(match.group(int(m[1]))), REDIRECT.target)
