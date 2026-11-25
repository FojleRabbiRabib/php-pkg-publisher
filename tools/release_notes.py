# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The notes of one release, taken from `CHANGELOG.md`: `python tools/release_notes.py vX.Y.Z`.

The release workflow runs it on the pushed tag and gives its output to GitHub as the release
notes. It fails closed: the tag must be a final tag (`vX.Y.Z`, no leading zeros, the rule the
publisher applies to a product's tags), the changelog must hold exactly one `## [X.Y.Z] - DATE`
section with a real date and at least one entry, and `## [Unreleased]` must hold none, because an
entry left there would be missing from the notes. Only the standard library is used, so it runs
on a bare runner.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path
from typing import Final

_NUMBER: Final = r"(?:0|[1-9][0-9]*)"
TAG: Final = re.compile(rf"v({_NUMBER}\.{_NUMBER}\.{_NUMBER})")
HEADING: Final = re.compile(r"## \[([^\]]+)\](?: - (\S+))?[ \t]*")
UNRELEASED: Final = "Unreleased"
# the `[x.y.z]: url` lines that end a Keep a Changelog file are neither entries nor notes
LINK_DEFINITION: Final = re.compile(r"\[[^\]]+\]:\s*\S+")
DEFAULT_CHANGELOG: Final = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


class ReleaseNotesError(Exception):
    """The changelog or the tag does not allow a release."""


def _entries(body: list[str]) -> bool:
    """Whether a section holds an entry: any line that is neither blank nor a heading."""
    return any(line.strip() and not line.startswith("#") for line in body)


def _sections(text: str) -> list[tuple[str, str | None, list[str]]]:
    """The `## [name] - date` sections as (name, date, body lines), in file order."""
    found: list[tuple[str, str | None, list[str]]] = []
    for line in text.splitlines():
        if line.startswith("## "):
            match = HEADING.fullmatch(line)
            if match is None:
                raise ReleaseNotesError(f"a section heading is not '## [name] - date': {line!r}")
            found.append((match.group(1), match.group(2), []))
        elif found and not LINK_DEFINITION.fullmatch(line.strip()):
            found[-1][2].append(line)
    return found


def _date(value: str | None, version: str) -> None:
    # fromisoformat also takes forms like 20261120 in newer Pythons; the heading is yyyy-mm-dd
    if value is None or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ReleaseNotesError(f"the section [{version}] has no date written yyyy-mm-dd")
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        raise ReleaseNotesError(
            f"the section [{version}] has the impossible date {value}"
        ) from None


def notes(changelog: str, tag: str) -> str:
    """The body of the changelog section of `tag`, or the reason there is none."""
    match = TAG.fullmatch(tag)
    if match is None:
        raise ReleaseNotesError(f"{tag!r} is not a final tag (vX.Y.Z, no leading zeros)")
    version = match.group(1)
    sections = _sections(changelog)
    for name, _date_text, body in sections:
        if name.casefold() == UNRELEASED.casefold() and _entries(body):
            raise ReleaseNotesError(
                f"[{UNRELEASED}] still has entries; move them under [{version}] first"
            )
    wanted = [s for s in sections if s[0] == version]
    if not wanted:
        raise ReleaseNotesError(f"the changelog has no section [{version}]")
    if len(wanted) > 1:
        raise ReleaseNotesError(f"the changelog has more than one section [{version}]")
    _name, date_text, body = wanted[0]
    _date(date_text, version)
    if not _entries(body):
        raise ReleaseNotesError(f"the section [{version}] has no entries")
    return "\n".join(body).strip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the changelog notes of a release tag.")
    parser.add_argument("tag", help="the release tag, vX.Y.Z")
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    args = parser.parse_args(argv)
    try:
        text = args.changelog.read_text(encoding="utf-8")
        output = notes(text, args.tag)
    except (OSError, UnicodeDecodeError, ReleaseNotesError) as error:
        print(f"RELEASE NOTES FAILED: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
