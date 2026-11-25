# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`tools/release_notes.py`: the tag and the changelog decide whether a release can be made."""

from __future__ import annotations

from pathlib import Path

import pytest
import release_notes
from release_notes import ReleaseNotesError, notes

from publisher import config

GOOD = """# Changelog

## [Unreleased]

### Added

## [1.2.3] - 2026-11-20

### Added

- the first thing
- the second thing

### Fixed

- a bug

## [1.2.2] - 2026-10-01

- older
"""


def test_the_notes_are_the_body_of_the_section_of_the_tag() -> None:
    assert notes(GOOD, "v1.2.3") == (
        "### Added\n\n- the first thing\n- the second thing\n\n### Fixed\n\n- a bug\n"
    )
    assert notes(GOOD, "v1.2.2") == "- older\n"


def test_an_unreleased_section_with_only_headings_or_nothing_is_fine() -> None:
    assert notes("## [Unreleased]\n\n## [1.0.0] - 2026-01-02\n\n- x\n", "v1.0.0") == "- x\n"
    assert notes("## [1.0.0] - 2026-01-02\n\n- x\n", "v1.0.0") == "- x\n"


def test_link_definitions_at_the_end_are_neither_entries_nor_notes() -> None:
    links = "\n[Unreleased]: https://example.invalid/a\n[1.0.0]: https://example.invalid/b\n"
    with pytest.raises(ReleaseNotesError, match="no entries"):
        notes("## [Unreleased]\n\n## [1.0.0] - 2026-01-02\n\n### Added\n" + links, "v1.0.0")
    assert notes("## [Unreleased]\n\n## [1.0.0] - 2026-01-02\n\n- x\n" + links, "v1.0.0") == "- x\n"
    # a link definition alone does not make [Unreleased] count as holding entries
    assert notes("## [Unreleased]\n" + links + "\n## [1.0.0] - 2026-01-02\n\n- x\n", "v1.0.0") == (
        "- x\n"
    )


@pytest.mark.parametrize("heading", ["## [unreleased]", "## [UNRELEASED]"])
def test_an_unreleased_heading_in_any_letter_case_is_checked(heading: str) -> None:
    with pytest.raises(ReleaseNotesError, match="Unreleased"):
        notes(f"{heading}\n\n- forgotten\n\n## [1.0.0] - 2026-01-02\n\n- x\n", "v1.0.0")


@pytest.mark.parametrize(
    "tag",
    [
        "1.2.3",
        "v1.2",
        "v1.2.3.4",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v1.2.3-rc1",
        "V1.2.3",
        "v1.2.3\n",
    ],
)
def test_a_tag_that_is_not_a_final_tag_is_refused(tag: str) -> None:
    with pytest.raises(ReleaseNotesError, match="not a final tag"):
        notes(GOOD, tag)


def test_the_tag_rule_is_the_publishers_final_tag_rule() -> None:
    for tag in (
        "v1.2.3",
        "v0.0.0",
        "v10.20.30",
        "v01.2.3",
        "v1.02.3",
        "v1.2",
        "v1.2.3-rc1",
        "1.2.3",
    ):
        assert bool(release_notes.TAG.fullmatch(tag)) == bool(config.FINAL_TAG.fullmatch(tag)), tag


def test_a_missing_section_is_refused() -> None:
    with pytest.raises(ReleaseNotesError, match=r"no section \[1\.2\.4\]"):
        notes(GOOD, "v1.2.4")


def test_a_repeated_section_is_refused() -> None:
    text = GOOD + "\n## [1.2.3] - 2026-11-21\n\n- again\n"
    with pytest.raises(ReleaseNotesError, match="more than one section"):
        notes(text, "v1.2.3")


@pytest.mark.parametrize(
    "heading",
    [
        "## [1.2.3]",
        "## [1.2.3] - 20261120",
        "## [1.2.3] - 2026-13-01",
        "## [1.2.3] - 2026-02-30",
        "## [1.2.3] - 2026-1-2",
        "## [1.2.3] - today",
    ],
)
def test_a_section_without_a_real_date_is_refused(heading: str) -> None:
    with pytest.raises(ReleaseNotesError, match="date"):
        notes(f"## [Unreleased]\n\n{heading}\n\n- x\n", "v1.2.3")


def test_a_section_without_entries_is_refused() -> None:
    with pytest.raises(ReleaseNotesError, match="no entries"):
        notes("## [1.2.3] - 2026-11-20\n\n### Added\n\n", "v1.2.3")


def test_an_unreleased_section_that_still_has_entries_is_refused() -> None:
    text = "## [Unreleased]\n\n- forgotten\n\n## [1.2.3] - 2026-11-20\n\n- x\n"
    with pytest.raises(ReleaseNotesError, match="Unreleased"):
        notes(text, "v1.2.3")
    # also when it is not the first section
    text = "## [1.2.3] - 2026-11-20\n\n- x\n\n## [Unreleased]\n\n- forgotten\n"
    with pytest.raises(ReleaseNotesError, match="Unreleased"):
        notes(text, "v1.2.3")


def test_a_section_heading_of_another_shape_is_refused() -> None:
    with pytest.raises(ReleaseNotesError, match="section heading"):
        notes("## Unreleased\n\n## [1.2.3] - 2026-11-20\n\n- x\n", "v1.2.3")


def test_text_before_the_first_section_is_not_part_of_any_notes() -> None:
    assert notes("intro\n\n## [1.0.0] - 2026-01-02\n\n- x\n", "v1.0.0") == "- x\n"


def test_the_command_prints_the_notes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(GOOD, encoding="utf-8")
    assert release_notes.main(["v1.2.2", "--changelog", str(path)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "- older\n"
    assert captured.err == ""


def test_the_command_fails_with_one_line_and_prints_no_notes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(GOOD, encoding="utf-8")
    assert release_notes.main(["v9.9.9", "--changelog", str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "RELEASE NOTES FAILED: the changelog has no section [9.9.9]\n"
    assert release_notes.main(["v1.2.3", "--changelog", str(tmp_path / "missing.md")]) == 1
    assert capsys.readouterr().err.startswith("RELEASE NOTES FAILED: ")


def test_the_real_changelog_has_sections_this_tool_can_read() -> None:
    text = release_notes.DEFAULT_CHANGELOG.read_text(encoding="utf-8")
    sections = release_notes._sections(text)
    assert sections[0][0] == release_notes.UNRELEASED
    assert [name for name, _date, _body in sections].count(release_notes.UNRELEASED) == 1
