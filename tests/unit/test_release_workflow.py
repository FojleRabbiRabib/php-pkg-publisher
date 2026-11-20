# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`release.yml`: the permissions, the order of the steps, and no ref name inside a script."""

from __future__ import annotations

from typing import Any, Final

import yaml
from repofiles import ROOT

WORKFLOWS: Final = ROOT / ".github" / "workflows"
RELEASE_TEXT: Final = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
RELEASE: Final[dict[Any, Any]] = yaml.safe_load(RELEASE_TEXT)
CI: Final[dict[Any, Any]] = yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))
# PyYAML reads the key `on` as the boolean True
ON: Final = True
# the title is written with an en dash; a hyphen must fail the test
EN_DASH: Final = chr(0x2013)


def _steps() -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = RELEASE["jobs"]["release"]["steps"]
    return steps


def _named(name: str) -> dict[str, Any]:
    (step,) = [s for s in _steps() if s.get("name") == name]
    return step


def test_only_a_pushed_tag_starts_it() -> None:
    assert RELEASE[ON] == {"push": {"tags": ["v*"]}}


def test_every_ci_gate_runs_first_through_the_same_workflow() -> None:
    assert RELEASE["jobs"]["ci"]["uses"] == "./.github/workflows/ci.yml"
    assert "workflow_call" in CI[ON]
    assert RELEASE["jobs"]["release"]["needs"] == "ci"


def test_nothing_may_write_except_the_release_job() -> None:
    assert RELEASE["permissions"] == {}
    assert RELEASE["jobs"]["ci"]["permissions"] == {"contents": "read"}
    assert RELEASE["jobs"]["release"]["permissions"] == {"contents": "write"}
    assert "secrets" not in RELEASE["jobs"]["ci"]


def test_the_checkout_has_the_whole_history_and_keeps_no_credentials() -> None:
    (checkout,) = [s for s in _steps() if "actions/checkout@" in s.get("uses", "")]
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}


def test_no_script_holds_an_expression_so_a_ref_name_cannot_become_code() -> None:
    for step in _steps():
        assert "${{" not in step.get("run", ""), step["name"]
    for name in ("Take the notes from the changelog", "Check the tag", "Create the release"):
        assert _named(name)["env"]["TAG"] == "${{ github.ref_name }}"


def test_the_tool_checks_the_tag_before_anything_else_uses_it() -> None:
    names = [s.get("name") for s in _steps()]
    assert names.index("Take the notes from the changelog") < names.index("Check the tag")
    assert names.index("Check the tag") < names.index("Create the release")
    assert _named("Take the notes from the changelog")["run"] == (
        'python3 tools/release_notes.py "$TAG" > "$RUNNER_TEMP/notes.md"'
    )


def test_the_tag_must_be_annotated_and_on_main() -> None:
    script = _named("Check the tag")["run"]
    assert '--jq .object.type)" = tag' in script
    assert "git merge-base --is-ancestor HEAD origin/main" in script


def test_the_release_has_the_ruled_title_the_notes_and_a_verified_tag() -> None:
    script = " ".join(_named("Create the release")["run"].replace("\\\n", " ").split())
    assert script == (
        f'gh release create "$TAG" --verify-tag --title "PHP Package Publisher {EN_DASH} $TAG" '
        '--notes-file "$RUNNER_TEMP/notes.md"'
    )


def test_a_failed_step_stops_the_job() -> None:
    for step in _steps():
        assert "continue-on-error" not in step
        assert "if" not in step
