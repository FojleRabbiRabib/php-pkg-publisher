# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`release.yml`: the permissions, the order of the steps, and no ref name inside a script.

The deploy job only carries a bundle of the tag to the host: what it may hold and how it logs in
are fixed here, and the container test of the deploy host runs its scripts for real.
"""

from __future__ import annotations

import re
from typing import Any, Final

import pkg_deploy
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
BUNDLE: Final = "Bundle the tag"
SEND: Final = "Send the bundle to the host"
SECRETS: Final = ("DEPLOY_SSH_KEY", "DEPLOY_KNOWN_HOSTS", "DEPLOY_TARGET")


def _steps(job: str = "release") -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = RELEASE["jobs"][job]["steps"]
    return steps


def _named(name: str, job: str = "release") -> dict[str, Any]:
    (step,) = [s for s in _steps(job) if s.get("name") == name]
    return step


def _ssh_command() -> str:
    """The deploy step's ssh call as one line."""
    script: str = _named(SEND, "deploy")["run"]
    (command,) = re.findall(r"^ssh .*?(?<!\\)$", script.replace("\\\n", " "), re.M)
    return " ".join(command.split())


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
    assert RELEASE["jobs"]["deploy"]["permissions"] == {"contents": "read"}
    assert "secrets" not in RELEASE["jobs"]["ci"]


def test_the_checkout_has_the_whole_history_and_keeps_no_credentials() -> None:
    for job in ("release", "deploy"):
        (checkout,) = [s for s in _steps(job) if "actions/checkout@" in s.get("uses", "")]
        assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}, job


def test_no_script_holds_an_expression_so_a_ref_name_cannot_become_code() -> None:
    for job in ("release", "deploy"):
        for step in _steps(job):
            assert "${{" not in step.get("run", ""), step.get("name")
    for name in ("Take the notes from the changelog", "Check the tag", "Create the release"):
        assert _named(name)["env"]["TAG"] == "${{ github.ref_name }}"
    assert _named(BUNDLE, "deploy")["env"] == {"TAG": "${{ github.ref_name }}"}


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
    for job in ("release", "deploy"):
        for step in _steps(job):
            assert "continue-on-error" not in step
            assert "if" not in step
        assert "continue-on-error" not in RELEASE["jobs"][job]


def test_the_deploy_runs_after_the_release_in_the_environment_that_holds_the_secrets() -> None:
    job = RELEASE["jobs"]["deploy"]
    assert job["needs"] == "release"
    assert job["environment"] == "production"
    # one deploy at a time, and a running one is never cancelled half-way
    assert job["concurrency"] == {"group": "deploy", "cancel-in-progress": False}
    assert isinstance(job["timeout-minutes"], int)


def test_the_three_secrets_reach_only_the_one_step_that_logs_in() -> None:
    assert sorted(re.findall(r"secrets\.([A-Z_]+)", RELEASE_TEXT)) == sorted(SECRETS)
    expected = {name: f"${{{{ secrets.{name} }}}}" for name in SECRETS}
    assert _named(SEND, "deploy")["env"] == expected
    for step in _steps("deploy"):
        if step.get("name") != SEND:
            assert not any("secrets" in str(value) for value in step.get("env", {}).values())
    assert "secrets" not in RELEASE["jobs"]["release"]
    assert "secrets" not in RELEASE["jobs"]["ci"]


def test_the_bundle_is_made_from_the_tag_object_and_checked_before_it_leaves() -> None:
    script = _named(BUNDLE, "deploy")["run"]
    order = [
        '[[ "$TAG" =~ ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$ ]]',
        'git fetch --no-tags origin "+refs/tags/$TAG:refs/tags/$TAG"',
        'test "$(git cat-file -t "refs/tags/$TAG")" = tag',
        'git bundle create "$RUNNER_TEMP/tag.bundle" "refs/tags/$TAG"',
        'git --git-dir="$RUNNER_TEMP/verify.git" bundle verify "$RUNNER_TEMP/tag.bundle"',
        'test "$(stat -c %s "$RUNNER_TEMP/tag.bundle")" -le ',
    ]
    positions = [script.index(part) for part in order]
    assert positions == sorted(positions)
    # the size limit is the one the host enforces
    assert f"-le {pkg_deploy.MAX_BUNDLE_BYTES}\n" in script
    assert _named(BUNDLE, "deploy")["shell"] == "bash"


def test_the_login_pins_the_host_and_the_key_and_prints_nothing_else() -> None:
    command = _ssh_command()
    for option in (
        "ssh -q -F /dev/null",
        "-T",
        '-i "$RUNNER_TEMP/deploy_key"',
        "-o IdentitiesOnly=yes",
        "-o BatchMode=yes",
        "-o StrictHostKeyChecking=yes",
        '-o UserKnownHostsFile="$RUNNER_TEMP/known_hosts"',
        "-o GlobalKnownHostsFile=/dev/null",
        '-- "$DEPLOY_TARGET" < "$RUNNER_TEMP/tag.bundle"',
    ):
        assert option in command, option
    # the bundle is read from a file, so a failed `git bundle` cannot hide behind a pipe
    assert "|" not in command
    for forbidden in ("StrictHostKeyChecking=no", "accept-new", "UserKnownHostsFile=/dev/null"):
        assert forbidden not in RELEASE_TEXT, forbidden
    assert "ssh-keyscan" not in RELEASE_TEXT
    assert "set -x" not in RELEASE_TEXT
    script = _named(SEND, "deploy")["run"]
    assert script.index("umask 077") < script.index('deploy_key"\n')
    assert _named(SEND, "deploy")["shell"] == "bash"
