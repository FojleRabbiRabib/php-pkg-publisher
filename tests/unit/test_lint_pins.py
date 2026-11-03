# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

from pathlib import Path

import lint_pins
import pytest

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
DIGEST = "sha256:" + "a" * 64
HEADER = "permissions:\n  contents: read\n"


def _workflow(root: Path, body: str, name: str = "ci.yml") -> Path:
    directory = root / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


def _messages(root: Path) -> list[str]:
    return [finding.message for finding in lint_pins.lint_tree(root)]


def _jobs(body: str) -> str:
    return f"{HEADER}jobs:\n  a:\n{body}"


def test_fully_pinned_workflow_passes(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        "# never grant id-token: write\n"
        f"{HEADER}"
        "on:\n  push:\n  pull_request:\n"
        "jobs:\n  a:\n"
        f"    container:\n      image: php@{DIGEST}\n"
        f"    services:\n      db:\n        image: postgres@{DIGEST}\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{SHA} # v7\n"
        f'      - uses: "actions/checkout@{SHA}"\n'
        "      # - uses: actions/checkout@v4\n"
        "      - uses: ./local\n"
        f"      - uses: docker://alpine@{DIGEST}\n"
        "      - run: echo id-token write\n"
        "  b:\n"
        f"    uses: org/repo/.github/workflows/x.yml@{SHA}\n",
    )
    assert _messages(tmp_path) == []


def test_yaml_extension_is_scanned(tmp_path: Path) -> None:
    _workflow(tmp_path, _jobs("    steps:\n      - uses: actions/checkout@v4\n"), "ci.yaml")
    assert _messages(tmp_path) == ["actions/checkout@v4 is not pinned to a commit SHA"]


@pytest.mark.parametrize(
    "step",
    [
        "      - uses: actions/checkout@v4\n",
        "      - uses: actions/checkout@3d3c42e\n",
        f"      - uses: actions/checkout@{SHA.upper()}\n",
        "      - {uses: actions/checkout@v4}\n",
        "      - uses:\n          actions/checkout@v4\n",
        "      - uses: 'actions/checkout@v4'\n",
    ],
)
def test_unpinned_step_uses_is_rejected(tmp_path: Path, step: str) -> None:
    _workflow(tmp_path, _jobs(f"    steps:\n{step}"))
    messages = _messages(tmp_path)
    assert len(messages) == 1
    assert "is not pinned to a commit SHA" in messages[0]


def test_unpinned_reusable_workflow_is_rejected(tmp_path: Path) -> None:
    _workflow(tmp_path, f"{HEADER}jobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@main\n")
    assert any("is not pinned to a commit SHA" in m for m in _messages(tmp_path))


def test_unpinned_docker_reference_is_rejected(tmp_path: Path) -> None:
    _workflow(tmp_path, _jobs("    steps:\n      - uses: docker://alpine:3.22\n"))
    assert _messages(tmp_path) == ["docker://alpine:3.22 is not pinned by digest"]


@pytest.mark.parametrize(
    "block",
    [
        "    container: node:20\n",
        "    container:\n      image: php:8.3-alpine\n",
        "    services:\n      db:\n        image: postgres:16\n",
    ],
)
def test_container_and_service_images_need_a_digest(tmp_path: Path, block: str) -> None:
    _workflow(tmp_path, _jobs(block))
    assert any("is not pinned by digest" in m for m in _messages(tmp_path))


def test_string_container_with_digest_passes(tmp_path: Path) -> None:
    _workflow(tmp_path, _jobs(f"    container: php@{DIGEST}\n"))
    assert _messages(tmp_path) == []


def test_expression_built_image_is_rejected_with_a_clear_message(tmp_path: Path) -> None:
    _workflow(tmp_path, _jobs("    container:\n      image: ${{ matrix.image }}\n"))
    assert _messages(tmp_path) == [
        "image ${{ matrix.image }} is built from an expression; inline it"
    ]


@pytest.mark.parametrize(
    "grant",
    [
        "      id-token: write\n",
        '      id-token: "write"\n',
        "      id-token: 'write'\n",
        '      "id-token": write\n',
    ],
)
def test_id_token_write_is_rejected_in_every_spelling(tmp_path: Path, grant: str) -> None:
    _workflow(tmp_path, _jobs(f"    permissions:\n{grant}"))
    assert "id-token: write is not allowed here" in _messages(tmp_path)


def test_id_token_none_is_not_flagged(tmp_path: Path) -> None:
    _workflow(tmp_path, _jobs("    permissions:\n      id-token: none\n"))
    assert _messages(tmp_path) == []


def test_write_all_is_rejected_at_any_level(tmp_path: Path) -> None:
    _workflow(tmp_path, "permissions: write-all\njobs: {}\n")
    assert _messages(tmp_path) == ["permissions: write-all is not allowed"]
    _workflow(tmp_path, f"{HEADER}jobs:\n  a:\n    permissions: write-all\n")
    assert _messages(tmp_path) == ["permissions: write-all is not allowed"]


@pytest.mark.parametrize(
    "trigger",
    [
        "on: pull_request_target\n",
        "on: [push, pull_request_target]\n",
        "on:\n  pull_request_target:\n",
    ],
)
def test_pull_request_target_is_rejected_in_every_form(tmp_path: Path, trigger: str) -> None:
    _workflow(tmp_path, f"{trigger}{HEADER}jobs: {{}}\n")
    assert _messages(tmp_path) == ["pull_request_target is not allowed"]


def test_workflow_without_permissions_is_rejected(tmp_path: Path) -> None:
    _workflow(tmp_path, "jobs:\n  a:\n    permissions:\n      contents: read\n")
    assert _messages(tmp_path) == ["no top-level permissions: block"]


@pytest.mark.parametrize("body", ["a: [unclosed\n", "", "- just\n- a list\n"])
def test_unparseable_or_non_mapping_workflow_fails_closed(tmp_path: Path, body: str) -> None:
    _workflow(tmp_path, body)
    assert len(_messages(tmp_path)) == 1


def test_composite_action_is_scanned_without_requiring_permissions(tmp_path: Path) -> None:
    action = tmp_path / ".github" / "actions" / "setup"
    action.mkdir(parents=True)
    (action / "action.yml").write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    assert _messages(tmp_path) == ["actions/checkout@v4 is not pinned to a commit SHA"]
    (action / "action.yml").write_text(
        f"runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@{SHA}\n",
        encoding="utf-8",
    )
    assert _messages(tmp_path) == []


def test_docker_action_image_must_carry_a_digest(tmp_path: Path) -> None:
    (tmp_path / "action.yml").write_text(
        "runs:\n  using: docker\n  image: docker://alpine:3.22\n", encoding="utf-8"
    )
    assert _messages(tmp_path) == ["image docker://alpine:3.22 is not pinned by digest"]


def test_dockerfile_rules(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        f"FROM --platform=linux/amd64 alpine@{DIGEST} AS Build\n"
        "FROM build AS test\nFROM scratch\nFROM debian:bookworm\n",
        encoding="utf-8",
    )
    assert _messages(tmp_path) == ["FROM debian:bookworm is not pinned by digest"]


def test_arg_substituted_from_is_rejected_with_a_clear_message(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        f"ARG BASE=alpine@{DIGEST}\nFROM ${{BASE}}\n", encoding="utf-8"
    )
    assert _messages(tmp_path) == ["FROM ${BASE} is built from an ARG; inline the digest"]


@pytest.mark.parametrize("name", ["Dockerfile.el8", "app.Dockerfile", "Containerfile"])
def test_dockerfile_name_variants_are_scanned(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("FROM alpine:3.22\n", encoding="utf-8")
    assert _messages(tmp_path) == ["FROM alpine:3.22 is not pinned by digest"]


def test_vendored_and_environment_directories_are_skipped(tmp_path: Path) -> None:
    for skipped in (".venv", "vendor", "node_modules", ".git"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "Dockerfile").write_text("FROM alpine:3.22\n", encoding="utf-8")
    assert _messages(tmp_path) == []


def _precommit(root: Path, body: str) -> None:
    (root / ".pre-commit-config.yaml").write_text(body, encoding="utf-8")


def test_precommit_local_meta_and_sha_pinned_repos_pass(tmp_path: Path) -> None:
    _precommit(
        tmp_path,
        "repos:\n"
        "  - repo: local\n    hooks: []\n"
        "  - repo: meta\n    hooks: []\n"
        f"  - repo: https://example.invalid/hooks\n    rev: {SHA}\n    hooks: []\n",
    )
    assert _messages(tmp_path) == []


@pytest.mark.parametrize("rev", ["v1.2.3", "main", "3d3c42e", SHA.upper(), f"{SHA}0", '""'])
def test_precommit_unpinned_rev_is_rejected(tmp_path: Path, rev: str) -> None:
    _precommit(tmp_path, f"repos:\n  - repo: https://example.invalid/hooks\n    rev: {rev}\n")
    messages = _messages(tmp_path)
    assert len(messages) == 1
    assert "is not a 40-hex commit SHA" in messages[0]


def test_precommit_repo_without_rev_is_rejected(tmp_path: Path) -> None:
    _precommit(tmp_path, "repos:\n  - repo: https://example.invalid/hooks\n    hooks: []\n")
    assert _messages(tmp_path) == ["https://example.invalid/hooks has no rev"]


def test_precommit_quoted_sha_passes(tmp_path: Path) -> None:
    _precommit(tmp_path, f'repos:\n  - repo: https://example.invalid/hooks\n    rev: "{SHA}"\n')
    assert _messages(tmp_path) == []


def test_precommit_merge_key_cannot_hide_a_floating_repo(tmp_path: Path) -> None:
    _precommit(
        tmp_path,
        "base: &b {repo: https://example.invalid/hooks, rev: v1, hooks: [{id: a}]}\n"
        "repos:\n  - <<: *b\n",
    )
    assert "merge keys are not allowed" in _messages(tmp_path)


@pytest.mark.parametrize(
    "body",
    [
        "repos: foo\n",
        "repos:\n  a: {repo: https://example.invalid/hooks, rev: v1}\n",
        "repos:\n",
        "hooks: []\n",
    ],
)
def test_precommit_repos_must_be_a_list(tmp_path: Path, body: str) -> None:
    _precommit(tmp_path, body)
    assert _messages(tmp_path) == ["repos is not a list"]


@pytest.mark.parametrize("entry", ["https://example.invalid/hooks", "{rev: v1}", "[a, b]"])
def test_precommit_entry_must_name_a_repo(tmp_path: Path, entry: str) -> None:
    _precommit(tmp_path, f"repos:\n  - {entry}\n")
    assert _messages(tmp_path) == ["entry is not a mapping with a repo"]


@pytest.mark.parametrize("source", ["local", f"https://example.invalid/hooks\n    rev: {SHA}"])
def test_precommit_additional_dependencies_are_rejected(tmp_path: Path, source: str) -> None:
    _precommit(
        tmp_path,
        f"repos:\n  - repo: {source}\n    hooks:\n"
        "      - {id: a, language: unsupported, additional_dependencies: [foo]}\n",
    )
    assert _messages(tmp_path) == ["additional_dependencies are not allowed; use the pins"]


def test_precommit_local_hook_needs_a_language(tmp_path: Path) -> None:
    _precommit(tmp_path, "repos:\n  - repo: local\n    hooks:\n      - {id: a}\n")
    assert _messages(tmp_path) == ["local hook has no language"]


def test_workflow_merge_key_cannot_hide_a_floating_step(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        f"{HEADER}step: &s {{uses: actions/checkout@v4}}\n"
        "jobs:\n  a:\n    steps:\n      - <<: *s\n",
    )
    assert "merge keys are not allowed" in _messages(tmp_path)


def test_action_merge_key_cannot_hide_a_floating_step(tmp_path: Path) -> None:
    action = tmp_path / "action.yml"
    action.write_text(
        "step: &s {uses: actions/checkout@v4}\nruns:\n  using: composite\n  steps:\n    - <<: *s\n",
        encoding="utf-8",
    )
    assert "merge keys are not allowed" in _messages(tmp_path)


@pytest.mark.parametrize("language", ["python", "node", "docker"])
def test_precommit_local_hook_cannot_install_packages(tmp_path: Path, language: str) -> None:
    _precommit(
        tmp_path,
        f"repos:\n  - repo: local\n    hooks:\n      - {{id: a, language: {language}}}\n",
    )
    assert _messages(tmp_path) == [f"local hook language {language} installs packages"]


@pytest.mark.parametrize("body", ["repos: [unclosed\n", "", "- just\n- a list\n"])
def test_unparseable_precommit_config_fails_closed(tmp_path: Path, body: str) -> None:
    _precommit(tmp_path, body)
    assert len(_messages(tmp_path)) == 1


def test_main_reports_every_outcome(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert lint_pins.main([str(tmp_path)]) == 0
    assert "PIN LINT PASSED" in capsys.readouterr().out

    _workflow(tmp_path, _jobs("    steps:\n      - uses: actions/checkout@v4\n"))
    assert lint_pins.main([str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "not pinned to a commit SHA" in captured.err
    assert "PIN LINT PASSED" not in captured.out

    assert lint_pins.main([str(tmp_path / "missing")]) == 2
    assert "is not a directory" in capsys.readouterr().err
