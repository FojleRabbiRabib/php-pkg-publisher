#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Fail on any supply-chain pin that is not exact.

Checks, over the repository under ROOT:
  * every `uses:` in a workflow job or step, and in a local composite action, is a local
    path, a 40-hex commit SHA reference, or a `docker://` reference pinned by digest;
  * a local path is followed: it must stay inside ROOT and exist, and the composite action
    it names is checked too, wherever it lives (a skipped directory included);
  * every job `container:` image, `services:` image and Dockerfile `FROM` is pinned by
    digest;
  * a `run:` script installs with `pip install` only together with `--require-hashes`, and
    never pipes `curl` or `wget` into a shell (a text match over the script's commands: it
    catches mistakes, not a deliberate bypass);
  * no workflow triggers on `pull_request_target`, requests `id-token: write` or grants
    `permissions: write-all`;
  * every workflow declares top-level `permissions:`;
  * `.pre-commit-config.yaml` has no merge keys, pins every non-local repository to a 40-hex
    commit SHA, allows no `additional_dependencies`, and lets a local hook only run tools
    that are already installed (`unsupported`, `unsupported_script`, `system`, `script`).

Workflows and actions are parsed as YAML, so quoting, flow mappings, comments and values on
the following line are handled by the parser, not by pattern matching.

Only the top level of ROOT skips directories (`.git`, `.venv`, `vendor`, caches): a directory
of that name anywhere lower is scanned, and `.github` is never skipped.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
LOCAL_HOOK_LANGUAGES = frozenset({"script", "system", "unsupported", "unsupported_script"})
PIP_INSTALL = re.compile(r"\bpip3?\s+install\b")
REQUIRE_HASHES = re.compile(r"(?<!\S)--require-hashes(?!\S)")
INLINE_COMMENT = re.compile(r"\s#.*$")
DOWNLOAD_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:\S*/)?env\s+(?:\S+=\S+\s+)*)?"
    r"(?:\S*/)?(?:ba|da|z|k)?sh\b"
    r"|(?<![\w.-])(?:ba|da|z|k)?sh\s+(?:-\w+\s+)*[\"']?(?:<|\$)\(\s*(?:curl|wget)\b"
)
SHA_REF = re.compile(r"@[0-9a-f]{40}$")
DIGEST_REF = re.compile(r"@sha256:[0-9a-f]{64}$")
FROM_LINE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?", re.I)
SKIPPED_DIRECTORIES = frozenset(
    {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "node_modules", "vendor"}
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


@dataclass(frozen=True)
class LocalUse:
    """A `uses: ./path` reference, to be followed once the file that holds it is read."""

    path: Path
    line: int
    value: str


def _scalar(node: Node) -> str | None:
    return node.value if isinstance(node, ScalarNode) else None


def _pairs(node: Node | None) -> Iterator[tuple[str, Node]]:
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            key = _scalar(key_node)
            if key is not None:
                yield key, value_node


def _items(node: Node | None) -> Iterator[Node]:
    if isinstance(node, SequenceNode):
        yield from node.value


def _line(node: Node) -> int:
    return int(node.start_mark.line) + 1


def _check_uses(path: Path, node: Node, findings: list[Finding], local: list[LocalUse]) -> None:
    value = _scalar(node)
    if value is None:
        return
    if value.startswith("./"):
        local.append(LocalUse(path, _line(node), value))
        return
    if value.startswith("docker://"):
        if not DIGEST_REF.search(value):
            findings.append(Finding(path, _line(node), f"{value} is not pinned by digest"))
    elif not SHA_REF.search(value):
        findings.append(Finding(path, _line(node), f"{value} is not pinned to a commit SHA"))


def _check_image(path: Path, node: Node, findings: list[Finding]) -> None:
    value = _scalar(node)
    if value is None:
        return
    if "${" in value or value.startswith("$"):
        findings.append(
            Finding(path, _line(node), f"image {value} is built from an expression; inline it")
        )
    elif not DIGEST_REF.search(value):
        findings.append(Finding(path, _line(node), f"image {value} is not pinned by digest"))


def _commands(script: str) -> Iterator[str]:
    """The script's commands: line continuations and a trailing `|` or `&&` join the next line."""
    joined = re.sub(r"\\\n|(?<=[|&])\s*\n", " ", script)
    for line in joined.splitlines():
        stripped = INLINE_COMMENT.sub("", line.strip())
        if stripped and not stripped.startswith("#"):
            yield stripped


def _check_run(path: Path, node: Node, findings: list[Finding]) -> None:
    script = _scalar(node)
    if script is None:
        return
    for command in _commands(script):
        for part in re.split(r"&&|\|\||;|\|", command):
            if PIP_INSTALL.search(part) and not REQUIRE_HASHES.search(part):
                findings.append(
                    Finding(
                        path, _line(node), "pip install without --require-hashes in a run script"
                    )
                )
        if DOWNLOAD_TO_SHELL.search(command):
            findings.append(
                Finding(path, _line(node), "a download is piped into a shell in a run script")
            )


def _check_steps(
    path: Path, steps: Node | None, findings: list[Finding], local: list[LocalUse]
) -> None:
    for step in _items(steps):
        for key, value in _pairs(step):
            if key == "uses":
                _check_uses(path, value, findings, local)
            elif key == "run":
                _check_run(path, value, findings)


def _check_job(path: Path, job: Node, findings: list[Finding], local: list[LocalUse]) -> None:
    for key, value in _pairs(job):
        if key == "uses":
            _check_uses(path, value, findings, local)
        elif key == "container":
            if isinstance(value, ScalarNode):
                _check_image(path, value, findings)
            else:
                for inner_key, inner in _pairs(value):
                    if inner_key == "image":
                        _check_image(path, inner, findings)
        elif key == "services":
            for _name, service in _pairs(value):
                for inner_key, inner in _pairs(service):
                    if inner_key == "image":
                        _check_image(path, inner, findings)
        elif key == "steps":
            _check_steps(path, value, findings, local)


def _check_permissions(path: Path, node: Node, findings: list[Finding]) -> None:
    for key, value in _pairs(node):
        if key == "id-token" and _scalar(value) == "write":
            findings.append(Finding(path, _line(value), "id-token: write is not allowed here"))
        elif key == "permissions" and _scalar(value) == "write-all":
            findings.append(Finding(path, _line(value), "permissions: write-all is not allowed"))
        _check_permissions(path, value, findings)
    for item in _items(node):
        _check_permissions(path, item, findings)


def _triggers(node: Node) -> Iterator[tuple[str, Node]]:
    scalar = _scalar(node)
    if scalar is not None:
        yield scalar, node
    for item in _items(node):
        item_scalar = _scalar(item)
        if item_scalar is not None:
            yield item_scalar, item
    yield from _pairs(node)


def _load(path: Path, findings: list[Finding]) -> Node | None:
    try:
        root = yaml.compose(path.read_text(encoding="utf-8"), Loader=yaml.SafeLoader)
    except yaml.YAMLError as error:
        findings.append(Finding(path, 1, f"invalid YAML: {error}"))
        return None
    if not isinstance(root, MappingNode):
        findings.append(Finding(path, 1, "not a YAML mapping"))
        return None
    return root


def lint_workflow(path: Path, local: list[LocalUse]) -> list[Finding]:
    findings: list[Finding] = []
    root = _load(path, findings)
    if root is None:
        return findings
    _check_merge_keys(path, root, findings)
    has_permissions = False
    for key, value in _pairs(root):
        if key == "permissions":
            has_permissions = True
        elif key == "on":
            for name, node in _triggers(value):
                if name == "pull_request_target":
                    findings.append(
                        Finding(path, _line(node), "pull_request_target is not allowed")
                    )
        elif key == "jobs":
            for _job_id, job in _pairs(value):
                _check_job(path, job, findings, local)
    _check_permissions(path, root, findings)
    if not has_permissions:
        findings.append(Finding(path, 1, "no top-level permissions: block"))
    return findings


def lint_action(path: Path, local: list[LocalUse]) -> list[Finding]:
    findings: list[Finding] = []
    root = _load(path, findings)
    if root is None:
        return findings
    _check_merge_keys(path, root, findings)
    for key, value in _pairs(root):
        if key != "runs":
            continue
        for runs_key, runs_value in _pairs(value):
            if runs_key == "steps":
                _check_steps(path, runs_value, findings, local)
            elif runs_key == "image" and (_scalar(runs_value) or "").startswith("docker://"):
                _check_image(path, runs_value, findings)
    _check_permissions(path, root, findings)
    return findings


def _check_merge_keys(path: Path, node: Node, findings: list[Finding]) -> None:
    for key_node, value_node in node.value if isinstance(node, MappingNode) else ():
        if _scalar(key_node) == "<<":
            findings.append(Finding(path, _line(key_node), "merge keys are not allowed"))
        _check_merge_keys(path, value_node, findings)
    for item in _items(node):
        _check_merge_keys(path, item, findings)


def _check_precommit_repo(path: Path, entry: Node, findings: list[Finding]) -> None:
    fields = dict(_pairs(entry))
    source = _scalar(fields["repo"]) if "repo" in fields else None
    if source is None:
        findings.append(Finding(path, _line(entry), "entry is not a mapping with a repo"))
        return
    if source not in ("local", "meta"):
        rev = fields.get("rev")
        if rev is None:
            findings.append(Finding(path, _line(fields["repo"]), f"{source} has no rev"))
        elif not COMMIT_SHA.fullmatch(_scalar(rev) or ""):
            findings.append(
                Finding(path, _line(rev), f"rev {_scalar(rev)} is not a 40-hex commit SHA")
            )
    for hook in _items(fields.get("hooks")):
        hook_fields = dict(_pairs(hook))
        if "additional_dependencies" in hook_fields:
            findings.append(
                Finding(path, _line(hook), "additional_dependencies are not allowed; use the pins")
            )
        if source != "local":
            continue
        language = _scalar(hook_fields["language"]) if "language" in hook_fields else None
        if language is None:
            findings.append(Finding(path, _line(hook), "local hook has no language"))
        elif language not in LOCAL_HOOK_LANGUAGES:
            findings.append(
                Finding(path, _line(hook), f"local hook language {language} installs packages")
            )


def lint_precommit(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    root = _load(path, findings)
    if root is None:
        return findings
    _check_merge_keys(path, root, findings)
    repos = dict(_pairs(root)).get("repos")
    if not isinstance(repos, SequenceNode):
        findings.append(Finding(path, 1 if repos is None else _line(repos), "repos is not a list"))
        return findings
    for entry in repos.value:
        _check_precommit_repo(path, entry, findings)
    return findings


def lint_dockerfile(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    stages: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = FROM_LINE.match(raw)
        if not match:
            continue
        image = match.group("image")
        if image.startswith("$"):
            findings.append(
                Finding(path, number, f"FROM {image} is built from an ARG; inline the digest")
            )
        elif (
            image.lower() != "scratch"
            and image.lower() not in stages
            and not DIGEST_REF.search(image)
        ):
            findings.append(Finding(path, number, f"FROM {image} is not pinned by digest"))
        if match.group("alias"):
            stages.add(match.group("alias").lower())
    return findings


def _is_dockerfile(name: str) -> bool:
    return name == "Containerfile" or name.startswith("Dockerfile") or name.endswith(".Dockerfile")


def _is_action(name: str) -> bool:
    return name in ("action.yml", "action.yaml")


def _files(root: Path) -> Iterator[Path]:
    """Every file under `root`; only the top level skips the directories of SKIPPED_DIRECTORIES."""
    for directory, subdirectories, names in os.walk(root):
        if Path(directory) == root:
            subdirectories[:] = [d for d in subdirectories if d not in SKIPPED_DIRECTORIES]
        subdirectories.sort()
        for name in sorted(names):
            yield Path(directory) / name


def _follow(root: Path, use: LocalUse, linted: set[Path], local: list[LocalUse]) -> list[Finding]:
    """Check what a local `uses:` names: inside `root`, present, and a checked action."""
    target = (root / use.value).resolve()
    if not target.is_relative_to(root.resolve()):
        return [Finding(use.path, use.line, f"{use.value} leaves the repository")]
    if target.is_file():
        return []  # a reusable workflow; the ones under .github/workflows are linted as found
    if not target.is_dir():
        return [Finding(use.path, use.line, f"{use.value} does not exist")]
    actions = [target / name for name in ("action.yml", "action.yaml") if (target / name).is_file()]
    if not actions:
        return [Finding(use.path, use.line, f"{use.value} has no action.yml")]
    findings: list[Finding] = []
    for action in actions:
        if action not in linted:
            linted.add(action)
            findings.extend(lint_action(action, local))
    return findings


def lint_tree(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    local: list[LocalUse] = []
    linted: set[Path] = set()
    workflows = root / ".github" / "workflows"
    for path in _files(root):
        if path.parent == workflows and path.suffix in (".yml", ".yaml"):
            findings.extend(lint_workflow(path, local))
        elif _is_action(path.name):
            linted.add(path.resolve())
            findings.extend(lint_action(path, local))
        elif path.name == ".pre-commit-config.yaml":
            findings.extend(lint_precommit(path))
        elif _is_dockerfile(path.name):
            findings.extend(lint_dockerfile(path))
    while local:
        findings.extend(_follow(root, local.pop(0), linted, local))
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        print(f"FAIL: {args.root} is not a directory", file=sys.stderr)
        return 2
    findings = lint_tree(args.root)
    for finding in findings:
        print(f"FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("PIN LINT PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
