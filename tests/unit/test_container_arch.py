# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The architecture the container layer runs: `CONTAINER_ARCH`, else the docker server's own."""

from __future__ import annotations

import subprocess

import pytest
from arch import ARCHITECTURES, ENVIRONMENT, Arch, native


def _ask(monkeypatch: pytest.MonkeyPatch, name: str | None) -> Arch:
    """Read the architecture afresh, with the variable set to `name` or unset."""
    if name is None:
        monkeypatch.delenv(ENVIRONMENT, raising=False)
    else:
        monkeypatch.setenv(ENVIRONMENT, name)
    return native.__wrapped__()


def test_each_architecture_has_the_names_apt_and_dnf_use() -> None:
    names = {"amd64": Arch("amd64", "x86_64"), "arm64": Arch("arm64", "aarch64")}
    assert names == ARCHITECTURES


def test_the_variable_picks_the_architecture(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _ask(monkeypatch, "arm64") == Arch("arm64", "aarch64")
    assert _ask(monkeypatch, "amd64") == Arch("amd64", "x86_64")


@pytest.mark.parametrize("name", ["x86_64", "aarch64", "riscv64", "ARM64"])
def test_an_architecture_without_container_tests_is_refused(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    with pytest.raises(OSError, match="no container tests for"):
        _ask(monkeypatch, name)


def test_without_the_variable_the_docker_servers_architecture_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked: list[list[str]] = []

    def fake(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        asked.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="arm64\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    assert _ask(monkeypatch, None) == Arch("arm64", "aarch64")
    assert asked == [["docker", "version", "--format", "{{.Server.Arch}}"]]


def test_a_docker_that_cannot_answer_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="no daemon")

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(OSError, match="did not report its architecture: no daemon"):
        _ask(monkeypatch, None)
