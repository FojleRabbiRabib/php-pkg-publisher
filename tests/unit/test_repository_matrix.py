# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The supported matrix is written in several places by hand; these tests make them agree.

`publisher/config.py` is the source of truth for the PHP versions and the architectures, and
`tests/container/images.py` for the distributions. Everything else that repeats them (the client
script, the outside watch, the container helpers, the CI matrix, the install guide, Dependabot)
is read as text or imported and compared, so a change in one place fails until the others follow.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath
from typing import Any, Final

import platform_watch
import pytest
import yaml
from images import IMAGES
from repofiles import ROOT, tracked_files
from setupkit import VERSIONS

from publisher import config, verify

# The Dependabot ecosystem of each dependency file that is named the same in every folder.
MANIFESTS: Final = {
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "composer.json": "composer",
    "go.mod": "gomod",
    "package.json": "npm",
    "pyproject.toml": "pip",
}
SETUP: Final = (ROOT / "setup.sh").read_text(encoding="utf-8")
CI: Final = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
GUIDE: Final = " ".join((ROOT / "docs" / "installation.md").read_text(encoding="utf-8").split())
DEPENDABOT: Final = yaml.safe_load(
    (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
)


def _setup_value(name: str) -> str:
    (value,) = re.findall(rf"^{name}='([^']*)'$", SETUP, re.MULTILINE)
    return str(value)


# --- PHP versions ----------------------------------------------------------------------------


def test_every_copy_of_the_php_versions_is_the_configs() -> None:
    expected = sorted(config.PHP_VERSIONS)
    assert _setup_value("PHP_VERSIONS").split() == expected
    assert list(platform_watch.PHP_VERSIONS) == expected
    assert list(VERSIONS) == expected


# --- architectures ---------------------------------------------------------------------------


def test_the_architecture_maps_cover_exactly_the_configs_architectures() -> None:
    assert set(verify.DEB_ARCHITECTURES) == config.ARCHITECTURES
    assert set(verify.RPM_ARCHITECTURES) == config.ARCHITECTURES


def test_the_setup_script_accepts_exactly_the_architectures_the_repository_has() -> None:
    (apt,) = re.findall(
        r"^\t\t((?:\w+ \| )*\w+)\) ;;\n\t\t\*\) die .*the repository has amd", SETUP, re.MULTILINE
    )
    (dnf,) = re.findall(
        r"^\t\t((?:\w+ \| )*\w+)\) ;;\n\t\t\*\) die .*the repository has x86", SETUP, re.MULTILINE
    )
    assert set(apt.split(" | ")) == set(verify.DEB_ARCHITECTURES.values())
    assert set(dnf.split(" | ")) == set(verify.RPM_ARCHITECTURES.values())
    assert len(apt.split(" | ")) == len(verify.DEB_ARCHITECTURES)
    assert len(dnf.split(" | ")) == len(verify.RPM_ARCHITECTURES)


def test_the_outside_watch_looks_at_the_rpm_architectures_and_one_apt_architecture() -> None:
    assert sorted(platform_watch.RPM_ARCHITECTURES) == sorted(verify.RPM_ARCHITECTURES.values())
    assert platform_watch.APT_ARCHITECTURE in config.ARCHITECTURES


# --- distributions ---------------------------------------------------------------------------


def _ci_matrix() -> list[str]:
    workflow: dict[str, Any] = yaml.safe_load(CI)
    matrix = workflow["jobs"]["container-image"]["strategy"]["matrix"]["image"]
    return [str(name) for name in matrix]


def test_the_ci_matrix_runs_every_image_and_a_catch_all() -> None:
    names = _ci_matrix()
    assert names[-1] == "rest"
    assert sorted(names[:-1]) == sorted(IMAGES)


def test_the_catch_all_leaves_out_exactly_the_images_that_have_their_own_job() -> None:
    (excluded,) = re.findall(r"-k 'not \(([^)]*)\)'", CI)
    assert sorted(excluded.split(" or ")) == sorted(IMAGES)


def test_the_guide_lists_exactly_the_tested_distributions() -> None:
    (sentence,) = re.findall(r"Supported and tested: (.*?) on `amd64`", GUIDE)
    ubuntu, debian, alma, fedora = re.search(
        r"Ubuntu (.*?), Debian (.*?), AlmaLinux (.*?), and Fedora (\d+)", sentence
    ).groups()  # type: ignore[union-attr]
    listed = {
        *(f"ubuntu-{version}" for version in re.findall(r"\d\d\.\d\d", ubuntu)),
        *(f"debian-{name}" for name in re.findall(r"\((\w+)\)", debian)),
        *(f"almalinux-{number}" for number in re.findall(r"\d+", alma)),
        f"fedora-{fedora}",
    }
    assert listed == set(IMAGES)


def test_the_setup_script_knows_the_distribution_of_every_image() -> None:
    (apt_ids,) = re.findall(r"^\t((?:\w+ \| )*\w+)\)\n\t\tFAMILY=apt", SETUP, re.MULTILINE)
    (dnf_ids,) = re.findall(r"^\t((?:\w+ \| )*\w+)\)\n\t\tFAMILY=dnf", SETUP, re.MULTILINE)
    families = {"apt": set(apt_ids.split(" | ")), "dnf": set(dnf_ids.split(" | "))}
    for name, image in IMAGES.items():
        assert name.split("-")[0] in families[image.family], name


# --- Dependabot ------------------------------------------------------------------------------


def _updates() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for update in DEPENDABOT["updates"]:
        directories = update.get("directories") or [update["directory"]]
        found[update["package-ecosystem"]] = list(directories)
    return found


def _watched(name: str) -> tuple[str, str] | None:
    """The Dependabot ecosystem and folder that must cover a tracked file, if it is a manifest."""
    path = PurePosixPath(name)
    folder = "/" + path.parent.as_posix() if path.parent.as_posix() != "." else "/"
    if path.name in MANIFESTS:
        return MANIFESTS[path.name], folder
    if re.fullmatch(r"requirements.*\.(txt|in)", path.name):
        return "pip", folder
    if path.name.startswith("Dockerfile") or path.name.endswith(".Dockerfile"):
        return "docker", folder
    if path.parent.as_posix() == ".github/workflows" and path.suffix in (".yml", ".yaml"):
        return "github-actions", "/"
    if path.name in ("action.yml", "action.yaml"):
        return "github-actions", folder
    return None


def _unwatched(tracked: list[str], updates: dict[str, list[str]]) -> list[str]:
    """Tracked manifests whose ecosystem and folder no Dependabot entry covers."""
    missing = []
    for name in tracked:
        watched = _watched(name)
        if watched is None:
            continue
        ecosystem, folder = watched
        if not any(fnmatch.fnmatch(folder, pattern) for pattern in updates.get(ecosystem, [])):
            missing.append(name)
    return missing


def _unneeded(tracked: list[str], updates: dict[str, list[str]]) -> set[str]:
    """Ecosystems Dependabot is told to watch that no tracked file belongs to."""
    needed = {watched[0] for name in tracked if (watched := _watched(name)) is not None}
    return set(updates) - needed


def test_dependabot_watches_every_dependency_manifest_the_repository_has() -> None:
    assert _unwatched(tracked_files(), _updates()) == []


def test_dependabot_has_no_ecosystem_without_a_manifest() -> None:
    assert _unneeded(tracked_files(), _updates()) == set()


def test_an_unwatched_manifest_or_an_unneeded_ecosystem_is_found() -> None:
    updates = {"pip": ["/"], "github-actions": ["/", "/.github/actions/*"], "docker": ["/"]}
    tracked = [
        "requirements.txt",
        "package.json",
        "tools/requirements.txt",
        ".github/workflows/ci.yml",
        ".github/actions/a/action.yml",
        "README.md",
    ]
    assert _unwatched(tracked, updates) == ["package.json", "tools/requirements.txt"]
    assert _unneeded(tracked, updates) == {"docker"}
    assert _unwatched(["README.md"], {}) == []


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("composer.json", ("composer", "/")),
        ("requirements-dev.in", ("pip", "/")),
        ("requirements-dev.txt", ("pip", "/")),
        ("tools/requirements-x.txt", ("pip", "/tools")),
        ("pyproject.toml", ("pip", "/")),
        ("package.json", ("npm", "/")),
        ("deploy/go.mod", ("gomod", "/deploy")),
        ("Dockerfile", ("docker", "/")),
        ("images/app.Dockerfile", ("docker", "/images")),
        (".github/workflows/ci.yml", ("github-actions", "/")),
        (".github/workflows/x.yaml", ("github-actions", "/")),
        (".github/actions/setup/action.yml", ("github-actions", "/.github/actions/setup")),
        ("setup.sh", None),
        ("tests/unit/requirements_test.py", None),
        (".github/dependabot.yml", None),
    ],
)
def test_a_tracked_file_is_recognised_as_a_dependency_manifest_by_its_name(
    name: str, expected: tuple[str, str] | None
) -> None:
    assert _watched(name) == expected
