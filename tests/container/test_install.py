# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The container layer: a real `apt` or `dnf` of each distribution installs from a published tree.

Run with `pytest -m container` (bare `pytest` skips it). It needs a running docker and the nine
images of `images.py` already pulled by those references (containers start with `--pull never`).
Each distribution and PHP version (8.3, 8.4, 8.5) gets one lifecycle in one container: install
through the 302 redirect, metadata with one flipped byte that the client must refuse while a new
release is published, the upgrade once it is intact, and a rollback that the client sees as the
older set. The tree is built by the real pass (see `tests/negative`); the packages are fakes with
no PHP in them, so `php -m` is the product repositories' own install test.

The client trusts the two public keys a user would (the repository key and the RPM key); the
dnf configuration lists both, so this layer does not show that each is needed for its own file
(the unit and negative layers check that). No package bytes come from the tree.
"""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from box import Box, docker_available
from clients import Apt, Dnf, publish
from conftest import client
from images import IMAGES, Image
from mirror import Mirror
from rig import Rig, product

pytestmark = pytest.mark.container

FIRST = "v1.0.0"
SECOND = "v1.1.0"
PHP_VERSIONS = ("8.3", "8.4", "8.5")


def _kit(directory: Path, rig: Rig, mirror: Mirror, php: str) -> Path:
    """Public keys and client configuration, world-readable: `_apt` reads them in the sandbox."""
    directory.mkdir()
    shutil.copy(rig.kit.master.public, directory / "repo.asc")
    shutil.copy(rig.kit.rpm_keys["good"].public, directory / "rpm.asc")
    (directory / "apt.d").mkdir()
    (directory / "apt.d" / "test.sources").write_text(
        f"Types: deb\nURIs: {mirror.base}/apt\nSuites: stable\nComponents: main\n"
        "Signed-By: /kit/repo.asc\n",
        encoding="utf-8",
    )
    (directory / "repos.d").mkdir()
    (directory / "repos.d" / "test.repo").write_text(
        f"[test]\nname=test\nbaseurl={mirror.base}/rpm/{php}/x86_64\nenabled=1\n"
        "gpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///kit/repo.asc file:///kit/rpm.asc\n",
        encoding="utf-8",
    )
    for path in (directory, *directory.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return directory


@pytest.fixture(scope="session", autouse=True)
def _docker() -> None:
    assert docker_available(), "the container layer needs a running docker"


@pytest.mark.parametrize("php", PHP_VERSIONS)
@pytest.mark.parametrize("name", list(IMAGES))
def test_a_real_client_installs_upgrades_follows_a_rollback_and_refuses_tampering(
    name: str, php: str, make_rig: Callable[..., Rig], tmp_path: Path
) -> None:
    image: Image = IMAGES[name]
    who = product("a-php", "a", php)
    rig = make_rig(who)
    now = time.time()
    first_id = publish(rig, who, FIRST, now)
    with Mirror(rig) as mirror, Box(image, _kit(tmp_path / "kit", rig, mirror, php)) as box:
        tool: Apt | Dnf = Apt(box, php) if image.family == "apt" else Dnf(box, php)
        # install, through the redirect
        done = tool.update()
        assert done.code == 0, done.output
        assert tool.listed() == {tool.version(FIRST)}
        done = tool.install()
        assert done.code == 0, done.output
        assert tool.installed() == tool.version(FIRST)
        assert any(f"/releases/download/{FIRST}/" in url for url in mirror.redirects)
        # a new release whose metadata has one flipped byte: refused, never offered
        publish(rig, who, SECOND, now + 60)
        mirror.tamper = (
            {"apt/dists/stable/InRelease", "apt/dists/stable/Release"}
            if isinstance(tool, Apt)
            else {f"rpm/{php}/x86_64/repodata/repomd.xml.asc"}
        )
        done = tool.update()
        assert tool.refused(done), done.output
        offered = tool.listed()
        assert tool.version(SECOND) not in offered
        if isinstance(tool, Apt):  # apt keeps its old index; dnf5 drops the repository's data
            assert offered == {tool.version(FIRST)}
        assert tool.installed() == tool.version(FIRST)
        # the same release, untampered: upgrade
        mirror.tamper = set()
        done = tool.update()
        assert done.code == 0, done.output
        assert tool.listed() == {tool.version(FIRST), tool.version(SECOND)}
        done = tool.install() if isinstance(tool, Apt) else tool.upgrade()
        assert done.code == 0, done.output
        assert tool.installed() == tool.version(SECOND)
        # a rollback: the client sees the older set again
        rig.rollback(first_id, now + 120)
        done = tool.update()
        assert done.code == 0, done.output
        assert tool.listed() == {tool.version(FIRST)}
    assert client(rig).package_bytes_in_tree() == []
