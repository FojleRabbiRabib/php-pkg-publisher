# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Every command block of `docs/installation.md`, run in order on each distribution.

The blocks are run as written (as root, the published host swapped for a local mirror of the
site, the extension placeholder filled in) on a client that still has its own repositories, which
is what a person following the guide has. After the install blocks the extension is there and the
guide's files are in place; the removal blocks then leave neither.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest
from box import Box, docker_available
from clients import native_product, publish
from docblocks import blocks, runnable
from images import IMAGES, Image
from keyrings import RPM_KEY_NAME
from mirror import Mirror
from rig import Kit, Rig
from setupkit import APT_SOURCES, DNF_REPO, PHP, TAG, kit_dir, served

pytestmark = pytest.mark.container


@pytest.fixture(scope="session", autouse=True)
def _docker() -> None:
    assert docker_available(), "the container layer needs a running docker"


@pytest.mark.parametrize("name", list(IMAGES))
def test_the_commands_of_the_install_guide_run_on_each_distribution(
    name: str,
    kit: Kit,
    packages: Path,
    php_rpms: Path,
    make_rig: Callable[..., Rig],
    tmp_path: Path,
) -> None:
    image: Image = IMAGES[name]
    who = native_product("a-php", "a", PHP)
    rig = make_rig(who, rpm_key=RPM_KEY_NAME)
    publish(rig, who, TAG, time.time())
    mine = [b for b in blocks() if b.family == image.family]
    with (
        Mirror(rig, served(packages)) as mirror,
        Box(image, kit_dir(tmp_path / "kit", php_rpms, mirror)) as box,
    ):
        keys = set(box.run("sh", "-c", "rpm -qa 'gpg-pubkey*' 2>/dev/null || true").output.split())
        for block in (b for b in mine if not b.remove):
            done = box.run("sh", "-ec", runnable(block, site=mirror.base, extension="a"))
            assert done.code == 0, f"{block.text}\n{done.output}"
            if "--show-keys" in block.text:
                # the guide's fingerprint step shows the key the rig signs with
                shown = done.output.replace(" ", "")
                assert kit.master.primary_fingerprint.upper() in shown, done.output
        installed = box.run("sh", "-c", f"ls {APT_SOURCES} {DNF_REPO} 2>/dev/null").output
        assert (APT_SOURCES if image.family == "apt" else DNF_REPO) in installed
        extension = "php8.3-a" if image.family == "apt" else "php-a"
        query = ["dpkg", "-s", extension] if image.family == "apt" else ["rpm", "-q", extension]
        assert box.run(*query).code == 0
        for block in (b for b in mine if b.remove):
            done = box.run("sh", "-ec", runnable(block, site=mirror.base, extension="a"))
            assert done.code == 0, f"{block.text}\n{done.output}"
        assert box.run("sh", "-c", f"ls {APT_SOURCES}").code != 0 or image.family == "dnf"
        assert box.run("sh", "-c", f"ls {DNF_REPO}").code != 0 or image.family == "apt"
        # the key the guide imported is out of rpm's key store again, and no other key went
        left = set(box.run("sh", "-c", "rpm -qa 'gpg-pubkey*' 2>/dev/null || true").output.split())
        assert left == keys, (keys, left)
