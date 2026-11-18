# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`setup.sh` run as root by the shell of each distribution against a local mirror of the site.

The mirror serves the tree built by the real pass and the two keyring downloads under
`/keyring/`. The client is prepared with `curl` and `gnupg` from the distribution's own
repositories; after that those repositories are switched off, so the script's refresh sees only
ours. The fake packages are signed by the keyring's RPM subkey, so dnf checks them against the
key file the keyring installed. The fingerprint the script prints is compared with the rig's own
key. The corners (refusals, PHP detection, gnupg) are in `test_setup_cases.py`.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest
from box import Box, docker_available
from clients import publish
from images import IMAGES, Image
from keyrings import RPM_KEY_NAME
from mirror import Mirror
from rig import Kit, Rig, product
from setupkit import (
    APT_SOURCES,
    DEAD_ID,
    DNF_REPO,
    PHP,
    TAG,
    TAMPER_APT,
    TAMPER_RPM,
    add_dead_repository,
    apt_lists,
    check_printed,
    kit_dir,
    prepare,
    repo,
    run,
    served,
    sources,
)

pytestmark = pytest.mark.container


@pytest.fixture(scope="session", autouse=True)
def _docker() -> None:
    assert docker_available(), "the container layer needs a running docker"


def _apt(box: Box, mirror: Mirror, kit: Kit) -> None:
    lists = apt_lists(box)
    # a first run that is refused leaves no sources file behind
    mirror.tamper = set(TAMPER_APT)
    done = run(box)
    assert done.code != 0 and "refused the repository" in done.output, done.output
    assert box.run("ls", APT_SOURCES).code != 0
    mirror.tamper = set()
    done = run(box)
    assert done.code == 0, done.output
    # the refresh was scoped to ours: the dead source did not fail it or cost the others' indexes
    assert lists <= apt_lists(box), lists - apt_lists(box)
    assert box.run("cat", APT_SOURCES).output == sources(mirror.base)
    # the apt keyring holds the primary key and the repo subkey only
    check_printed(kit, done.output, subkeys=1)
    assert box.run("dpkg-query", "-W", "-f=${Version}", "rabib-archive-keyring").code == 0
    done = box.run("apt-cache", "madison", f"php{PHP}-a")
    assert "1.0.0-1" in done.output, done.output
    done = box.run("apt-get", "install", "-y", f"php{PHP}-a")
    assert done.code == 0, done.output
    assert any(f"/releases/download/{TAG}/" in url for url in mirror.redirects)
    # a second run changes nothing
    done = run(box)
    assert done.code == 0, done.output
    assert box.run("cat", APT_SOURCES).output == sources(mirror.base)
    # a refused index fails the run and says so, and the host is left as it was: a hand-edited
    # sources file keeps its edit and the earlier index stays in place
    done = box.run("sh", "-c", f"printf '# kept\\n' >> {APT_SOURCES}")
    assert done.code == 0, done.output
    edited = box.run("cat", APT_SOURCES).output
    assert edited == sources(mirror.base) + "# kept\n", edited
    index = f"/var/lib/apt/lists/{mirror.base.removeprefix('http://')}_apt_dists_stable_InRelease"
    assert box.run("ls", index).code == 0
    mirror.tamper = set(TAMPER_APT)
    done = run(box)
    assert done.code != 0, done.output
    assert "refused the repository" in done.output, done.output
    assert box.run("cat", APT_SOURCES).output == edited
    assert box.run("ls", index).code == 0
    mirror.tamper = set()


def _dnf(box: Box, mirror: Mirror, kit: Kit) -> None:
    done = box.run("rpm", "-i", "/kit/php/php-common-8.3.1.rpm")
    assert done.code == 0, done.output
    before = box.run("rpm", "-qa", "gpg-pubkey*").output.split()
    # a first run that is refused leaves no repository file behind
    mirror.tamper = {TAMPER_RPM}
    done = run(box)
    assert done.code != 0 and "refused the repository" in done.output, done.output
    assert box.run("ls", DNF_REPO).code != 0
    mirror.tamper = set()
    done = run(box)
    assert done.code == 0, done.output
    assert box.run("cat", DNF_REPO).output == repo(mirror.base, {PHP})
    check_printed(kit, done.output, subkeys=2)
    # the key was imported outside the transaction
    after = box.run("rpm", "-qa", "gpg-pubkey*").output.split()
    assert len(after) > len(before), (before, after)
    assert box.run("rpm", "-q", "rabib-release").code == 0
    # the dead repository is still configured; the install must not load it
    done = box.run(
        *("dnf", "-y", "install", f"--disablerepo={DEAD_ID}"),
        *("php-a", f"php{PHP.replace('.', '')}-php-a"),
    )
    assert done.code == 0, done.output
    assert any(f"/releases/download/{TAG}/" in url for url in mirror.redirects)
    # a second run changes nothing
    done = run(box)
    assert done.code == 0, done.output
    assert box.run("cat", DNF_REPO).output == repo(mirror.base, {PHP})
    # a hand-added key survives a re-run; a hand-written gpgcheck = 0 or pkg_gpgcheck does not
    text = "priority=50\\ngpgcheck = 0\\npkg_gpgcheck=0\\n"
    done = box.run("sh", "-c", f"printf '{text}' >> {DNF_REPO}")
    assert done.code == 0, done.output
    done = run(box)
    assert done.code == 0, done.output
    assert box.run("cat", DNF_REPO).output == repo(mirror.base, {PHP}) + "priority=50\n"
    # a refused repomd.xml fails the run and says so, and the repository file keeps a hand-made
    # edit through the refused refresh
    done = box.run("sh", "-c", f"printf '# kept\\n' >> {DNF_REPO}")
    assert done.code == 0, done.output
    edited = box.run("cat", DNF_REPO).output
    assert edited == repo(mirror.base, {PHP}) + "priority=50\n# kept\n", edited
    mirror.tamper = {TAMPER_RPM}
    done = run(box)
    assert done.code != 0, done.output
    assert "refused the repository" in done.output, done.output
    assert box.run("cat", DNF_REPO).output == edited
    mirror.tamper = set()
    # an unreachable repomd.xml fails the run even where dnf is set to skip unavailable repos
    done = box.run("sh", "-c", "printf 'skip_if_unavailable=True\\n' >> /etc/dnf/dnf.conf")
    assert done.code == 0, done.output
    mirror.missing = {TAMPER_RPM.removesuffix(".asc")}
    done = run(box)
    assert done.code != 0, done.output
    assert "refused the repository" in done.output, done.output
    mirror.missing = set()


@pytest.mark.parametrize("name", list(IMAGES))
def test_setup_installs_refreshes_only_ours_and_leaves_the_host_as_found_when_refused(
    name: str,
    kit: Kit,
    packages: Path,
    php_rpms: Path,
    make_rig: Callable[..., Rig],
    tmp_path: Path,
) -> None:
    image: Image = IMAGES[name]
    who = product("a-php", "a", PHP)
    rig = make_rig(who, rpm_key=RPM_KEY_NAME)
    publish(rig, who, TAG, time.time())
    with (
        Mirror(rig, served(packages)) as mirror,
        Box(image, kit_dir(tmp_path / "kit", php_rpms, mirror)) as box,
    ):
        prepare(box, image.family, gpg=True, offline=True)
        add_dead_repository(box, image.family)
        if image.family == "apt":
            _apt(box, mirror, kit)
        else:
            _dnf(box, mirror, kit)
