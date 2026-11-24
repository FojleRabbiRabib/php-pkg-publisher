# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The keyring packages installed by a real `apt` or `dnf` of each distribution.

The packages come from `tools/build_keyring.py` over a certificate that has the design's shape:
one master, the repository subkey that signs the tree, and a second subkey for the RPM job (see
`keyrings.py`). The client is pointed at the key file the package installed, never at a key in
the kit, so the test shows that the installed key alone verifies the published metadata. On dnf
the repository id starts with `rabib-`, so the cache clean-up of `rabib-release` has something to
remove: the test makes the key caches of a `rabib-` repository and of another repository,
installs the keyring and then an upgrade of it, and expects only the `rabib-` caches to go each
time. The full rotation of the signing subkey is the key drill, not this test.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest
from box import Box, docker_available
from clients import Apt, Dnf, native_product, publish
from images import IMAGES, Image
from keyrings import DEB_KEY, RPM_KEY, VERSIONS, client_kit, deb_name, rpm_name
from mirror import Mirror
from rig import Rig

pytestmark = pytest.mark.container

PHP = "8.3"
TAG = "v1.0.0"
CACHES = {
    "rabib": ("/var/cache/dnf/rabib-test-0123abcd", "/var/cache/libdnf5/rabib-test-0123abcd"),
    "other": ("/var/cache/dnf/other-0123abcd", "/var/cache/libdnf5/other-0123abcd"),
}


@pytest.fixture(scope="session", autouse=True)
def _docker() -> None:
    assert docker_available(), "the container layer needs a running docker"


def _apt(box: Box) -> None:
    tool = Apt(box, PHP)
    # without the keyring the signature cannot be checked: nothing is offered
    tool.update()
    assert tool.listed() == set()
    done = box.run("apt-get", "install", "-y", f"/kit/pkg/{deb_name(VERSIONS[0])}")
    assert done.code == 0, done.output
    assert (
        box.run("dpkg-query", "-W", "-f=${Version}", "rabib-archive-keyring").output
        == (VERSIONS[0])
    )
    assert box.run("test", "-f", DEB_KEY).code == 0
    # the installed keyring alone verifies the published metadata
    done = tool.update()
    assert done.code == 0 and not tool.refused(done), done.output
    assert tool.listed() == {tool.version(TAG)}
    done = tool.install()
    assert done.code == 0, done.output
    assert tool.installed() == tool.version(TAG)
    # a later keyring release upgrades in place and the metadata still verifies
    done = box.run("apt-get", "install", "-y", f"/kit/pkg/{deb_name(VERSIONS[1])}")
    assert done.code == 0, done.output
    assert (
        box.run("dpkg-query", "-W", "-f=${Version}", "rabib-archive-keyring").output
        == (VERSIONS[1])
    )
    done = tool.update()
    assert done.code == 0 and not tool.refused(done), done.output
    assert tool.listed() == {tool.version(TAG)}


def _caches(box: Box) -> dict[str, bool]:
    """Which of the prepared key caches exist."""
    return {
        path: box.run("test", "-e", f"{path}/pubring").code == 0
        for paths in CACHES.values()
        for path in paths
    }


def _make_caches(box: Box) -> None:
    for paths in CACHES.values():
        for path in paths:
            done = box.run("mkdir", "-p", f"{path}/pubring")
            assert done.code == 0, done.output
    assert all(_caches(box).values())


def _signed_rpm(box: Box) -> None:
    """This distribution's `rpmkeys` accepts the signed rpm against the key file the rpm installs.

    An unsigned copy is the control: `rpmkeys --checksig` exits 0 for it but reports no signature.
    """
    database = "/root/signed-rpmdb"
    assert box.run("mkdir", database).code == 0
    done = box.run("rpmkeys", "--dbpath", database, "--import", RPM_KEY)
    assert done.code == 0, done.output
    package = f"/kit/pkg/signed/{rpm_name(VERSIONS[0])}"
    done = box.run("rpmkeys", "--dbpath", database, "--checksig", package)
    assert done.code == 0, done.output
    assert done.output.strip() == f"{package}: digests signatures OK", done.output
    unsigned = box.run(
        "rpmkeys", "--dbpath", database, "--checksig", f"/kit/pkg/{rpm_name(VERSIONS[0])}"
    )
    assert "signatures OK" not in unsigned.output, unsigned.output


def _dnf(box: Box) -> None:
    tool = Dnf(box, PHP)
    install = ("dnf", "-y", "--setopt=reposdir=/kit/repos.d", "--disablerepo=*", "install")
    # without the key file the repository cannot be verified: nothing is offered
    tool.update()
    done = box.run("dnf", *tool.OPTIONS, "repoquery", "--available", "php-a")
    assert tool.version(TAG) not in done.output
    for version in VERSIONS:
        _make_caches(box)
        done = box.run(*install, f"/kit/pkg/{rpm_name(version)}")
        assert done.code == 0, done.output
        assert box.run("rpm", "-q", "--qf", "%{VERSION}", "rabib-release").output == version
        assert box.run("test", "-f", RPM_KEY).code == 0
        # the clean-up removes the key caches of the `rabib-` repositories and nothing else
        left = _caches(box)
        assert [path for path, present in left.items() if present] == [
            f"{path}" for path in CACHES["other"]
        ], left
        # the installed key file alone verifies the published metadata
        done = tool.update()
        assert done.code == 0 and not tool.refused(done), done.output
        assert tool.listed() == {tool.version(TAG)}
    _signed_rpm(box)
    done = tool.install()
    assert done.code == 0, done.output
    assert tool.installed() == tool.version(TAG)


@pytest.mark.parametrize("name", list(IMAGES))
def test_a_real_client_trusts_the_installed_keyring_and_the_upgrade_clears_the_key_caches(
    name: str, packages: Path, make_rig: Callable[..., Rig], tmp_path: Path
) -> None:
    image: Image = IMAGES[name]
    who = native_product("a-php", "a", PHP)
    rig = make_rig(who)
    publish(rig, who, TAG, time.time())
    with (
        Mirror(rig) as mirror,
        Box(image, client_kit(tmp_path / "kit", packages, mirror, PHP)) as box,
    ):
        if image.family == "apt":
            _apt(box)
        else:
            _dnf(box)
