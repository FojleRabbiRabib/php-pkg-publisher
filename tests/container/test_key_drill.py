# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The key drill: a rotation of the repository's signing subkey, seen by a real `apt` or `dnf`.

The first keyring release lists the current subkey; the repository is signed with it and a client
with that keyring verifies it. The second release lists the current and the next subkey. The
repository then switches to the next subkey (a new release, so a whole new publisher pass signs
with it, one subkey only):

- a client that did not upgrade the keyring refuses the repository, with the message each
  distribution gives (`refusals.py`, which the install guide quotes);
- the same client, after it upgrades the keyring package, verifies the repository and installs.

On dnf the upgrade must also delete the cached repository key (EL10 and Fedora keep the first key
they imported and otherwise report "Signing key not found"), which `rabib-release` does.
"""

from __future__ import annotations

import dataclasses
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from arch import native
from box import Box, docker_available
from clients import Apt, Dnf, native_product, publish
from images import IMAGES, Image
from keyrings import (
    ROTATION_KEY_NAME,
    RPM_KEY_NAME,
    VERSIONS,
    client_kit,
    deb_name,
    rpm_name,
)
from mirror import Mirror
from refusals import APT_DEFAULT, DROPS_THE_DATA, REFUSALS, SQV_TAIL
from rig import Kit, Rig

from publisher.settings import SigningPins

pytestmark = pytest.mark.container

PHP = "8.3"
TAG = "v1.0.0"
NEXT_TAG = "v1.0.1"
INSTALL = ("dnf", "-y", "--setopt=reposdir=/kit/repos.d", "--disablerepo=*", "install")


@pytest.fixture(scope="session", autouse=True)
def _docker() -> None:
    assert docker_available(), "the container layer needs a running docker"


def _switch_to_the_next_subkey(rig: Rig, kit: Kit) -> None:
    """The next publisher pass signs with the rotation key's subkey."""
    key = kit.rpm_keys[ROTATION_KEY_NAME]
    rig.settings = dataclasses.replace(
        rig.settings,
        signing=SigningPins(
            home=key.home,
            fingerprint=key.subkey_fingerprint,
            certificate=key.public,
            primary=key.primary_fingerprint,
        ),
    )


def _signed_by(rig: Rig, kit: Kit, subkey: str, home: Path) -> None:
    """The published tree carries exactly one signature each, made by `subkey` of the primary key.

    Read with the host's gpg and the public certificate, not with the code that signed.
    """
    certificate = kit.rpm_keys[ROTATION_KEY_NAME].public
    base = [kit.tools.gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1"]
    home.mkdir(mode=0o700, exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    imported = subprocess.run(  # noqa: S603
        [*map(str, [*base, "--import", certificate])], capture_output=True, env=env, check=False
    )
    assert imported.returncode == 0, imported.stderr
    tree = rig.current / "rpm" / PHP / native().rpm / "repodata"
    for files in (
        [rig.current / "apt" / "dists" / "stable" / "InRelease"],
        [tree / "repomd.xml.asc", tree / "repomd.xml"],
    ):
        done = subprocess.run(  # noqa: S603
            [*map(str, [*base, "--verify", *files])],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert done.returncode == 0, done.stderr
        signed = [line.split() for line in done.stdout.splitlines() if " VALIDSIG " in line]
        assert [(w[2], w[11]) for w in signed] == [
            (subkey.upper(), kit.master.primary_fingerprint.upper())
        ], (files, signed)


def _apt(box: Box, rig: Rig, kit: Kit, name: str, home: Path) -> None:
    tool = Apt(box, PHP)
    who = rig.products.products[0]
    current = kit.master.subkey_fingerprint
    next_key = kit.rpm_keys[ROTATION_KEY_NAME].subkey_fingerprint
    assert current != next_key
    _signed_by(rig, kit, current, home)
    done = box.run("apt-get", "install", "-y", f"/kit/pkg/{deb_name(VERSIONS[0])}")
    assert done.code == 0, done.output
    done = tool.update()
    assert done.code == 0 and not tool.refused(done), done.output
    assert tool.listed() == {tool.version(TAG)}
    _switch_to_the_next_subkey(rig, kit)
    publish(rig, who, NEXT_TAG, time.time())
    _signed_by(rig, kit, next_key, home)
    # the client that did not upgrade the keyring cannot verify the new signature, and says
    # that it is the next subkey it misses
    done = tool.update()
    assert tool.refused(done), done.output
    assert REFUSALS.get(name, APT_DEFAULT) in done.output, done.output
    assert next_key[-16:] in done.output.upper(), done.output
    if name in REFUSALS:
        assert SQV_TAIL in done.output, done.output
    # nothing new was accepted: the previous index files are still in use
    assert tool.listed() == {tool.version(TAG)}
    # the keyring upgrade brings the next subkey, and the same client verifies and installs
    done = box.run("apt-get", "install", "-y", f"/kit/pkg/{deb_name(VERSIONS[1])}")
    assert done.code == 0, done.output
    done = tool.update()
    assert done.code == 0 and not tool.refused(done), done.output
    assert tool.version(NEXT_TAG) in tool.listed()
    done = tool.install()
    assert done.code == 0, done.output
    assert tool.installed() == tool.version(NEXT_TAG)


def _dnf(box: Box, rig: Rig, kit: Kit, name: str, home: Path) -> None:
    tool = Dnf(box, PHP)
    who = rig.products.products[0]
    current = kit.master.subkey_fingerprint
    next_key = kit.rpm_keys[ROTATION_KEY_NAME].subkey_fingerprint
    assert current != next_key
    _signed_by(rig, kit, current, home)
    done = box.run(*INSTALL, f"/kit/pkg/{rpm_name(VERSIONS[0])}")
    assert done.code == 0, done.output
    done = tool.update()
    assert done.code == 0 and not tool.refused(done), done.output
    assert tool.listed() == {tool.version(TAG)}
    _switch_to_the_next_subkey(rig, kit)
    publish(rig, who, NEXT_TAG, time.time())
    _signed_by(rig, kit, next_key, home)
    # the client that did not upgrade the keyring cannot verify the new signature
    done = tool.update()
    assert tool.refused(done), done.output
    assert REFUSALS[name] in done.output, done.output
    # nothing new was accepted; what is still offered is what the client does with a refusal
    assert tool.listed() == (set() if name in DROPS_THE_DATA else {tool.version(TAG)})
    # the upgrade brings the next subkey and clears the cached repository key
    done = box.run(*INSTALL, f"/kit/pkg/{rpm_name(VERSIONS[1])}")
    assert done.code == 0, done.output
    done = tool.update()
    assert done.code == 0 and not tool.refused(done), done.output
    assert tool.version(NEXT_TAG) in tool.listed()
    done = tool.install()
    assert done.code == 0, done.output
    assert tool.installed() == tool.version(NEXT_TAG)


@pytest.mark.parametrize("name", list(IMAGES))
def test_a_client_that_did_not_upgrade_the_keyring_fails_the_rotation_and_one_that_did_follows_it(
    name: str,
    kit: Kit,
    packages: Path,
    make_rig: Callable[..., Rig],
    tmp_path: Path,
) -> None:
    image: Image = IMAGES[name]
    who = native_product("a-php", "a", PHP)
    rig = make_rig(who, rpm_key=RPM_KEY_NAME)
    publish(rig, who, TAG, time.time())
    with (
        Mirror(rig) as mirror,
        Box(image, client_kit(tmp_path / "kit", packages, mirror, PHP)) as box,
    ):
        if image.family == "apt":
            _apt(box, rig, kit, name, tmp_path / "verify")
        else:
            _dnf(box, rig, kit, name, tmp_path / "verify")
