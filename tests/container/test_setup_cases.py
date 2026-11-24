# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""`setup.sh` in the corners: what it refuses, which PHP it finds, and when it installs gnupg.

The main lifecycle is `test_setup.py`. The refusal cases need no network. The gnupg cases use the
distribution's own repositories on purpose, because that is the path under test.
"""

from __future__ import annotations

import re
import shlex
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from box import Box, docker_available
from clients import native_product, publish
from images import IMAGES, Image
from keyrings import DEB_KEY, RPM_KEY, RPM_KEY_NAME
from mirror import Mirror
from rig import Kit, Rig
from setupkit import (
    APT_SOURCES,
    DNF_REPO,
    PHP,
    TAG,
    check_printed,
    kit_dir,
    prepare,
    printed,
    repo,
    run,
    served,
)

pytestmark = pytest.mark.container

DNF_IMAGES = [name for name, image in IMAGES.items() if image.family == "dnf"]
ENABLED = re.compile(r"^\[rabib-php(\d)(\d)\]\n(?:[^\[\n].*\n)*?enabled=1$", re.MULTILINE)


@pytest.fixture(scope="session", autouse=True)
def _docker() -> None:
    assert docker_available(), "the container layer needs a running docker"


def _enabled(box: Box) -> set[str]:
    """The PHP versions whose section of the repository file is enabled."""
    text = box.run("cat", DNF_REPO).output
    return {f"{major}.{minor}" for major, minor in ENABLED.findall(text)}


@pytest.mark.parametrize("name", list(IMAGES))
def test_setup_refuses_what_it_cannot_serve_and_writes_nothing(
    name: str, php_rpms: Path, make_rig: Callable[..., Rig], tmp_path: Path
) -> None:
    image: Image = IMAGES[name]
    rig = make_rig(native_product("a-php", "a", PHP))
    with Mirror(rig) as mirror, Box(image, kit_dir(tmp_path / "kit", php_rpms, mirror)) as box:
        # not root
        done = box.run("sh", "/kit/setup.sh", user="65534")
        assert done.code == 1 and "it must run as root" in done.output, done.output
        # arguments: the one option is checked before anything else is looked at
        for arguments in (("--help",), ("--fingerprint",), ("--fingerprint", "ABC")):
            done = box.run("sh", "/kit/setup.sh", *arguments)
            assert done.code == 1, done.output
            assert "--fingerprint" in done.output or "40 hexadecimal digits" in done.output
        # an architecture the repository has no packages for
        stub = "dpkg" if image.family == "apt" else "uname"
        done = box.run("sh", "-c", f"printf '#!/bin/sh\\necho riscv64\\n' > /usr/local/bin/{stub}")
        assert done.code == 0, done.output
        assert box.run("chmod", "755", f"/usr/local/bin/{stub}").code == 0
        done = run(box)
        assert done.code == 1 and "unsupported architecture riscv64" in done.output, done.output
        assert box.run("rm", f"/usr/local/bin/{stub}").code == 0
        # without curl (the apt images ship none)
        if image.family == "apt":
            done = run(box)
            assert done.code == 1 and "curl is required" in done.output, done.output
        # a distribution it does not know
        done = box.run("sh", "-c", "printf 'ID=plan9\\n' > /etc/os-release")
        assert done.code == 0, done.output
        done = run(box)
        assert done.code == 1 and "unsupported distribution (ID=plan9)" in done.output, done.output
        # none of it wrote a repository definition
        assert box.run("sh", "-c", "ls /etc/apt/sources.list.d/rabib.sources").code != 0
        assert box.run("sh", "-c", "ls /etc/yum.repos.d/rabib.repo").code != 0


@pytest.mark.parametrize("name", list(IMAGES))
def test_setup_stops_before_anything_is_installed_when_the_fingerprint_differs(
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
    primary = kit.master.primary_fingerprint.upper()
    with (
        Mirror(rig, served(packages)) as mirror,
        Box(image, kit_dir(tmp_path / "kit", php_rpms, mirror)) as box,
    ):
        prepare(box, image.family, gpg=True, offline=True)
        keys = set(box.run("sh", "-c", "rpm -qa 'gpg-pubkey*' 2>/dev/null || true").output.split())
        wrong = "0123456789ABCDEF0123456789ABCDEF01234567"
        done = box.run("sh", "/kit/setup.sh", "--fingerprint", wrong)
        assert done.code == 1, done.output
        assert "is not the fingerprint you gave; nothing was installed" in done.output, done.output
        # the key was shown, read out of the package, before the refusal
        assert printed(done.output)[0] == ("primary key", primary), done.output
        # nothing was installed, imported or written
        package = "rabib-archive-keyring" if image.family == "apt" else "rabib-release"
        query = ["dpkg", "-s", package] if image.family == "apt" else ["rpm", "-q", package]
        assert box.run(*query).code != 0
        listing = f"ls {DEB_KEY} {RPM_KEY} {APT_SOURCES} {DNF_REPO} 2>/dev/null"
        assert box.run("sh", "-c", listing).output == ""
        now = box.run("sh", "-c", "rpm -qa 'gpg-pubkey*' 2>/dev/null || true").output.split()
        assert set(now) == keys
        # the right fingerprint, in lower case and in groups, goes through
        grouped = " ".join(primary.lower()[i : i + 4] for i in range(0, 40, 4))
        done = box.run("sh", "/kit/setup.sh", "--fingerprint", grouped)
        assert done.code == 0, done.output
        assert "The key matches the fingerprint you gave." in done.output, done.output
        assert box.run(*query).code == 0
        check_printed(kit, done.output, subkeys=1 if image.family == "apt" else 2)


@pytest.mark.parametrize("name", ["debian-bookworm", "almalinux-10"])
def test_setup_without_gpg_installs_gnupg_but_not_the_keyring_when_the_fingerprint_differs(
    name: str,
    packages: Path,
    php_rpms: Path,
    make_rig: Callable[..., Rig],
    tmp_path: Path,
) -> None:
    image: Image = IMAGES[name]
    who = native_product("a-php", "a", PHP)
    rig = make_rig(who, rpm_key=RPM_KEY_NAME)
    publish(rig, who, TAG, time.time())
    with (
        Mirror(rig, served(packages)) as mirror,
        Box(image, kit_dir(tmp_path / "kit", php_rpms, mirror)) as box,
    ):
        prepare(box, image.family, gpg=False, offline=False)
        assert box.run("sh", "-c", "command -v gpg").code != 0
        done = box.run("sh", "/kit/setup.sh", "--fingerprint", "0123456789ABCDEF" * 2 + "01234567")
        assert done.code == 1, done.output
        assert "Installing gnupg" in done.output, done.output
        assert "is not the fingerprint you gave; nothing was installed" in done.output, done.output
        # gnupg came from the distribution; nothing of ours was installed, imported or written
        package = "rabib-archive-keyring" if image.family == "apt" else "rabib-release"
        query = ["dpkg", "-s", package] if image.family == "apt" else ["rpm", "-q", package]
        assert box.run(*query).code != 0
        listing = f"ls {DEB_KEY} {RPM_KEY} {APT_SOURCES} {DNF_REPO} 2>/dev/null"
        assert box.run("sh", "-c", listing).output == ""
        keys = box.run("sh", "-c", "rpm -qa 'gpg-pubkey*' 2>/dev/null || true").output
        assert "rabib" not in keys.lower()


@pytest.mark.parametrize("name", DNF_IMAGES)
def test_setup_enables_the_section_of_each_php_it_finds_and_never_disables_one(
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
    with (
        Mirror(rig, served(packages)) as mirror,
        Box(image, kit_dir(tmp_path / "kit", php_rpms, mirror)) as box,
    ):
        prepare(box, image.family, gpg=True, offline=True)
        # no PHP: every section is off, and the hint says how to enable one
        done = run(box)
        assert done.code == 0, done.output
        assert box.run("cat", DNF_REPO).output == repo(mirror.base, set())
        hint = next(
            (line for line in done.output.splitlines() if line.startswith("  dnf config-manager ")),
            "",
        )
        assert hint, done.output
        # the printed command works as printed
        done = box.run(*shlex.split(hint))
        assert done.code == 0, done.output
        listed = box.run("dnf", "repolist", "--enabled").output
        assert "rabib-php83" in listed, listed
        # what the hint enabled counts, in whichever file this dnf stored it: a run finds it,
        # refreshes it and no longer prints the hint
        done = run(box)
        assert done.code == 0, done.output
        assert "dnf config-manager" not in done.output, done.output
        assert _enabled(box) == {"8.3"}
        # the system PHP 8.4: its section is enabled, whatever was enabled stays
        assert box.run("rpm", "-i", "/kit/php/php-common-8.4.2.rpm").code == 0
        done = run(box)
        assert done.code == 0, done.output
        assert _enabled(box) == {"8.3", "8.4"}
        # Remi's versioned PHP 8.5
        assert box.run("rpm", "-i", "/kit/php/php85-php-common-8.5.0.rpm").code == 0
        done = run(box)
        assert done.code == 0, done.output
        assert _enabled(box) == {"8.3", "8.4", "8.5"}
        # nothing is detected any more: nothing is disabled either
        assert box.run("rpm", "-e", "php-common", "php85-php-common").code == 0
        done = run(box)
        assert done.code == 0, done.output
        assert _enabled(box) == {"8.3", "8.4", "8.5"}
        # dnf's own view: dnf5 stores the hint's setting in an override file, not in the repo
        # file, so only dnf can say that the 8.3 section is still enabled
        listed = box.run("dnf", "repolist", "--enabled").output
        for section in ("rabib-php83", "rabib-php84", "rabib-php85"):
            assert section in listed, listed
        if "dnf5" in box.run("dnf", "--version").output:
            # an explicit off in an override file beats a detected PHP, and the file keeps it off
            off = "/etc/dnf/repos.override.d/50-off.repo"
            done = box.run("sh", "-c", f"printf '[rabib-php84]\\nenabled=0\\n' > {off}")
            assert done.code == 0, done.output
            assert box.run("rpm", "-i", "/kit/php/php-common-8.4.2.rpm").code == 0
            done = run(box)
            assert done.code == 0, done.output
            assert _enabled(box) == {"8.3", "8.5"}
        else:
            # dnf 4 edits the repository file, so a section turned off by hand is turned on
            # again by a run while its PHP is installed (the install guide says so)
            assert box.run("rpm", "-i", "/kit/php/php-common-8.3.1.rpm").code == 0
            done = box.run("dnf", "config-manager", "--set-disabled", "rabib-php83")
            assert done.code == 0, done.output
            assert _enabled(box) == {"8.4", "8.5"}
            done = run(box)
            assert done.code == 0, done.output
            assert _enabled(box) == {"8.3", "8.4", "8.5"}
        check_printed(kit, done.output, subkeys=2)


@pytest.mark.parametrize("name", ["debian-bookworm", "almalinux-10"])
def test_setup_installs_gnupg_when_the_client_has_none(
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
    with (
        Mirror(rig, served(packages)) as mirror,
        Box(image, kit_dir(tmp_path / "kit", php_rpms, mirror)) as box,
    ):
        prepare(box, image.family, gpg=False, offline=False)
        assert box.run("sh", "-c", "command -v gpg").code != 0
        done = run(box)
        assert done.code == 0, done.output
        assert "Installing gnupg" in done.output, done.output
        assert box.run("sh", "-c", "command -v gpg").code == 0
        check_printed(kit, done.output, subkeys=1 if image.family == "apt" else 2)
