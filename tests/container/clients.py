# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The `apt` and `dnf` drivers and the publish step shared by the container tests."""

from __future__ import annotations

import re

from box import Box, Done
from rig import Rig

from publisher.config import Product

BASE_RPM = "php-a"


def publish(rig: Rig, who: Product, tag: str, now: float) -> str:
    """Release `tag` of `who` through one real pass and return the new generation's id."""
    files = rig.kit.release(who, tag, rpm_key=rig.rpm_key)
    rig.feed.add(who.repo, tag, files)
    result = rig.run_pass(now)
    assert result.failure is None, f"the publisher pass failed: {result.failure}"
    return rig.current_id()


class Apt:
    OPTIONS = ("-o", "Dir::Etc::SourceList=/dev/null", "-o", "Dir::Etc::SourceParts=/kit/apt.d")

    def __init__(self, box: Box, php: str) -> None:
        self.box = box
        self.package = f"php{php}-a"

    def update(self) -> Done:
        return self.box.run("apt-get", *self.OPTIONS, "update")

    def install(self) -> Done:
        return self.box.run("apt-get", *self.OPTIONS, "install", "-y", self.package)

    def listed(self) -> set[str]:
        """The versions the repository offers, as `apt-cache madison` lists them."""
        done = self.box.run("apt-cache", *self.OPTIONS, "madison", self.package)
        assert done.code == 0, done.output
        return {line.split("|")[1].strip() for line in done.output.splitlines() if "|" in line}

    def installed(self) -> str:
        return self.box.run("dpkg-query", "-W", "-f=${Version}", self.package).output

    @staticmethod
    def refused(done: Done) -> bool:
        """apt exits 0 for a refused index ("the repository is not updated"), so read the error."""
        text = done.output.lower()
        return done.code != 0 or ("err:" in text and "signature" in text)

    @staticmethod
    def version(tag: str) -> str:
        return tag.removeprefix("v") + "-1"


class Dnf:
    OPTIONS = ("-y", "--setopt=reposdir=/kit/repos.d")

    def __init__(self, box: Box, php: str) -> None:
        self.box = box
        self.versioned = f"php{php.replace('.', '')}-php-a"

    def update(self) -> Done:
        return self.box.run("dnf", *self.OPTIONS, "makecache", "--refresh")

    def install(self) -> Done:
        return self.box.run("dnf", *self.OPTIONS, "install", BASE_RPM, self.versioned)

    def upgrade(self) -> Done:
        return self.box.run("dnf", *self.OPTIONS, "upgrade", BASE_RPM, self.versioned)

    def listed(self) -> set[str]:
        """The versions the repository offers, as `dnf repoquery` lists them."""
        done = self.box.run(
            "dnf",
            *self.OPTIONS,
            "repoquery",
            "--available",
            "--queryformat",
            "%{version}\n",
            BASE_RPM,
        )
        assert done.code == 0, done.output
        return {
            line.strip()
            for line in done.output.splitlines()
            if re.fullmatch(r"\d+\.\d+\.\d+", line.strip())
        }

    def installed(self) -> str:
        return self.box.run("rpm", "-q", "--qf", "%{VERSION}", BASE_RPM).output

    @staticmethod
    def refused(done: Done) -> bool:
        """dnf5 reports a bad `repomd.xml` signature and still exits 0, so read the error too."""
        return done.code != 0 or "gpg signature verification error" in done.output.lower()

    @staticmethod
    def version(tag: str) -> str:
        return tag.removeprefix("v")
