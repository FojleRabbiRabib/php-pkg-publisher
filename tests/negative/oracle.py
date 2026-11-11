# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Read a published tree the way a client would, without calling the publisher's own code.

Signatures are checked with `gpgv` against the pinned public certificate; the package lists are
parsed from `Packages` and `primary.xml` with the standard library.
"""

from __future__ import annotations

import datetime
import gzip
import hashlib
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

COMMON = "{http://linux.duke.edu/metadata/common}"
REPO = "{http://linux.duke.edu/metadata/repo}"
DATE_FORMAT = "%a, %d %b %Y %H:%M:%S UTC"
GPG = "/usr/bin/gpg"
GPGV = "/usr/bin/gpgv"


class Client:
    """What a client sees of the tree under `root` (`apt/` and `rpm/` are inside it)."""

    def __init__(self, root: Path, certificate: Path, scratch: Path) -> None:
        self.root = root
        scratch.mkdir(parents=True, exist_ok=True)
        self._keyring = scratch / "client.gpg"
        environment = {"GNUPGHOME": str(scratch), "PATH": "/usr/bin:/bin"}
        scratch.chmod(0o700)
        subprocess.run(  # noqa: S603
            [GPG, "--batch", "--yes", "--dearmor", "--output", self._keyring, certificate],
            env=environment,
            check=True,
            capture_output=True,
        )

    def _gpgv(self, *arguments: Path) -> bool:
        done = subprocess.run(  # noqa: S603
            [GPGV, "--keyring", self._keyring, *arguments],
            env={"PATH": "/usr/bin:/bin"},
            check=False,
            capture_output=True,
        )
        return done.returncode == 0

    def in_release_verifies(self) -> bool:
        """`gpgv` accepts the clear-signed `InRelease`."""
        return self._gpgv(self.root / "apt/dists/stable/InRelease")

    def release_gpg_verifies(self) -> bool:
        """`gpgv` accepts the detached `Release.gpg` over `Release`."""
        base = self.root / "apt/dists/stable"
        return self._gpgv(base / "Release.gpg", base / "Release")

    def repomd_verifies(self) -> bool:
        """Every `repomd.xml` has a detached signature that `gpgv` accepts (there are six)."""
        listed = sorted(self.root.glob("rpm/*/*/repodata/repomd.xml"))
        return len(listed) == 6 and all(
            self._gpgv(item.with_name("repomd.xml.asc"), item) for item in listed
        )

    def apt_packages(self) -> dict[str, str]:
        """File name -> version of every package in every `Packages` file."""
        found: dict[str, str] = {}
        for index in sorted(self.root.glob("apt/dists/stable/*/binary-*/Packages")):
            for stanza in index.read_text(encoding="utf-8").split("\n\n"):
                fields = dict(line.split(": ", 1) for line in stanza.splitlines() if ": " in line)
                if "Filename" in fields:
                    found[PurePosixPath(fields["Filename"]).name] = fields["Version"]
        return found

    def rpm_packages(self) -> dict[str, str]:
        """File name -> version of the packages in the `primary.xml` each `repomd.xml` names.

        `repodata/` also keeps hash-named files of earlier generations; a client never reads
        them, because only `repomd.xml` says which `primary.xml` is current.
        """
        found: dict[str, str] = {}
        for repomd in sorted(self.root.glob("rpm/*/*/repodata/repomd.xml")):
            entry = next(
                data
                for data in ET.parse(repomd).getroot().findall(f"{REPO}data")  # noqa: S314
                if data.attrib["type"] == "primary"
            )
            location = entry.find(f"{REPO}location")
            assert location is not None
            index = repomd.parent.parent / location.attrib["href"]
            with gzip.open(index) as handle:
                tree = ET.parse(handle)  # noqa: S314  (our own throwaway tree)
            for package in tree.getroot().findall(f"{COMMON}package"):
                location = package.find(f"{COMMON}location")
                version = package.find(f"{COMMON}version")
                assert location is not None
                assert version is not None
                found[PurePosixPath(location.attrib["href"]).name] = version.attrib["ver"]
        return found

    def served_files(self) -> frozenset[str]:
        """The file names a client can install from this tree."""
        return frozenset(self.served_versions())

    def served_versions(self) -> dict[str, str]:
        """File name -> version of every package a client can install from this tree."""
        return {**self.apt_packages(), **self.rpm_packages()}

    def index_hashes_match(self) -> bool:
        """The signed files record the hash and size of every index a client then reads.

        apt: the `SHA256` block of `InRelease` must list each `Packages` file and match it.
        dnf: each `repomd.xml` must match the file its `primary` entry names (gzip and plain).
        """
        base = self.root / "apt/dists/stable"
        text = (base / "InRelease").read_text(encoding="utf-8")
        block = re.search(r"^SHA256:\n((?: .*\n)+)", text, re.MULTILINE)
        if block is None:
            return False
        listed: dict[str, tuple[str, int]] = {}
        for line in block.group(1).splitlines():
            digest, size, name = line.split()
            listed[name] = (digest, int(size))
        indexes = sorted(base.glob("*/binary-*/Packages"))
        repomds = sorted(self.root.glob("rpm/*/*/repodata/repomd.xml"))
        if not indexes or len(repomds) != 6:
            return False  # nothing to compare is not a match
        for index in indexes:
            data = index.read_bytes()
            wanted = listed.get(index.relative_to(base).as_posix())
            if wanted != (hashlib.sha256(data).hexdigest(), len(data)):
                return False
        for repomd in repomds:
            for entry in ET.parse(repomd).getroot().findall(f"{REPO}data"):  # noqa: S314
                location = entry.find(f"{REPO}location")
                checksum = entry.find(f"{REPO}checksum")
                assert location is not None
                assert checksum is not None
                data = (repomd.parent.parent / location.attrib["href"]).read_bytes()
                if hashlib.sha256(data).hexdigest() != checksum.text:
                    return False
                opened = entry.find(f"{REPO}open-checksum")
                if opened is not None and (
                    hashlib.sha256(gzip.decompress(data)).hexdigest() != opened.text
                ):
                    return False
        return True

    def release_dates(self) -> tuple[datetime.datetime, datetime.datetime]:
        """`Date` and `Valid-Until` of the signed `InRelease`."""
        text = (self.root / "apt/dists/stable/InRelease").read_text(encoding="utf-8")
        values = {
            name: re.search(rf"^{name}: (.+)$", text, re.MULTILINE)
            for name in ("Date", "Valid-Until")
        }
        found = [values["Date"], values["Valid-Until"]]
        assert all(found)
        issued, until = (
            datetime.datetime.strptime(match.group(1), DATE_FORMAT).replace(
                tzinfo=datetime.timezone.utc
            )
            for match in found
            if match is not None
        )
        return issued, until

    def package_bytes_in_tree(self) -> list[str]:
        """Any `.deb` or `.rpm` file inside the tree; the repository never serves one."""
        return sorted(
            str(path.relative_to(self.root))
            for path in self.root.rglob("*")
            if path.suffix in (".deb", ".rpm")
        )
