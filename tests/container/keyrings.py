# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The keyring packages the container tests install, built by `tools/build_keyring.py`.

The certificate has the design's shape: one master, the current repository subkey (the rig's own),
a second subkey for the RPM job, and the next repository subkey, which only the second keyring
release lists. The directory holds both versions of each package under its versioned name, a
signed copy of the first rpm in `signed/`, and the two fixed-name files a client downloads from
`/keyring/` in `served/`.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import build_keyring
from mirror import Mirror
from pkgkit import Key, add_signing_subkey, stop_agent, subkeys_only, with_second_subkey
from rig import Kit

VERSIONS: Final = ("2026.1", "2026.2")
MAINTAINER: Final = "Test Maintainer <maintainer@example.invalid>"
EPOCH: Final = 1780000000
DEB_KEY: Final = "/usr/share/keyrings/rabib-archive-keyring.gpg"
RPM_KEY: Final = "/etc/pki/rpm-gpg/RPM-GPG-KEY-rabib"
RPM_KEY_NAME: Final = "keyring"  # the name under which `build` registers its RPM signing key
# the name of the key whose signing subkey is the repository's next one: its home holds the
# subkeys only, and the second keyring release lists that subkey next to the current one
ROTATION_KEY_NAME: Final = "rotation"
SERVED_DEB: Final = "rabib-archive-keyring.deb"
SERVED_RPM: Final = "rabib-release.rpm"


def client_kit(directory: Path, packages: Path, mirror: Mirror, php: str) -> Path:
    """Client configuration that trusts only the key files the keyring packages install."""
    directory.mkdir()
    shutil.copytree(packages, directory / "pkg")
    (directory / "apt.d").mkdir()
    (directory / "apt.d" / "test.sources").write_text(
        f"Types: deb\nURIs: {mirror.base}/apt\nSuites: stable\nComponents: main\n"
        f"Signed-By: {DEB_KEY}\n",
        encoding="utf-8",
    )
    (directory / "repos.d").mkdir()
    (directory / "repos.d" / "test.repo").write_text(
        f"[rabib-test]\nname=test\nbaseurl={mirror.base}/rpm/{php}/x86_64\nenabled=1\n"
        f"gpgcheck=0\nrepo_gpgcheck=1\ngpgkey=file://{RPM_KEY}\n",
        encoding="utf-8",
    )
    for path in (directory, *directory.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return directory


def deb_name(version: str) -> str:
    return f"rabib-archive-keyring_{version}_all.deb"


def rpm_name(version: str) -> str:
    return f"rabib-release-{version}-1.noarch.rpm"


def build(kit: Kit, root: Path) -> Iterator[Path]:
    """Build everything under `root`, yield the package directory, stop the signing agents."""
    cert = with_second_subkey(kit.tools, kit.master, root, "cert")
    try:
        # a release signed with this key verifies against the key file the rpm installs
        kit.rpm_keys[RPM_KEY_NAME] = cert
        # the repository's next signing subkey: only the second keyring release lists it
        rotated = add_signing_subkey(kit.tools, cert, root, "rotated")
        kit.rpm_keys[ROTATION_KEY_NAME] = subkeys_only(kit.tools, rotated, root, "rotation")
        yield from _packages(kit, root, cert, rotated)
    finally:
        kit.rpm_keys.pop(RPM_KEY_NAME, None)
        rotation = kit.rpm_keys.pop(ROTATION_KEY_NAME, None)
        if rotation is not None:
            stop_agent(rotation)
        stop_agent(cert)


def _packages(kit: Kit, root: Path, cert: Key, rotated: Key) -> Iterator[Path]:
    directory = root / "packages"
    directory.mkdir()

    def run(version: str, output: Path, *extra: str) -> None:
        # the first release trusts the current repository subkey, the second adds the next one
        second = version == VERSIONS[1]
        repo = [kit.master.subkey_fingerprint, *([rotated.subkey_fingerprint] if second else [])]
        code = build_keyring.main(
            [
                *("--key", str(rotated.public if second else cert.public)),
                *("--fingerprint", cert.primary_fingerprint.upper()),
                *(arg for item in repo for arg in ("--repo-subkey", item.upper())),
                *("--rpm-subkey", cert.subkey_fingerprint.upper()),
                *("--version", version),
                *("--maintainer", MAINTAINER),
                *("--source-date-epoch", str(EPOCH)),
                *("--output", str(output)),
                *extra,
            ]
        )
        assert code == 0

    for version in VERSIONS:
        output = root / f"out-{version}"
        run(version, output, "--unsigned")
        for name in (deb_name(version), rpm_name(version)):
            shutil.copy(output / name, directory / name)
    # the rpm that ships is signed by the RPM subkey
    signed = root / "out-signed"
    run(
        VERSIONS[0],
        signed,
        "--sign-home",
        str(cert.home),
        "--sign-key",
        cert.subkey_fingerprint,
    )
    (directory / "signed").mkdir()
    shutil.copy(signed / rpm_name(VERSIONS[0]), directory / "signed" / rpm_name(VERSIONS[0]))
    (directory / "served").mkdir()
    shutil.copy(signed / SERVED_RPM, directory / "served" / SERVED_RPM)
    shutil.copy(root / f"out-{VERSIONS[0]}" / SERVED_DEB, directory / "served" / SERVED_DEB)
    for path in (directory, *directory.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
    yield directory
