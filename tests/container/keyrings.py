# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The keyring packages the container tests install, built by `tools/build_keyring.py`.

The certificate has the design's shape: one master, the repository subkey that signs the tree
(the rig's own), and a second subkey for the RPM job. The directory holds both versions of each
package under its versioned name, a signed copy of the first rpm in `signed/`, and the two
fixed-name files a client downloads from `/keyring/` in `served/`.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import build_keyring
from pkgkit import stop_agent, with_second_subkey
from rig import Kit

VERSIONS: Final = ("2026.1", "2026.2")
MAINTAINER: Final = "Test Maintainer <maintainer@example.invalid>"
EPOCH: Final = 1780000000
DEB_KEY: Final = "/usr/share/keyrings/rabib-archive-keyring.gpg"
RPM_KEY: Final = "/etc/pki/rpm-gpg/RPM-GPG-KEY-rabib"
RPM_KEY_NAME: Final = "keyring"  # the name under which `build` registers its RPM signing key
SERVED_DEB: Final = "rabib-archive-keyring.deb"
SERVED_RPM: Final = "rabib-release.rpm"


def deb_name(version: str) -> str:
    return f"rabib-archive-keyring_{version}_all.deb"


def rpm_name(version: str) -> str:
    return f"rabib-release-{version}-1.noarch.rpm"


def build(kit: Kit, root: Path) -> Iterator[Path]:
    """Build everything under `root`, yield the package directory, stop the signing agent."""
    cert = with_second_subkey(kit.tools, kit.master, root, "cert")
    # a release signed with this key verifies against the key file the rpm installs
    kit.rpm_keys[RPM_KEY_NAME] = cert
    directory = root / "packages"
    directory.mkdir()

    def run(version: str, output: Path, *extra: str) -> None:
        code = build_keyring.main(
            [
                *("--key", str(cert.public)),
                *("--fingerprint", cert.primary_fingerprint.upper()),
                *("--repo-subkey", kit.master.subkey_fingerprint.upper()),
                *("--rpm-subkey", cert.subkey_fingerprint.upper()),
                *("--version", version),
                *("--maintainer", MAINTAINER),
                *("--source-date-epoch", str(EPOCH)),
                *("--output", str(output)),
                *extra,
            ]
        )
        assert code == 0

    try:
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
    finally:
        kit.rpm_keys.pop(RPM_KEY_NAME, None)
        stop_agent(cert)
