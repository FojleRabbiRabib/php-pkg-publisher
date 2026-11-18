# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""What the `setup.sh` container tests share: the script copy, expected files, the client prep.

The script keeps one `BASE` constant; the tests run a copy in which that single line names the
mirror, so everything else is the shipped text. Expected values are spelled out here byte for byte
and are not read from the script.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from box import Box, Done
from keyrings import DEB_KEY, RPM_KEY, SERVED_DEB, SERVED_RPM
from mirror import Mirror
from pkgkit import build_rpm
from rig import Kit

ROOT: Final = Path(__file__).resolve().parents[2]
BASE_LINE: Final = "BASE='https://pkg.rabib.me'"
APT_SOURCES: Final = "/etc/apt/sources.list.d/rabib.sources"
DNF_REPO: Final = "/etc/yum.repos.d/rabib.repo"
PHP: Final = "8.3"
TAG: Final = "v1.0.0"
DEAD_ID: Final = "dead"
VERSIONS: Final = ("8.3", "8.4", "8.5")
FAKE_PHP: Final = {
    "php-common-8.3.1.rpm": ("php-common", "8.3.1"),
    "php-common-8.4.2.rpm": ("php-common", "8.4.2"),
    "php85-php-common-8.5.0.rpm": ("php85-php-common", "8.5.0"),
}
TAMPER_APT: Final = {"apt/dists/stable/InRelease", "apt/dists/stable/Release"}
TAMPER_RPM: Final = f"rpm/{PHP}/x86_64/repodata/repomd.xml.asc"
KEY_LINE: Final = re.compile(
    r"^ {2}(primary key|signing subkey) ([0-9A-F]{40}), "
    r"(expires \d{4}-\d{2}-\d{2}|does not expire)$",
    re.MULTILINE,
)


def build_php_rpms(root: Path) -> Path:
    """Empty rpms named like the PHP packages setup.sh looks for, to install as a fake PHP."""
    directory = root / "php"
    directory.mkdir()
    for file, (name, version) in FAKE_PHP.items():
        build = directory / f"build-{file}"
        build.mkdir()
        data = build_rpm(build, name=name, version=version, release="1", arch="noarch")
        (directory / file).write_bytes(data)
    return directory


def script(base: str) -> str:
    text = (ROOT / "setup.sh").read_text(encoding="utf-8")
    assert text.count(BASE_LINE) == 1, "setup.sh must keep exactly one BASE line"
    return text.replace(BASE_LINE, f"BASE='{base}'")


def sources(base: str) -> str:
    return f"Types: deb\nURIs: {base}/apt\nSuites: stable\nComponents: main\nSigned-By: {DEB_KEY}\n"


def repo(base: str, enabled: set[str]) -> str:
    blocks = []
    for version in VERSIONS:
        digits = version.replace(".", "")
        blocks.append(
            f"[rabib-php{digits}]\nname=Rabib PHP extensions for PHP {version}\n"
            f"baseurl={base}/rpm/{version}/$basearch\nenabled={int(version in enabled)}\n"
            f"gpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file://{RPM_KEY}\n"
        )
    return "\n".join(blocks)


def served(packages: Path) -> dict[str, bytes]:
    """The two files a client downloads from `/keyring/`."""
    directory = packages / "served"
    return {
        f"keyring/{SERVED_DEB}": (directory / SERVED_DEB).read_bytes(),
        f"keyring/{SERVED_RPM}": (directory / SERVED_RPM).read_bytes(),
    }


def kit_dir(directory: Path, php_rpms: Path, mirror: Mirror) -> Path:
    """The modified script and the fake PHP rpms, world-readable inside the container."""
    directory.mkdir()
    (directory / "setup.sh").write_text(script(mirror.base), encoding="utf-8")
    (directory / "php").mkdir()
    for file in FAKE_PHP:
        (directory / "php" / file).write_bytes((php_rpms / file).read_bytes())
    for path in (directory, *directory.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return directory


def prepare(box: Box, family: str, *, gpg: bool, offline: bool) -> None:
    """Give the client `curl` (and `gnupg`), then optionally switch off its own repositories."""
    if family == "apt":
        packages = ["curl", "gnupg"] if gpg else ["curl"]
        done = box.run("apt-get", "update", "-qq")
        assert done.code == 0, done.output
        done = box.run("apt-get", "install", "-y", "-qq", "--no-install-recommends", *packages)
        assert done.code == 0, done.output
        if offline:
            done = box.run("sh", "-c", "rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*")
            assert done.code == 0, done.output
    else:
        if gpg and box.run("sh", "-c", "command -v gpg").code != 0:
            done = box.run("dnf", "install", "-y", "-q", "gnupg2")
            assert done.code == 0, done.output
        if offline:
            done = box.run(
                "sh", "-c", "mkdir /root/repos-off && mv /etc/yum.repos.d/*.repo /root/repos-off/"
            )
            assert done.code == 0, done.output


def add_dead_repository(box: Box, family: str) -> None:
    """An unrelated repository whose server refuses connections, and that must fail its refresh."""
    if family == "apt":
        text = "Types: deb\nURIs: http://127.0.0.1:1/\nSuites: stable\nComponents: main\n"
        path = "/etc/apt/sources.list.d/dead.sources"
    else:
        text = (
            f"[{DEAD_ID}]\nname=dead\nbaseurl=http://127.0.0.1:1/\nenabled=1\n"
            "skip_if_unavailable=0\ngpgcheck=0\n"
        )
        path = "/etc/yum.repos.d/dead.repo"
    done = box.run("sh", "-c", f"printf '%s' '{text}' > {path}")
    assert done.code == 0, done.output


def apt_lists(box: Box) -> set[str]:
    """The index files apt keeps for the repositories it knows."""
    done = box.run("ls", "/var/lib/apt/lists")
    assert done.code == 0, done.output
    return set(done.output.split())


def printed(output: str) -> list[tuple[str, str]]:
    """The (kind, fingerprint) pairs of the key lines the script printed."""
    return [(kind, fingerprint) for kind, fingerprint, _ in KEY_LINE.findall(output)]


def run(box: Box) -> Done:
    return box.run("sh", "/kit/setup.sh")


def check_printed(kit: Kit, output: str, *, subkeys: int) -> None:
    """The primary key first, then the signing subkeys, and the repo subkey is among them."""
    found = printed(output)
    assert found[0] == ("primary key", kit.master.primary_fingerprint.upper()), output
    assert all(kind == "signing subkey" for kind, _ in found[1:]), output
    assert len(found) == 1 + subkeys, output
    assert kit.master.subkey_fingerprint.upper() in {fingerprint for _, fingerprint in found}
