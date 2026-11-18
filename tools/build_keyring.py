#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Build the two keyring packages from the public certificate, offline.

    python tools/build_keyring.py --key rabib.asc --fingerprint <primary> \\
        --repo-subkey <fpr> [--repo-subkey <fpr> ...] --rpm-subkey <fpr> [--rpm-subkey <fpr> ...] \\
        --version 2026.1 --maintainer "Name <address>" --source-date-epoch <seconds> \\
        --output DIR  (--sign-home GNUPGHOME --sign-key <fpr> | --unsigned)

`rabib-archive-keyring` (deb) installs the apt keyring: the primary key and the repo subkeys
only, so apt never accepts metadata signed by the RPM subkey. `rabib-release` (rpm) installs the
full key for dnf (repo and RPM subkeys) and clears dnf's cached copy of it; it does not import the
key, because rpm 6 cannot do that inside a transaction and dnf imports it from the `.repo` file.

Nothing is inferred and nothing is kept: the primary fingerprint and every subkey are named on the
command line, the certificate must be public, unexpired and unrevoked, and each exported key is
read back and must hold exactly the expected keys before anything is written. The packages are
reproducible: the same inputs and `--source-date-epoch` give the same bytes (a signed rpm differs
by its signature time). Programs run as argument arrays, never through a shell.
"""

from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
SOURCES: Final = ROOT / "keyring"
SEARCH_PATH: Final = "/usr/local/bin:/usr/bin:/bin"
CHILD_PATH: Final = "/usr/bin:/bin"
FINGERPRINT: Final = re.compile(r"[0-9A-F]{40}")
VERSION: Final = re.compile(r"[0-9]{4}\.[1-9][0-9]*")
VALID_STATES: Final = frozenset({"-", "u", "f", "m"})
DEB_NAME: Final = "rabib-archive-keyring"
RPM_NAME: Final = "rabib-release"
APT_KEYRING: Final = "usr/share/keyrings/rabib-archive-keyring.gpg"
RPM_KEY: Final = "RPM-GPG-KEY-rabib"
WEEKDAYS: Final = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MONTHS: Final = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
TOKENS: Final = re.compile(r"@[A-Z_]+@")
# No `%`: rpmbuild expands macros, including `%(command)`, in the spec's changelog text.
MAINTAINER: Final = re.compile(r"[^<>\n%]+ <[^<>\s@%]+@[^<>\s@%]+>")


class BuildError(Exception):
    """The keyring cannot be built; the text says why and holds no key material."""


@dataclass(frozen=True, slots=True)
class Cert:
    primary: str
    subkeys: dict[str, str]  # subkey fingerprint -> capabilities


def _program(name: str) -> str:
    found = shutil.which(name, path=SEARCH_PATH)
    if found is None:
        raise BuildError(f"{name} is not installed in {SEARCH_PATH}")
    return found


def _run(
    command: Sequence[str | Path], *, env: dict[str, str] | None = None, cwd: Path | None = None
) -> str:
    environment = {"PATH": CHILD_PATH, "LC_ALL": "C", **(env or {})}
    done = subprocess.run(  # noqa: S603
        [os.fspath(part) for part in command],
        capture_output=True,
        check=False,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    if done.returncode != 0:
        raise BuildError(f"{Path(str(command[0])).name} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def inspect(gpg: str, home: Path, data: Path) -> Cert:
    """Read a key file: one public primary key, valid, and its valid subkeys."""
    listing = _run(
        [
            gpg,
            *("--homedir", home),
            *("--batch", "--no-tty", "--with-colons", "--fixed-list-mode"),
            *("--show-keys", data),
        ],
        env={"GNUPGHOME": str(home)},
    )
    records = [line.split(":") for line in listing.splitlines()]
    if any(record[0] in ("sec", "ssb") for record in records):
        raise BuildError("the key file holds secret key material; give the public certificate")
    primaries = [i for i, record in enumerate(records) if record[0] == "pub"]
    if len(primaries) != 1:
        raise BuildError("the key file must hold exactly one primary key")
    primary = records[primaries[0]]
    if primary[1] not in VALID_STATES:
        raise BuildError("the primary key is expired or revoked")
    subkeys: dict[str, str] = {}
    fingerprints: list[str] = []
    for index, record in enumerate(records):
        if record[0] not in ("pub", "sub"):
            continue
        following = records[index + 1] if index + 1 < len(records) else []
        fingerprint = following[9].upper() if following[:1] == ["fpr"] else ""
        fingerprints.append(fingerprint)
        if record[0] == "sub" and record[1] in VALID_STATES:
            subkeys[fingerprint] = record[11].lower()
    if not FINGERPRINT.fullmatch(fingerprints[0]):
        raise BuildError("the primary key has no readable fingerprint")
    return Cert(primary=fingerprints[0], subkeys=subkeys)


def check(cert: Cert, *, fingerprint: str, repo: Sequence[str], rpm: Sequence[str]) -> None:
    if cert.primary != fingerprint:
        raise BuildError("the primary key is not the one named by --fingerprint")
    if set(repo) & set(rpm):
        raise BuildError("a subkey cannot be both a repo subkey and an RPM subkey")
    for name, fingerprints in (("repo", repo), ("rpm", rpm)):
        if not fingerprints:
            raise BuildError(f"name at least one --{name}-subkey")
        for item in fingerprints:
            capabilities = cert.subkeys.get(item)
            if capabilities is None:
                raise BuildError(f"{name} subkey {item[-16:]} is missing, expired or revoked")
            if "s" not in capabilities:
                raise BuildError(f"{name} subkey {item[-16:]} cannot sign")


def drop_filter(keep: Sequence[str]) -> str:
    """The gpg export filter that drops every subkey except the `keep` fingerprints.

    `<>` is the string comparison. `!=` is numeric: gpg reads a fingerprint as a number, so two
    fingerprints that start with a letter would both compare as 0 and every subkey would stay.
    """
    return "drop-subkey=" + " && ".join(f"fpr <> {item}" for item in keep)


def export(
    gpg: str, home: Path, data: Path, *, cert: Cert, keep: Sequence[str], armor: bool
) -> bytes:
    """Export the primary key with only the `keep` subkeys, then read the result back."""
    env = {"GNUPGHOME": str(home)}
    base: list[str | Path] = [gpg, "--homedir", home, "--batch", "--no-tty"]
    _run([*base, "--import", data], env=env)
    command: list[str | Path] = [*base, "--export", "--export-options", "export-minimal"]
    command += ["--export-filter", drop_filter(keep)]
    if armor:
        command.append("--armor")
    target = home / "exported"
    command += ["--output", target, cert.primary]
    _run(command, env=env)
    data_out = target.read_bytes()
    again = inspect(gpg, home, target)
    target.unlink()
    if again.primary != cert.primary or set(again.subkeys) != set(keep):
        raise BuildError("the exported key does not hold exactly the expected keys")
    return data_out


def _stamp(root: Path, epoch: int) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch))


def _substitute(template: str, values: dict[str, str]) -> str:
    """Fill the `@TOKEN@`s of an rpm spec; `%` is doubled so no value is read as a macro."""
    text = template
    for name, value in values.items():
        text = text.replace(f"@{name}@", value.replace("%", "%%"))
    if TOKENS.search(text):
        raise BuildError("a template token was not replaced")
    return text


def build_deb(
    work: Path, key: bytes, *, version: str, maintainer: str, epoch: int, output: Path
) -> Path:
    root = work / "deb"
    doc = root / "usr/share/doc" / DEB_NAME
    for directory in (
        doc,
        root / "usr/share/keyrings",
        root / "DEBIAN",
    ):
        directory.mkdir(parents=True)
    (root / APT_KEYRING).write_bytes(key)
    shutil.copyfile(SOURCES / "copyright", doc / "copyright")
    for name in ("LICENSE", "NOTICE"):  # Apache-2.0 section 4: every redistribution keeps both
        shutil.copyfile(ROOT / name, doc / name)
    day = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    stamp = (
        f"{WEEKDAYS[day.weekday()]}, {day.day:02d} {MONTHS[day.month - 1]} {day.year} "
        f"{day:%H:%M:%S} +0000"
    )
    changelog = (
        f"{DEB_NAME} ({version}) unstable; urgency=medium\n\n"
        f"  * Keyring release {version}.\n\n -- {maintainer}  {stamp}\n"
    )
    # A version without a revision makes a native package, whose changelog is `changelog.gz`.
    (doc / "changelog.gz").write_bytes(gzip.compress(changelog.encode(), 9, mtime=0))
    size = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    # dpkg-deb --verify and debsums read this list; MD5 is the format, not a security control.
    (root / "DEBIAN/md5sums").write_text(
        "".join(
            f"{hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()}  "
            f"{path.relative_to(root)}\n"
            for path in sorted(root.rglob("*"))
            if path.is_file()
        ),
        encoding="utf-8",
    )
    (root / "DEBIAN/control").write_text(
        f"Package: {DEB_NAME}\nVersion: {version}\nArchitecture: all\n"
        f"Maintainer: {maintainer}\nInstalled-Size: {-(-size // 1024)}\n"
        "Section: misc\nPriority: optional\nHomepage: https://pkg.rabib.me\n"
        "Description: package signing key of the Rabib PHP extension repository\n"
        " The public key apt uses to verify the repository metadata, installed under\n"
        " /usr/share/keyrings. It holds the primary key and the repository signing\n"
        " subkeys only.\n",
        encoding="utf-8",
    )
    for path in root.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    root.chmod(0o755)
    _stamp(root, epoch)
    target = output / f"{DEB_NAME}_{version}_all.deb"
    _run(
        [_program("dpkg-deb"), "--root-owner-group", "-Zxz", "--build", root, target],
        env={"SOURCE_DATE_EPOCH": str(epoch)},
    )
    return target


def build_rpm(
    work: Path, key: bytes, *, version: str, maintainer: str, epoch: int, output: Path
) -> Path:
    top = work / "rpm"
    for part in ("SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS"):
        (top / part).mkdir(parents=True)
    (top / "SOURCES" / RPM_KEY).write_bytes(key)
    shutil.copyfile(ROOT / "LICENSE", top / "SOURCES" / "LICENSE")
    shutil.copyfile(ROOT / "NOTICE", top / "SOURCES" / "NOTICE")
    day = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    spec = top / "SPECS" / f"{RPM_NAME}.spec"
    stamp = f"{WEEKDAYS[day.weekday()]} {MONTHS[day.month - 1]} {day.day:02d} {day.year}"
    spec.write_text(
        _substitute(
            (SOURCES / f"{RPM_NAME}.spec.in").read_text(encoding="utf-8"),
            {
                "VERSION": version,
                "DATE": stamp,
                "MAINTAINER": maintainer,
            },
        ),
        encoding="utf-8",
    )
    defines = {
        "_topdir": str(top),
        "_buildhost": "localhost",
        "use_source_date_epoch_as_buildtime": "1",
        "clamp_mtime_to_source_date_epoch": "1",
        "source_date_epoch_from_changelog": "0",
        "_binary_payload": "w6.xzdio",
        "_build_id_links": "none",
    }
    command: list[str | Path] = [_program("rpmbuild"), "-bb", "--target", "noarch-linux"]
    for name, value in defines.items():
        command += ["--define", f"{name} {value}"]
    _run([*command, spec], env={"SOURCE_DATE_EPOCH": str(epoch)})
    (built,) = (top / "RPMS").rglob("*.rpm")
    target = output / built.name
    shutil.copyfile(built, target)
    return target


def sign_rpm(package: Path, *, home: Path, fingerprint: str, certificate: Path, work: Path) -> None:
    """Sign with exactly one subkey, then check the result against the public certificate."""
    gpg = _program("gpg")
    try:
        _run(
            [
                _program("rpmsign"),
                *("--define", f"__gpg {gpg}"),
                *("--define", f"_gpg_path {home}"),
                *("--define", f"_gpg_name {fingerprint}!"),
                *("--addsign", package),
            ]
        )
    finally:  # gpg starts an agent in the key home; leave none running with the subkey loaded
        _run([_program("gpgconf"), "--homedir", home, "--kill", "gpg-agent"])
    database = work / "rpmdb"
    database.mkdir()
    _run([_program("rpmkeys"), "--dbpath", database, "--import", certificate])
    checked = _run([_program("rpmkeys"), "--dbpath", database, "--checksig", package])
    if checked.strip() != f"{package}: digests signatures OK":
        raise BuildError("the signed rpm does not verify against the certificate")
    # the certificate holds several signing subkeys: require the one that was asked for
    shown = _run(
        [_program("rpm"), "-qp", "--nosignature", "--qf", "%{RSAHEADER:pgpsig}", package]
    ).strip()
    if not shown.endswith(f"Key ID {fingerprint[-16:].lower()}"):
        raise BuildError("the signed rpm carries a signature by another key")


def _write_output(packages: Sequence[tuple[Path, str]], output: Path) -> list[Path]:
    """Copy every package under its own name and its fixed name, all staged before any rename.

    A copy that fails leaves no staged file behind, and no directory this run created. The renames
    that follow are within one directory.
    """
    created = not output.exists()
    staged: list[tuple[Path, Path]] = []
    try:
        output.mkdir(parents=True, exist_ok=True)
        for built, fixed in packages:
            for name in (built.name, fixed):
                temporary = output / f".{name}.part"
                staged.append((temporary, output / name))
                shutil.copyfile(built, temporary)
                temporary.chmod(0o644)
        for temporary, destination in staged:
            temporary.replace(destination)
    except OSError as error:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
        if created:
            shutil.rmtree(output, ignore_errors=True)
        raise BuildError(f"cannot write the output: {error.strerror or 'I/O error'}") from None
    return [destination for _, destination in staged]


def build(arguments: argparse.Namespace) -> list[Path]:
    gpg = _program("gpg")
    key_file: Path = arguments.key
    repo = [item.upper() for item in arguments.repo_subkey]
    rpm = [item.upper() for item in arguments.rpm_subkey]
    fingerprint = arguments.fingerprint.upper()
    for item in (fingerprint, *repo, *rpm):
        if not FINGERPRINT.fullmatch(item):
            raise BuildError("a fingerprint must be 40 hexadecimal digits")
    if not VERSION.fullmatch(arguments.version):
        raise BuildError("the version must look like 2026.1")
    if not MAINTAINER.fullmatch(arguments.maintainer):
        raise BuildError("the maintainer must look like: Name <address>")
    if arguments.source_date_epoch < 0:
        raise BuildError("--source-date-epoch must not be negative")
    if arguments.unsigned == bool(arguments.sign_home or arguments.sign_key):
        raise BuildError("give either --sign-home with --sign-key, or --unsigned")
    if bool(arguments.sign_home) != bool(arguments.sign_key):
        raise BuildError("--sign-home and --sign-key go together")
    if arguments.sign_key and arguments.sign_key.upper() not in rpm:
        raise BuildError("--sign-key must be one of the --rpm-subkey fingerprints")
    output: Path = arguments.output
    work = Path(tempfile.mkdtemp(prefix="kr-"))
    try:
        work.chmod(0o700)
        home = work / "gnupg"
        home.mkdir(mode=0o700)
        cert = inspect(gpg, home, key_file)
        check(cert, fingerprint=fingerprint, repo=repo, rpm=rpm)
        apt_key = export(gpg, home, key_file, cert=cert, keep=repo, armor=False)
        rpm_key = export(gpg, home, key_file, cert=cert, keep=[*repo, *rpm], armor=True)
        built_dir = work / "out"
        built_dir.mkdir()
        epoch: int = arguments.source_date_epoch
        deb = build_deb(
            work,
            apt_key,
            version=arguments.version,
            maintainer=arguments.maintainer,
            epoch=epoch,
            output=built_dir,
        )
        package = build_rpm(
            work,
            rpm_key,
            version=arguments.version,
            maintainer=arguments.maintainer,
            epoch=epoch,
            output=built_dir,
        )
        if arguments.sign_home:
            certificate = work / "certificate.asc"
            certificate.write_bytes(rpm_key)
            sign_rpm(
                package,
                home=arguments.sign_home,
                fingerprint=arguments.sign_key.upper(),
                certificate=certificate,
                work=work,
            )
        return _write_output(((deb, f"{DEB_NAME}.deb"), (package, f"{RPM_NAME}.rpm")), output)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_keyring.py", description=__doc__.split("\n")[0])
    parser.add_argument("--key", type=Path, required=True, help="the public certificate")
    parser.add_argument("--fingerprint", required=True, help="the primary key fingerprint")
    parser.add_argument("--repo-subkey", action="append", default=[], metavar="FPR")
    parser.add_argument("--rpm-subkey", action="append", default=[], metavar="FPR")
    parser.add_argument("--version", required=True)
    parser.add_argument("--maintainer", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sign-home", type=Path)
    parser.add_argument("--sign-key")
    parser.add_argument("--unsigned", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        written = build(arguments)
    except BuildError as error:
        print(f"failed: {error}", file=sys.stderr)
        return 1
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
