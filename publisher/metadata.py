# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Build the unsigned APT and RPM metadata for the admitted packages.

The standard tools do the work: `apt-ftparchive` writes the `Packages` indexes, the `Release`
file and the by-hash copies, and `createrepo_c` writes the `repodata`. This module only stages
what they read, runs them as argument arrays, and then checks their output against the admitted
records by exact set, so a package that a tool silently drops, adds or changes fails the build.

Layout of the result (the served tree; signing and publishing happen later):
  dists/stable/Release and dists/stable/main/binary-<arch>/Packages{,.gz,.xz}, plus by-hash
  rpm/<php>/<basearch>/repodata/...
It never holds a package: the VPS serves metadata and redirects every download. The packages are
only linked into a scratch directory, because the tools read files, and that directory is
removed afterwards. The apt `Filename:` is `pool/<product>/<tag>/<file>`, served at
`/apt/pool/...`; the rpm location is `../../../pool/...`, which a client at
`/rpm/<php>/<basearch>/` resolves to `/pool/...` (measured on EL8, EL9, EL10 and Fedora 44).
`Date` and `Valid-Until` come from the system clock, `Valid-Until` being `VALID_SECONDS` later.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import lzma
import os
import re
import shutil
import stat
import tempfile
import time
import zlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Literal

from publisher import config, feed, files, net
from publisher.admit import FINAL_ONLY, AdmittedPackage, Kind, ProductState, kind_of, tag_order
from publisher.cache import Cache, DownloadError
from publisher.feed import Asset
from publisher.tools import Result, Tools, run
from publisher.verify import RPM_ARCHITECTURES

Compression = Literal["none", "gz", "xz"]

SUITE: Final = "stable"
COMPONENT: Final = "main"
ORIGIN: Final = "Fojle Rabbi (Rabib)"
LABEL: Final = "Fojle Rabbi PHP extensions"
DESCRIPTION: Final = "PHP extensions by Fojle Rabbi (Rabib)"
VALID_SECONDS: Final = 14 * 24 * 3600
MAX_CLOCK_SKEW_SECONDS: Final = 3600
PUBLISHED_MODE: Final = 0o644
PUBLISHED_DIRECTORY_MODE: Final = 0o755
APT_TIMEOUT_SECONDS: Final = 300.0
RPM_TIMEOUT_SECONDS: Final = 600.0
RPM_TREE_DEPTH: Final = 3
LOCATION_PREFIX: Final = "../" * RPM_TREE_DEPTH
MAX_INDEX_BYTES: Final = 1024 * 1024 * 1024
READ_CHUNK_BYTES: Final = 1024 * 1024
RELEASE_DATE_FORMAT: Final = "%a, %d %b %Y %H:%M:%S UTC"
INDEX_NAMES: Final = ("Packages", "Packages.gz", "Packages.xz")
BY_HASH_ALGORITHMS: Final = {"SHA256": 64, "SHA512": 128}  # name -> hex digits
SAFE_PATH: Final = re.compile(r"[A-Za-z0-9_./-]+")
SHA256: Final = re.compile(r"[0-9a-f]{64}")
PACKAGE_SUFFIX: Final = {"deb": ".deb", "rpm": ".rpm"}
REPOMD_DATA: Final = re.compile(r'<data type="([a-z_]+)">(.*?)</data>', re.DOTALL)
RPM_PACKAGE: Final = re.compile(r'<package type="rpm">(.*?)</package>', re.DOTALL)


class MetadataError(Exception):
    """The metadata cannot be built, or a tool's output does not match the admitted records."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Entry:
    """One admitted package to list: where it belongs and what was verified."""

    repo: str
    tag: str
    package: AdmittedPackage

    @property
    def pool_path(self) -> str:
        return f"pool/{self.repo}/{self.tag}/{self.package.name}"


@dataclass(frozen=True, slots=True, kw_only=True)
class Built:
    entries: int
    apt_architectures: tuple[str, ...]
    rpm_trees: tuple[str, ...]


def select(
    products: config.ProductList,
    exclusions: config.ExclusionList,
    states: Mapping[str, ProductState],
    *,
    kinds: frozenset[Kind] = FINAL_ONLY,
) -> tuple[Entry, ...]:
    """List what the repository serves: admitted, not excluded, and still declared.

    A declared product without a loaded state is an error, never an empty list, so a state that
    failed to load cannot publish a repository that silently lacks the product.
    """
    entries: list[Entry] = []
    for product in products.products:
        state = states.get(product.repo)
        if state is None:
            raise MetadataError(f"no state was loaded for {product.repo}")
        excluded = set(product.exclude) | {
            item.tag for item in exclusions.exclusions if item.product == product.repo
        }
        for tag in sorted(state.admitted, key=tag_order):
            if tag in excluded or kind_of(tag) not in kinds:
                continue
            for package in state.admitted[tag].packages:
                if package.php in product.php and package.arch in product.arch:
                    entries.append(Entry(repo=product.repo, tag=tag, package=package))
    return tuple(entries)


def _check_entry(entry: Entry) -> None:
    package = entry.package
    if (
        not config.REPO_NAME.fullmatch(entry.repo)
        or ".." in entry.repo
        or not config.RELEASE_TAG.fullmatch(entry.tag)
        or not feed.ASSET_NAME.fullmatch(package.name)
        or ".." in package.name
        or package.kind not in PACKAGE_SUFFIX
        or not package.name.endswith(PACKAGE_SUFFIX[package.kind])
        or package.php not in config.PHP_VERSIONS
        or package.arch not in config.ARCHITECTURES
        or not SHA256.fullmatch(package.sha256)
        or package.size < 0
    ):
        raise MetadataError(f"the admitted record of {net.safe(package.name)} is not valid")


def _require_directory(path: Path, *, empty: bool) -> None:
    if not path.is_absolute():
        raise MetadataError(f"{path}: must be an absolute path")
    try:
        info = path.lstat()
        listing = list(path.iterdir()) if empty else []
    except OSError as error:
        raise MetadataError(f"{path}: cannot inspect: {error.strerror or error}") from error
    if path.is_symlink() or not path.is_dir() or info.st_uid != os.geteuid():
        raise MetadataError(f"{path}: must be a directory owned by the current user")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise MetadataError(f"{path}: must not be writable by others")
    if listing:
        raise MetadataError(f"{path}: must be empty")


def _run(args: Sequence[str | Path], *, home: Path, timeout: float, what: str) -> Result:
    result = run(args, home=home, timeout=timeout)
    if result.code != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise MetadataError(f"{what} failed: {net.safe(detail)}")
    return result


def _fetch(entries: Sequence[Entry], cache: Cache) -> dict[Entry, Path]:
    """Return the cached file of every entry, downloading again what the cache lacks.

    The bytes are checked against the digest recorded at admission, so a package fetched now is
    exactly the one that was verified.
    """
    paths: dict[Entry, Path] = {}
    for entry in entries:
        package = entry.package
        asset = Asset(
            name=package.name,
            size=package.size,
            digest=f"sha256:{package.sha256}",
            url=feed.download_url(entry.repo, entry.tag, package.name),
        )
        try:
            paths[entry] = cache.obtain(asset)
        except DownloadError as error:
            raise MetadataError(f"cannot fetch {net.safe(package.name)}: {error}") from error
    return paths


def _link(root: Path, entries: Sequence[Entry], paths: Mapping[Entry, Path]) -> None:
    """Make `root/pool/<product>/<tag>/<file>` link to each cached file."""
    for entry in entries:
        destination = root / entry.pool_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(paths[entry])


@contextlib.contextmanager
def _open(path: Path, compression: Compression) -> Iterator[io.BufferedIOBase]:
    if compression == "gz":
        with gzip.open(path, "rb") as compressed:
            yield compressed
    elif compression == "xz":
        with lzma.open(path, "rb") as compressed_xz:
            yield compressed_xz
    else:
        with path.open("rb") as plain:
            yield plain


def _digest(path: Path, compression: Compression = "none", *, algorithm: str = "SHA256") -> str:
    """Hex digest of a file, or of its decompressed content, reading a bounded amount."""
    digest = hashlib.new(algorithm.lower())
    total = 0
    try:
        with _open(path, compression) as handle:
            while chunk := handle.read(READ_CHUNK_BYTES):
                total += len(chunk)
                if total > MAX_INDEX_BYTES:
                    raise MetadataError(f"{path.name}: larger than allowed")
                digest.update(chunk)
    except (OSError, EOFError, lzma.LZMAError, zlib.error) as error:
        raise MetadataError(f"{path.name}: cannot be read: {error}") from error
    return digest.hexdigest()


def _text(path: Path, compression: Compression = "none") -> str:
    try:
        with _open(path, compression) as handle:
            raw = handle.read(MAX_INDEX_BYTES + 1)
    except (OSError, EOFError, lzma.LZMAError, zlib.error) as error:
        raise MetadataError(f"{path.name}: cannot be read: {error}") from error
    if len(raw) > MAX_INDEX_BYTES:
        raise MetadataError(f"{path.name}: larger than allowed")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MetadataError(f"{path.name}: is not valid UTF-8") from error


def _stanzas(text: str) -> Iterator[dict[str, str]]:
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.split("\n"):
            if line[:1] in (" ", "\t") or not line:
                continue
            key, _, value = line.partition(": ")
            fields.setdefault(key, value)
        if fields:
            yield fields


def _generate_config(stage: Path, arch: str) -> str:
    if not SAFE_PATH.fullmatch(str(stage)):
        raise MetadataError(f"{stage}: the working path has characters the tool cannot take")
    index = f"dists/{SUITE}/{COMPONENT}/binary-{arch}/Packages"
    return (
        f'Dir {{ ArchiveDir "{stage}"; }};\n'
        'Default { Packages::Compress ". gzip xz"; };\n'
        f'BinDirectory "pool" {{ Packages "{index}"; }};\n'
    )


def _check_packages(index_dir: Path, wanted: Sequence[Entry]) -> None:
    """The index must list exactly the wanted packages, with the admitted digest and size."""
    plain = index_dir / "Packages"
    if {path.name for path in index_dir.iterdir()} != set(INDEX_NAMES) or any(
        path.is_symlink() or not path.is_file() for path in index_dir.iterdir()
    ):
        raise MetadataError(f"{index_dir.name}: must hold exactly the three indexes")
    expected = {(e.pool_path, e.package.sha256, e.package.size) for e in wanted}
    found: set[tuple[str, str, int]] = set()
    count = 0
    for fields in _stanzas(_text(plain)):
        count += 1
        try:
            found.add((fields["Filename"], fields["SHA256"], int(fields["Size"])))
        except (KeyError, ValueError) as error:
            raise MetadataError(f"{plain.name}: a package entry is incomplete") from error
    if count != len(found) or found != expected:
        raise MetadataError(f"{plain.parent.name}: Packages does not match the admitted packages")
    reference = _digest(plain)
    if (
        _digest(index_dir / "Packages.gz", "gz") != reference
        or _digest(index_dir / "Packages.xz", "xz") != reference
    ):
        raise MetadataError(f"{plain.parent.name}: compressed indexes differ from Packages")


def parse_release(
    text: str,
) -> tuple[dict[str, str], dict[str, dict[str, tuple[str, int]]]]:
    """Return the fields and, per by-hash algorithm (SHA256, SHA512), name -> (digest, size)."""
    fields: dict[str, str] = {}
    hashes: dict[str, dict[str, tuple[str, int]]] = {name: {} for name in BY_HASH_ALGORITHMS}
    section = ""
    for line in text.split("\n"):
        if line[:1] == " " and section in BY_HASH_ALGORITHMS:
            parts = line.split()
            if (
                len(parts) != 3
                or not re.fullmatch(f"[0-9a-f]{{{BY_HASH_ALGORITHMS[section]}}}", parts[0])
                or not parts[1].isdigit()
            ):
                raise MetadataError(f"Release has a malformed {section} line")
            hashes[section][parts[2]] = (parts[0], int(parts[1]))
        elif line and line[:1] != " ":
            key, _, value = line.partition(":")
            section = key if key in BY_HASH_ALGORITHMS else ""
            fields[key] = value.strip()
    return fields, hashes


def _check_release(dists: Path, architectures: Sequence[str]) -> None:
    fields, hashes = parse_release(_text(dists / "Release"))
    expected_fields = {
        "Origin": ORIGIN,
        "Label": LABEL,
        "Suite": SUITE,
        "Codename": SUITE,
        "Description": DESCRIPTION,
        "Architectures": " ".join(architectures),
        "Components": COMPONENT,
        "Acquire-By-Hash": "yes",
    }
    for key, value in expected_fields.items():
        if fields.get(key) != value:
            raise MetadataError(f"Release field {key} is not {value!r}")
    try:
        issued = datetime.strptime(fields["Date"], RELEASE_DATE_FORMAT)
        until = datetime.strptime(fields["Valid-Until"], RELEASE_DATE_FORMAT)
    except (KeyError, ValueError) as error:
        raise MetadataError("Release lacks a readable Date or Valid-Until") from error
    if abs(time.time() - issued.replace(tzinfo=timezone.utc).timestamp()) > MAX_CLOCK_SKEW_SECONDS:
        raise MetadataError("Release Date is not near the clock")
    if (until - issued).total_seconds() != VALID_SECONDS:
        raise MetadataError("Release Valid-Until is not Date plus the validity period")
    names = {f"{COMPONENT}/binary-{arch}/{name}" for arch in architectures for name in INDEX_NAMES}
    # apt asks for the strongest hash Release lists (SHA512), so every by-hash algorithm counts.
    for algorithm, listed in hashes.items():
        if set(listed) != names:
            raise MetadataError(f"Release does not list exactly the index files under {algorithm}")
        for name, (expected, size) in listed.items():
            path = dists / name
            by_hash = path.parent / "by-hash" / algorithm / expected
            if (
                _digest(path, algorithm=algorithm) != expected
                or path.stat().st_size != size
                or not by_hash.is_file()
                or _digest(by_hash, algorithm=algorithm) != expected
            ):
                raise MetadataError(
                    f"Release entry {name} does not match the file or its {algorithm} by-hash copy"
                )


def _build_apt(
    entries: Sequence[Entry],
    paths: Mapping[Entry, Path],
    tools: Tools,
    target: Path,
    staging: Path,
) -> tuple[str, ...]:
    architectures = tuple(sorted(config.ARCHITECTURES))
    dists = target / "dists" / SUITE
    for arch in architectures:
        stage = staging / "apt" / arch
        index_dir = stage / "dists" / SUITE / COMPONENT / f"binary-{arch}"
        index_dir.mkdir(parents=True)
        wanted = [e for e in entries if e.package.kind == "deb" and e.package.arch == arch]
        (stage / "pool").mkdir()
        _link(stage, wanted, paths)
        configuration = staging / f"generate-{arch}.conf"
        configuration.write_text(_generate_config(stage, arch), encoding="utf-8")
        _run(
            [tools.apt_ftparchive, "generate", configuration],
            home=staging,
            timeout=APT_TIMEOUT_SECONDS,
            what="apt-ftparchive generate",
        )
        _check_packages(index_dir, wanted)
        destination = dists / COMPONENT / f"binary-{arch}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(index_dir, destination, symlinks=True)
    settings = {
        "APT::FTPArchive::DoByHash": "1",
        "APT::FTPArchive::Release::Origin": ORIGIN,
        "APT::FTPArchive::Release::Label": LABEL,
        "APT::FTPArchive::Release::Suite": SUITE,
        "APT::FTPArchive::Release::Codename": SUITE,
        "APT::FTPArchive::Release::Description": DESCRIPTION,
        "APT::FTPArchive::Release::Architectures": " ".join(architectures),
        "APT::FTPArchive::Release::Components": COMPONENT,
        "APT::FTPArchive::Release::Acquire-By-Hash": "yes",
        "APT::FTPArchive::Release::ValidTime": str(VALID_SECONDS),
        "APT::FTPArchive::Release::NumericTimezone": "0",
    }
    arguments: list[str | Path] = [tools.apt_ftparchive]
    for key, value in settings.items():
        arguments += ["-o", f"{key}={value}"]
    arguments += ["release", dists]
    result = _run(
        arguments, home=staging, timeout=APT_TIMEOUT_SECONDS, what="apt-ftparchive release"
    )
    try:
        files.write_atomic(dists / "Release", result.stdout.encode("utf-8"), mode=PUBLISHED_MODE)
    except OSError as error:
        raise MetadataError(f"cannot write Release: {error.strerror or error}") from error
    _check_release(dists, architectures)
    return architectures


def _check_repodata(repodata: Path, wanted: Sequence[Entry]) -> None:
    """repomd.xml must describe exactly the files present, and primary.xml the wanted packages."""
    repomd = _text(repodata / "repomd.xml")
    listed: dict[str, Path] = {}
    for kind, body in REPOMD_DATA.findall(repomd):
        location = re.search(r'<location href="repodata/([^"/]+)"/>', body)
        checksum = re.search(r'<checksum type="sha256">([0-9a-f]{64})</checksum>', body)
        opened = re.search(r'<open-checksum type="sha256">([0-9a-f]{64})</open-checksum>', body)
        if location is None or checksum is None or opened is None:
            raise MetadataError(f"repomd.xml entry {kind} is incomplete")
        path = repodata / location.group(1)
        if _digest(path) != checksum.group(1):
            raise MetadataError(f"repomd.xml checksum of {kind} does not match the file")
        if _digest(path, "gz") != opened.group(1):
            raise MetadataError(f"repomd.xml open-checksum of {kind} does not match the file")
        listed[kind] = path
    if not {"primary", "filelists", "other"} <= listed.keys():
        raise MetadataError("repomd.xml lacks primary, filelists or other")
    present = {entry.name for entry in repodata.iterdir()}
    if present != {"repomd.xml", *(path.name for path in listed.values())}:
        raise MetadataError("repodata holds files that repomd.xml does not list")
    primary = _text(listed["primary"], "gz")
    declared = re.search(r'<metadata[^>]* packages="([0-9]+)"', primary)
    found: set[tuple[str, str, int]] = set()
    blocks = RPM_PACKAGE.findall(primary)
    for block in blocks:
        checksum = re.search(
            r'<checksum type="sha256" pkgid="YES">([0-9a-f]{64})</checksum>', block
        )
        size = re.search(r'<size package="([0-9]+)"', block)
        location = re.search(r'<location href="([^"]+)"/>', block)
        if checksum is None or size is None or location is None:
            raise MetadataError("primary.xml has an incomplete package entry")
        found.add((location.group(1), checksum.group(1), int(size.group(1))))
    expected = {(LOCATION_PREFIX + e.pool_path, e.package.sha256, e.package.size) for e in wanted}
    if (
        declared is None
        or int(declared.group(1)) != len(wanted)
        or len(blocks) != len(found)
        or found != expected
    ):
        raise MetadataError(f"{repodata.parent.name}: primary.xml does not match the packages")


def _build_rpm(
    entries: Sequence[Entry],
    paths: Mapping[Entry, Path],
    tools: Tools,
    target: Path,
    staging: Path,
) -> tuple[str, ...]:
    trees: list[str] = []
    for php in sorted(config.PHP_VERSIONS):
        for arch in sorted(config.ARCHITECTURES):
            basearch = RPM_ARCHITECTURES[arch]
            stage = staging / "rpm" / php / basearch
            stage.mkdir(parents=True)
            wanted = [
                e
                for e in entries
                if e.package.kind == "rpm" and e.package.php == php and e.package.arch == arch
            ]
            _link(stage, wanted, paths)
            _run(
                [
                    tools.createrepo_c,
                    "--quiet",
                    "--no-database",
                    "--location-prefix",
                    LOCATION_PREFIX,
                    stage,
                ],
                home=staging,
                timeout=RPM_TIMEOUT_SECONDS,
                what="createrepo_c",
            )
            _check_repodata(stage / "repodata", wanted)
            destination = target / "rpm" / php / basearch
            destination.mkdir(parents=True)
            shutil.copytree(stage / "repodata", destination / "repodata", symlinks=True)
            trees.append(f"rpm/{php}/{basearch}")
    return tuple(trees)


def _require_no_package_bytes(target: Path) -> None:
    """The tree must hold metadata only: no package and no link that could expose the cache."""
    for path in target.rglob("*"):
        if path.is_symlink() or path.suffix in (".deb", ".rpm"):
            raise MetadataError(
                f"{path.relative_to(target)}: the tree must hold no package or link"
            )


def _normalize_modes(target: Path) -> None:
    """Make the tree readable by the web server whatever umask the tools ran under."""
    try:
        for path in [target, *target.rglob("*")]:
            path.chmod(PUBLISHED_DIRECTORY_MODE if path.is_dir() else PUBLISHED_MODE)
    except OSError as error:
        raise MetadataError(f"cannot set the file modes: {error.strerror or error}") from error


def build(
    entries: Sequence[Entry],
    *,
    cache: Cache,
    tools: Tools,
    target: Path,
    work: Path,
) -> Built:
    """Write the unsigned metadata of `entries` into the empty directory `target`.

    On failure `target` may hold a partial tree; the caller discards it. Tool faults (missing
    program, timeout, flood) raise ToolError and a mismatch raises MetadataError.
    """
    _require_directory(target, empty=True)
    _require_directory(work, empty=False)
    for entry in entries:
        _check_entry(entry)
    if len({(e.repo, e.pool_path) for e in entries}) != len(entries):
        raise MetadataError("the same package is listed twice")
    staging = Path(tempfile.mkdtemp(prefix="metadata-", dir=work))
    try:
        paths = _fetch(entries, cache)
        architectures = _build_apt(entries, paths, tools, target, staging)
        trees = _build_rpm(entries, paths, tools, target, staging)
        _require_no_package_bytes(target)
        _normalize_modes(target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return Built(entries=len(entries), apt_architectures=architectures, rpm_trees=trees)
