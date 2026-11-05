# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Decide whether one release of a declared product may be admitted.

Authority, in order:
  1. the cosign bundle of each package, checked offline against a Sigstore trusted-root file,
     pinned to the product's release workflow at the exact tag and to the GitHub OIDC issuer,
     with the transparency log left on, is the trust root;
  2. `SHA256SUMS` is unsigned and proves integrity only;
  3. an rpm must carry a signature by a valid signing key of the pinned RPM key; the key's own
     expiry and revocation are checked here, because rpm itself accepts a revoked key.

A package is parsed (dpkg-deb, rpm) only after cosign has accepted its bytes. The expected
cells (PHP version x architecture x package layout) come from the product declaration and the
tag, so a release that lacks a package or a bundle, or carries another version, is rejected.
Rejected means this release only; ToolError (tools.py) means the run cannot continue.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final, Literal

from publisher import config, net
from publisher.cache import Cache, CacheDirectoryError, require_private_directory, sync_directory
from publisher.feed import GITHUB_OWNER, Asset, Release
from publisher.tools import Result, ToolError, ToolOutputLimit, Tools, ToolTimeout, run

OIDC_ISSUER: Final = "https://token.actions.githubusercontent.com"
WORKFLOW_PATH: Final = ".github/workflows/release.yml"
SUMS_NAME: Final = "SHA256SUMS"
BUNDLE_SUFFIX: Final = ".bundle"
MAX_SMALL_FILE_BYTES: Final = 1024 * 1024
MAX_KEY_FILE_BYTES: Final = 64 * 1024
COSIGN_TIMEOUT_SECONDS: Final = 120.0
PACKAGE_TOOL_TIMEOUT_SECONDS: Final = 60.0
INITIALIZE_TIMEOUT_SECONDS: Final = 120.0
TRUST_ROOT_MAX_AGE_SECONDS: Final = 7 * 24 * 3600.0
TRUSTED_ROOT_MEDIA_TYPE: Final = "application/vnd.dev.sigstore.trustedroot"
TUF_DIRECTORY: Final = "tuf"
TRUSTED_ROOT_FILE: Final = "trusted_root.json"
# Where `cosign initialize` leaves the file inside TUF_ROOT; a cosign internal, re-check on a bump.
TRUSTED_ROOT_TARGET: Final = Path("tuf-repo-cdn.sigstore.dev/targets/trusted_root.json")

DEB_ARCHITECTURES: Final = {"amd64": "amd64", "arm64": "arm64"}
RPM_ARCHITECTURES: Final = {"amd64": "x86_64", "arm64": "aarch64"}
SUMS_LINE: Final = re.compile(r"([0-9a-f]{64})  (?:\./)?([A-Za-z0-9][A-Za-z0-9._-]{0,127})")
RPM_SIGNATURE: Final = re.compile(r"RSA/SHA(?:256|384|512), [^\n]+, Key ID ([0-9a-f]{16})")
VALID_KEY_STATES: Final = frozenset({"-", "u", "f", "m"})

PackageKind = Literal["deb", "rpm"]
Layout = Literal["deb", "base", "versioned"]


class VerifyError(Exception):
    """Base of the verification errors."""


class Rejected(VerifyError):
    """This release breaks a verification rule; other releases are unaffected."""


class Unsupported(VerifyError):
    """The product declares something this publisher cannot verify yet."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Package:
    """One package the release must contain, with the metadata it must declare."""

    name: str
    kind: PackageKind
    layout: Layout
    php: str
    arch: str
    package: str
    version: str
    release: str
    machine: str


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedPackage:
    package: Package
    path: Path


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedRoot:
    """The trusted-root file to verify with, and whether this run fetched it fresh."""

    path: Path
    age_seconds: float
    refreshed: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class Verified:
    tag: str
    packages: tuple[VerifiedPackage, ...]


def identity(repo: str, tag: str) -> str:
    """The exact certificate identity of `repo`'s release workflow at `tag`."""
    return f"https://github.com/{GITHUB_OWNER}/{repo}/{WORKFLOW_PATH}@refs/tags/{tag}"


def expected_packages(product: config.Product, tag: str) -> tuple[Package, ...]:
    """List every package a release of `product` at `tag` must carry (3 per PHP x arch cell)."""
    if "zts" in product.ts:
        raise Unsupported(f"{product.repo} declares zts; only nts can be verified")
    if not config.RELEASE_TAG.fullmatch(tag):
        raise Rejected(f"tag {net.safe(tag)} is not a release tag")
    base, _, suffix = tag[1:].partition("-")
    deb_version = f"{base}~{suffix}-1" if suffix else f"{base}-1"
    rpm_release = f"0.1.{suffix}" if suffix else "1"
    extension = product.extension
    packages: list[Package] = []
    for php in product.php:
        number = php.replace(".", "")
        for arch in product.arch:
            machine = RPM_ARCHITECTURES[arch]
            deb_arch = DEB_ARCHITECTURES[arch]
            packages.append(
                Package(
                    name=f"php{php}-{extension}_{deb_version.replace('~', '.')}_{deb_arch}.deb",
                    kind="deb",
                    layout="deb",
                    php=php,
                    arch=arch,
                    package=f"php{php}-{extension}",
                    version=deb_version,
                    release="",
                    machine=deb_arch,
                )
            )
            base_release = f"{rpm_release}.php{number}"
            base_package = f"php-{extension}"
            packages.append(
                Package(
                    name=f"{base_package}-{base}-{base_release}.{machine}.rpm",
                    kind="rpm",
                    layout="base",
                    php=php,
                    arch=arch,
                    package=base_package,
                    version=base,
                    release=base_release,
                    machine=machine,
                )
            )
            versioned_package = f"php{number}-php-{extension}"
            packages.append(
                Package(
                    name=f"{versioned_package}-{base}-{rpm_release}.{machine}.rpm",
                    kind="rpm",
                    layout="versioned",
                    php=php,
                    arch=arch,
                    package=versioned_package,
                    version=base,
                    release=rpm_release,
                    machine=machine,
                )
            )
    return tuple(packages)


def parse_sums(data: bytes) -> dict[str, str]:
    """Read `sha256sum` output: `<hex>  <name>` lines, each name once, a leading `./` dropped."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected(f"{SUMS_NAME} is not valid UTF-8") from error
    if not text.endswith("\n"):
        raise Rejected(f"{SUMS_NAME} is empty or does not end with a newline")
    sums: dict[str, str] = {}
    for number, line in enumerate(text[:-1].split("\n"), start=1):
        match = SUMS_LINE.fullmatch(line)
        if match is None or ".." in match.group(2):
            raise Rejected(f"{SUMS_NAME} line {number} is malformed")
        digest, name = match.groups()
        if name in sums:
            raise Rejected(f"{SUMS_NAME} lists {name} twice")
        sums[name] = digest
    return sums


def check_sums(
    sums: dict[str, str], assets: dict[str, Asset], packages: tuple[Package, ...]
) -> None:
    """Every listed file must exist, and every package must be listed with its known digest."""
    for name in sums:
        if name not in assets:
            raise Rejected(f"{SUMS_NAME} lists {name}, which the release does not have")
    for package in packages:
        listed = sums.get(package.name)
        if listed is None:
            raise Rejected(f"{SUMS_NAME} does not list {package.name}")
        if f"sha256:{listed}" != assets[package.name].digest:
            raise Rejected(f"{SUMS_NAME} disagrees with the release about {package.name}")


def check_signature(
    tools: Tools,
    *,
    blob: Path,
    bundle: Path,
    trusted_root: Path,
    expected_identity: str,
    name: str,
    home: Path,
) -> None:
    """Accept `blob` only if its cosign bundle proves `expected_identity` signed it."""
    arguments: list[str | Path] = [
        tools.cosign,
        "verify-blob",
        "--bundle",
        bundle,
        "--trusted-root",
        trusted_root,
        "--certificate-identity",
        expected_identity,
        "--certificate-oidc-issuer",
        OIDC_ISSUER,
        blob,
    ]
    try:
        result = run(arguments, home=home, timeout=COSIGN_TIMEOUT_SECONDS)
    except (ToolTimeout, ToolOutputLimit) as error:
        raise Rejected(f"the signature check of {name} failed: {error}") from error
    if result.code != 0 or "Verified OK" not in result.stderr + result.stdout:
        raise Rejected(f"{name} is not signed by the release workflow of this tag")


def read_trusted_root(path: Path) -> bytes:
    """Read a Sigstore trusted-root file, refusing anything else."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_SMALL_FILE_BYTES + 1)
        document = json.loads(raw)
    except (OSError, ValueError) as error:
        raise ToolError(f"{path}: trusted root cannot be read") from error
    media_type = document.get("mediaType") if isinstance(document, dict) else None
    if len(raw) > MAX_SMALL_FILE_BYTES or not (
        isinstance(media_type, str) and media_type.startswith(TRUSTED_ROOT_MEDIA_TYPE)
    ):
        raise ToolError(f"{path}: not a Sigstore trusted root")
    return raw


def _store_trusted_root(raw: bytes, target: Path, *, now: float) -> None:
    """Replace `target` atomically; its modification time records when it was fetched."""
    descriptor, name = tempfile.mkstemp(dir=target.parent, prefix="root-")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.utime(temporary, (now, now))
        temporary.replace(target)
        sync_directory(target.parent)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise ToolError(
            f"{target}: cannot store the trusted root: {error.strerror or error}"
        ) from error


def _require_private(path: Path) -> None:
    try:
        require_private_directory(path)
    except CacheDirectoryError as error:
        raise ToolError(str(error)) from error


def _prepare_trust_directory(directory: Path, *, now: float) -> Path:
    """Check the trust directory, create its TUF store and drop leftovers of a killed run."""
    _require_private(directory)
    tuf = directory / TUF_DIRECTORY
    try:
        tuf.mkdir(mode=0o700, exist_ok=True)
    except OSError as error:
        raise ToolError(f"{tuf}: cannot create: {error.strerror or error}") from error
    _require_private(tuf)
    try:
        for entry in directory.glob("root-*"):
            if entry.lstat().st_mtime < now - INITIALIZE_TIMEOUT_SECONDS:
                entry.unlink(missing_ok=True)
    except OSError as error:
        raise ToolError(f"{directory}: cannot clean up: {error.strerror or error}") from error
    return tuf


def _fetch_trusted_root(tools: Tools, directory: Path, tuf: Path, *, now: float) -> Path:
    """Run `cosign initialize` into the persistent TUF store and keep a validated copy."""
    try:
        # A file left by an earlier run must never pass for this run's fetch.
        (tuf / TRUSTED_ROOT_TARGET).unlink(missing_ok=True)
    except OSError as error:
        raise ToolError(
            f"{tuf}: cannot clear the old trusted root: {error.strerror or error}"
        ) from error
    result = run(
        [tools.cosign, "initialize"],
        home=directory,
        timeout=INITIALIZE_TIMEOUT_SECONDS,
        env={"TUF_ROOT": str(tuf)},
    )
    if result.code != 0:
        raise ToolError("cosign initialize failed")
    target = directory / TRUSTED_ROOT_FILE
    _store_trusted_root(read_trusted_root(tuf / TRUSTED_ROOT_TARGET), target, now=now)
    return target


def obtain_trusted_root(tools: Tools, directory: Path, *, now: float) -> TrustedRoot:
    """Refresh the Sigstore trusted root, or fall back to a copy at most seven days old.

    `directory` is private to the publisher and persistent, so the TUF client inside it can
    follow root rotations from the last root it trusted. A failed refresh is run-wide, not a
    verdict on any release: a recent copy is returned with `refreshed=False` for the caller to
    report, an older, missing or future-dated copy stops the run.
    """
    tuf = _prepare_trust_directory(directory, now=now)
    try:
        path = _fetch_trusted_root(tools, directory, tuf, now=now)
    except ToolError as error:
        reason = error
    else:
        return TrustedRoot(path=path, age_seconds=0.0, refreshed=True)
    copy = directory / TRUSTED_ROOT_FILE
    try:
        info = copy.lstat()
    except OSError:
        raise ToolError(f"no trusted root and the refresh failed: {reason}") from reason
    age = now - info.st_mtime
    if not stat.S_ISREG(info.st_mode) or age < 0 or age > TRUST_ROOT_MAX_AGE_SECONDS:
        raise ToolError(
            f"the trusted root is unusable and the refresh failed: {reason}"
        ) from reason
    read_trusted_root(copy)
    return TrustedRoot(path=copy, age_seconds=age, refreshed=False)


class Verifier:
    """Runs the checks with one private working area; use it as a context manager."""

    def __init__(self, tools: Tools, *, rpm_key: Path, trusted_root: Path, work: Path) -> None:
        if not work.is_absolute() or not work.is_dir():
            raise ToolError(f"{work}: work directory must be an existing absolute path")
        self._tools = tools
        read_trusted_root(trusted_root)
        self._trusted_root = trusted_root
        self._home = Path(tempfile.mkdtemp(prefix="verify-", dir=work))
        try:
            self._rpm_db = self._home / "rpmdb"
            self._rpm_db.mkdir(mode=0o700)
            self._key_ids = self._load_rpm_key(rpm_key)
        except BaseException:
            shutil.rmtree(self._home, ignore_errors=True)
            raise

    def __enter__(self) -> Verifier:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        shutil.rmtree(self._home, ignore_errors=True)

    @property
    def key_ids(self) -> frozenset[str]:
        """The long key ids of the valid signing keys that rpm signatures are held to."""
        return self._key_ids

    def _load_rpm_key(self, path: Path) -> frozenset[str]:
        """Pin the signing keys of the RPM key file, refusing an expired or revoked key."""
        try:
            with path.open("rb") as handle:
                size = len(handle.read(MAX_KEY_FILE_BYTES + 1))
        except OSError as error:
            raise ToolError(f"{path}: rpm key cannot be read") from error
        if size > MAX_KEY_FILE_BYTES:
            raise ToolError(f"{path}: rpm key file is too large")
        gnupg = self._home / "gnupg"
        gnupg.mkdir(mode=0o700)
        arguments: list[str | Path] = [self._tools.gpg, "--batch", "--no-tty", "--with-colons"]
        arguments += ["--fixed-list-mode", "--show-keys", path]
        listing = run(arguments, home=self._home, env={"GNUPGHOME": str(gnupg)})
        if listing.code != 0:
            raise ToolError(f"{path}: gpg cannot read the rpm key")
        records = [line.split(":") for line in listing.stdout.splitlines()]
        primaries = [record for record in records if record[0] == "pub"]
        if len(primaries) != 1 or len(primaries[0]) < 12:
            raise ToolError(f"{path}: expected exactly one primary rpm key")
        if primaries[0][1] not in VALID_KEY_STATES:
            raise ToolError(f"{path}: the primary rpm key is expired or revoked")
        signing = [
            record
            for record in records
            if record[0] in ("pub", "sub")
            and len(record) >= 12
            and "s" in record[11]
            and record[1] in VALID_KEY_STATES
        ]
        ids = frozenset(record[4].lower() for record in signing)
        if not ids or not all(re.fullmatch(r"[0-9a-f]{16}", key) for key in ids):
            raise ToolError(f"{path}: no valid signing key in the rpm key file")
        imported = run(
            [self._tools.rpmkeys, "--dbpath", self._rpm_db, "--import", path],
            home=self._home,
        )
        if imported.code != 0:
            raise ToolError(f"{path}: rpmkeys cannot import the rpm key")
        return ids

    def verify(self, product: config.Product, release: Release, cache: Cache) -> Verified:
        """Admit-check `release`: returns its verified packages or raises Rejected/Unsupported."""
        wanted = expected_packages(product, release.tag)
        assets = {asset.name: asset for asset in release.assets}
        for name in (
            SUMS_NAME,
            *(p.name for p in wanted),
            *(p.name + BUNDLE_SUFFIX for p in wanted),
        ):
            if name not in assets:
                raise Rejected(f"release lacks {name}")
        for name in (SUMS_NAME, *(p.name + BUNDLE_SUFFIX for p in wanted)):
            if assets[name].size > MAX_SMALL_FILE_BYTES:
                raise Rejected(f"{name} is larger than allowed")
        wanted_identity = identity(product.repo, release.tag)
        verified: list[VerifiedPackage] = []
        for package in wanted:
            path = cache.obtain(assets[package.name])
            bundle = cache.obtain(assets[package.name + BUNDLE_SUFFIX])
            check_signature(
                self._tools,
                blob=path,
                bundle=bundle,
                trusted_root=self._trusted_root,
                expected_identity=wanted_identity,
                name=package.name,
                home=self._home,
            )
            verified.append(VerifiedPackage(package=package, path=path))
        sums = parse_sums(cache.obtain(assets[SUMS_NAME]).read_bytes())
        check_sums(sums, assets, wanted)
        for item in verified:
            if item.package.kind == "deb":
                self._check_deb(item)
            else:
                self._check_rpm(item)
        return Verified(tag=release.tag, packages=tuple(verified))

    def _package_tool(self, arguments: list[str | Path], name: str) -> Result:
        """Run a program on a package; a hang or flood is that release's fault, not the run's."""
        try:
            return run(arguments, home=self._home, timeout=PACKAGE_TOOL_TIMEOUT_SECONDS)
        except (ToolTimeout, ToolOutputLimit) as error:
            raise Rejected(f"{name} could not be inspected: {error}") from error

    def _check_deb(self, item: VerifiedPackage) -> None:
        package = item.package
        result = self._package_tool(
            [self._tools.dpkg_deb, "--field", item.path, "Package", "Version", "Architecture"],
            package.name,
        )
        fields = dict(line.split(": ", 1) for line in result.stdout.splitlines() if ": " in line)
        expected = {
            "Package": package.package,
            "Version": package.version,
            "Architecture": package.machine,
        }
        if result.code != 0 or fields != expected:
            raise Rejected(f"{package.name} does not declare the expected package metadata")

    def _check_rpm(self, item: VerifiedPackage) -> None:
        package = item.package
        base: list[str | Path] = [self._tools.rpm, "-qp", "--dbpath", self._rpm_db, "--nosignature"]
        format_fields = r"%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n%{EPOCHNUM}\n"
        fields = self._package_tool(
            [*base, "--nodigest", "--qf", format_fields, item.path], package.name
        )
        expected = [package.package, package.version, package.release, package.machine, "0"]
        if fields.code != 0 or fields.stdout.splitlines() != expected:
            raise Rejected(f"{package.name} does not declare the expected package metadata")
        signature = self._package_tool(
            [*base, "--qf", "%{RSAHEADER:pgpsig}", item.path], package.name
        )
        match = RPM_SIGNATURE.fullmatch(signature.stdout.strip())
        if signature.code != 0 or match is None or match.group(1) not in self._key_ids:
            raise Rejected(f"{package.name} is not signed by the pinned rpm key")
        checked = self._package_tool(
            [self._tools.rpmkeys, "--dbpath", self._rpm_db, "--checksig", item.path],
            package.name,
        )
        if checked.code != 0 or checked.stdout.strip() != f"{item.path}: digests signatures OK":
            raise Rejected(f"{package.name} fails the rpm signature check")
