# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import dataclasses
import hashlib
import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from pkgkit import Key, KeyState, build_deb, build_rpm, make_key, stop_agent

from publisher import tools, verify
from publisher.cache import Cache, Chunks, DownloadError
from publisher.config import Product
from publisher.feed import Asset, Release
from publisher.tools import ToolError, Tools
from publisher.verify import (
    Rejected,
    Unsupported,
    Verifier,
    check_signature,
    check_sums,
    expected_packages,
    identity,
    parse_sums,
)

SIGSTORE = Path(__file__).resolve().parents[1] / "fixtures" / "sigstore"
TRUSTED_ROOT = SIGSTORE / "trusted_root.json"
PROVENANCE = SIGSTORE / "usearch-php8.3-x86_64.provenance"
PROVENANCE_BUNDLE = SIGSTORE / "usearch-php8.3-x86_64.provenance.bundle"
REAL_IDENTITY = (
    "https://github.com/FojleRabbiRabib/usearch-php/.github/workflows/release.yml@refs/tags/v0.2.0"
)
PRODUCT = Product(
    repo="p-php", extension="p", php=("8.3",), arch=("amd64",), ts=("nts",), exclude=()
)
TAG = "v1.0.0"
DEB = "php8.3-p_1.0.0-1_amd64.deb"
BASE_RPM = "php-p-1.0.0-1.php83.x86_64.rpm"
VERSIONED_RPM = "php83-php-p-1.0.0-1.x86_64.rpm"
HEX = "a" * 64


@pytest.fixture(scope="module")
def real_tools() -> Tools:
    return Tools.locate(os.environ["PATH"])


@pytest.fixture(scope="module")
def keys(real_tools: Tools, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Key]]:
    root = tmp_path_factory.mktemp("keys")
    states: tuple[KeyState, ...] = ("valid", "valid", "expired", "primary-expired", "revoked")
    names = ("good", "other", "expired", "primary-expired", "revoked")
    made = {
        name: make_key(real_tools, root, name, state)
        for name, state in zip(names, states, strict=True)
    }
    yield made
    for key in made.values():
        stop_agent(key)


def _sums(files: dict[str, bytes]) -> bytes:
    lines = [
        f"{hashlib.sha256(data).hexdigest()}  ./{name}\n"
        for name, data in sorted(files.items())
        if not name.endswith((".bundle", "SHA256SUMS"))
    ]
    return "".join(lines).encode()


@pytest.fixture(scope="module")
def good_files(
    real_tools: Tools, keys: dict[str, Key], tmp_path_factory: pytest.TempPathFactory
) -> dict[str, bytes]:
    root = tmp_path_factory.mktemp("packages")
    files: dict[str, bytes] = {}
    for package in expected_packages(PRODUCT, TAG):
        if package.kind == "deb":
            files[package.name] = build_deb(
                real_tools,
                root,
                package=package.package,
                version=package.version,
                architecture=package.machine,
            )
        else:
            files[package.name] = build_rpm(
                root,
                name=package.package,
                version=package.version,
                release=package.release,
                arch=package.machine,
                key=keys["good"],
            )
        files[package.name + ".bundle"] = b"good"
    files["SHA256SUMS"] = _sums(files)
    return files


@pytest.fixture
def files(good_files: dict[str, bytes]) -> dict[str, bytes]:
    return dict(good_files)


def _fake_cosign(tmp_path: Path, tools: Tools) -> tuple[Tools, Path]:
    """A cosign stand-in: logs its arguments, accepts a bundle that says `good`."""
    log = tmp_path / "cosign.log"
    script = tmp_path / "cosign"
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" >> {log}\n'
        "env | sort >> " + str(log) + ".env\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--bundle" ]; then bundle="$2"; fi\n'
        "  shift\n"
        "done\n"
        'if [ "$(cat "$bundle")" = good ]; then echo "Verified OK" >&2; exit 0; fi\n'
        'echo "Error: no matching signatures" >&2\n'
        "exit 1\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return dataclasses.replace(tools, cosign=script), log


def _release(files: dict[str, bytes], tag: str = TAG) -> Release:
    assets = tuple(
        Asset(
            name=name,
            size=len(data),
            digest="sha256:" + hashlib.sha256(data).hexdigest(),
            url=f"https://github.com/FojleRabbiRabib/p-php/releases/download/{tag}/{name}",
        )
        for name, data in files.items()
    )
    return Release(tag=tag, kind="final", immutable=True, assets=assets)


class _Served:
    """Serves the current release files by asset name; `override` replaces what is sent."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.override: dict[str, bytes] = {}
        self.urls: list[str] = []

    def __call__(self, url: str, size: int) -> Chunks:
        self.urls.append(url)
        name = url.rsplit("/", 1)[-1]
        yield self.override.get(name, self.files[name])


class Run:
    """One verification of a built release; keeps what the tests want to inspect."""

    def __init__(
        self,
        tmp_path: Path,
        real_tools: Tools,
        keys: dict[str, Key],
        files: dict[str, bytes],
        *,
        key: str = "good",
        product: Product = PRODUCT,
    ) -> None:
        self.tools, self.log = _fake_cosign(tmp_path, real_tools)
        self.files = files
        self.product = product
        self.key = keys[key]
        self.served = _Served(files)
        root = tmp_path / "cache"
        root.mkdir(mode=0o700)
        self.cache = Cache(root, self.served)
        self.work = tmp_path / "work"
        self.work.mkdir(mode=0o700)

    def verifier(self) -> Verifier:
        return Verifier(
            self.tools, rpm_key=self.key.public, trusted_root=TRUSTED_ROOT, work=self.work
        )

    def verify(self, tag: str = TAG) -> verify.Verified:
        with self.verifier() as verifier:
            return verifier.verify(self.product, _release(self.files, tag), self.cache)


@pytest.fixture
def run(tmp_path: Path, real_tools: Tools, keys: dict[str, Key], files: dict[str, bytes]) -> Run:
    return Run(tmp_path, real_tools, keys, files)


# ---- expected packages ---------------------------------------------------------------------


def test_expected_names_for_a_final_release_match_the_producer_naming() -> None:
    product = Product(
        repo="usearch-php",
        extension="usearch",
        php=("8.3", "8.4"),
        arch=("amd64", "arm64"),
        ts=("nts",),
        exclude=(),
    )
    names = {package.name for package in expected_packages(product, "v0.3.0")}
    assert len(names) == 12
    assert {
        "php8.3-usearch_0.3.0-1_amd64.deb",
        "php8.4-usearch_0.3.0-1_arm64.deb",
        "php-usearch-0.3.0-1.php83.x86_64.rpm",
        "php-usearch-0.3.0-1.php84.aarch64.rpm",
        "php83-php-usearch-0.3.0-1.x86_64.rpm",
        "php84-php-usearch-0.3.0-1.aarch64.rpm",
    } <= names


def test_expected_names_for_a_prerelease_sort_below_the_final() -> None:
    product = dataclasses.replace(PRODUCT, extension="usearch")
    packages = {p.name: p for p in expected_packages(product, "v0.3.0-rc1")}
    deb = packages["php8.3-usearch_0.3.0.rc1-1_amd64.deb"]
    assert (deb.package, deb.version, deb.machine) == ("php8.3-usearch", "0.3.0~rc1-1", "amd64")
    base = packages["php-usearch-0.3.0-0.1.rc1.php83.x86_64.rpm"]
    assert (base.package, base.version, base.release) == ("php-usearch", "0.3.0", "0.1.rc1.php83")
    versioned = packages["php83-php-usearch-0.3.0-0.1.rc1.x86_64.rpm"]
    assert (versioned.package, versioned.release) == ("php83-php-usearch", "0.1.rc1")


def test_every_expected_name_is_a_valid_asset_name() -> None:
    for package in expected_packages(PRODUCT, "v1.2.3-rc9"):
        assert verify.SUMS_LINE.fullmatch(f"{HEX}  {package.name}")


def test_zts_is_unsupported() -> None:
    with pytest.raises(Unsupported, match="zts"):
        expected_packages(dataclasses.replace(PRODUCT, ts=("nts", "zts")), TAG)


@pytest.mark.parametrize("tag", ["1.0.0", "v1.0", "latest", "v1.0.0-RC1", "v1.0.0\n"])
def test_a_malformed_tag_is_rejected(tag: str) -> None:
    with pytest.raises(Rejected, match="not a release tag"):
        expected_packages(PRODUCT, tag)


def test_the_identity_is_the_exact_release_workflow_at_the_tag() -> None:
    assert identity("usearch-php", "v0.2.0") == REAL_IDENTITY


# ---- SHA256SUMS ----------------------------------------------------------------------------


def test_sums_accept_the_producer_format() -> None:
    sums = parse_sums(f"{HEX}  ./a.deb\n{'b' * 64}  b.rpm\n".encode())
    assert sums == {"a.deb": HEX, "b.rpm": "b" * 64}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n",
        f"{HEX}  a.deb",
        f"{HEX}  a.deb\n\n",
        f"{HEX} a.deb\n",
        f"{HEX} *a.deb\n",
        f"{HEX.upper()}  a.deb\n",
        f"{'a' * 63}  a.deb\n",
        f"{HEX}  a.deb\n{HEX}  a.deb\n",
        f"{HEX}  ./a.deb\n{HEX}  a.deb\n",
        f"{HEX}  dir/a.deb\n",
        f"{HEX}  ../a.deb\n",
        f"{HEX}  .//a.deb\n",
        f"{HEX}  a..deb\n",
        f"{HEX}  a b.deb\n",
        f"{HEX}  a~b.deb\n",
        f"{HEX}  a.deb \n",
        f"{HEX}  a.deb\r\n",
    ],
    ids=lambda text: repr(text)[:40],
)
def test_malformed_sums_are_rejected(text: str) -> None:
    with pytest.raises(Rejected):
        parse_sums(text.encode())


def test_sums_that_are_not_text_are_rejected() -> None:
    with pytest.raises(Rejected, match="UTF-8"):
        parse_sums(b"\xff\xfe\n")


def _assets(**digests: str) -> dict[str, Asset]:
    return {
        name: Asset(name=name, size=1, digest=f"sha256:{digest}", url="u")
        for name, digest in digests.items()
    }


def test_check_sums_accepts_a_matching_listing() -> None:
    packages = expected_packages(PRODUCT, TAG)
    assets = _assets(**{p.name: HEX for p in packages})
    check_sums({p.name: HEX for p in packages}, assets, packages)


def test_check_sums_rejects_a_disagreeing_digest() -> None:
    packages = expected_packages(PRODUCT, TAG)
    assets = _assets(**{p.name: HEX for p in packages})
    sums = {p.name: HEX for p in packages}
    sums[packages[0].name] = "b" * 64
    with pytest.raises(Rejected, match="disagrees"):
        check_sums(sums, assets, packages)


def test_check_sums_rejects_an_unlisted_package() -> None:
    packages = expected_packages(PRODUCT, TAG)
    assets = _assets(**{p.name: HEX for p in packages})
    with pytest.raises(Rejected, match="does not list"):
        check_sums({p.name: HEX for p in packages[1:]}, assets, packages)


def test_check_sums_rejects_a_file_the_release_lacks() -> None:
    packages = expected_packages(PRODUCT, TAG)
    assets = _assets(**{p.name: HEX for p in packages})
    sums = {p.name: HEX for p in packages} | {"ghost.deb": HEX}
    with pytest.raises(Rejected, match=r"ghost\.deb"):
        check_sums(sums, assets, packages)


# ---- cosign against a real published artifact ----------------------------------------------


def _signature(
    real_tools: Tools,
    tmp_path: Path,
    *,
    blob: Path = PROVENANCE,
    bundle: Path | None = None,
    who: str = REAL_IDENTITY,
) -> None:
    check_signature(
        real_tools,
        blob=blob,
        bundle=bundle or PROVENANCE_BUNDLE,
        trusted_root=TRUSTED_ROOT,
        expected_identity=who,
        name="provenance",
        home=tmp_path,
    )


def test_a_real_signed_artifact_verifies_offline(real_tools: Tools, tmp_path: Path) -> None:
    _signature(real_tools, tmp_path)


@pytest.mark.parametrize(
    "who",
    [
        "https://github.com/FojleRabbiRabib/usearch-php/.github/workflows/release.yml@refs/tags/v0.2.1",
        "https://github.com/FojleRabbiRabib/resvg-php/.github/workflows/release.yml@refs/tags/v0.2.0",
        "https://github.com/FojleRabbiRabib/usearch-php/.github/workflows/ci.yml@refs/tags/v0.2.0",
        "https://github.com/FojleRabbiRabib/usearch-php/.github/workflows/release.yml@refs/heads/main",
        "https://github.com/FojleRabbiRabib/usearch-php/.github/workflows/release.yml@refs/tags/.*",
        "",
    ],
    ids=["other-tag", "other-repo", "other-workflow", "branch-ref", "regexp", "empty"],
)
def test_a_wrong_identity_is_rejected(real_tools: Tools, tmp_path: Path, who: str) -> None:
    with pytest.raises(Rejected, match="not signed by the release workflow"):
        _signature(real_tools, tmp_path, who=who)


def test_changed_bytes_are_rejected(real_tools: Tools, tmp_path: Path) -> None:
    blob = tmp_path / "provenance"
    blob.write_bytes(PROVENANCE.read_bytes() + b"x")
    with pytest.raises(Rejected, match="not signed"):
        _signature(real_tools, tmp_path, blob=blob)


def test_a_changed_bundle_is_rejected(real_tools: Tools, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    data = bytearray(PROVENANCE_BUNDLE.read_bytes())
    data[len(data) // 2] ^= 1
    bundle.write_bytes(bytes(data))
    with pytest.raises(Rejected, match="not signed"):
        _signature(real_tools, tmp_path, bundle=bundle)


def test_a_missing_bundle_is_rejected(real_tools: Tools, tmp_path: Path) -> None:
    with pytest.raises(Rejected, match="not signed"):
        _signature(real_tools, tmp_path, bundle=tmp_path / "missing")


def test_a_bundle_for_other_bytes_is_rejected(real_tools: Tools, tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.write_bytes(b"something else entirely")
    with pytest.raises(Rejected, match="not signed"):
        _signature(real_tools, tmp_path, blob=other)


def test_a_slow_check_is_rejected_not_fatal(
    tmp_path: Path, real_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "cosign"
    script.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setattr(verify, "COSIGN_TIMEOUT_SECONDS", 0.3)
    started = time.monotonic()
    with pytest.raises(Rejected, match="took longer than"):
        check_signature(
            dataclasses.replace(real_tools, cosign=script),
            blob=PROVENANCE,
            bundle=PROVENANCE_BUNDLE,
            trusted_root=TRUSTED_ROOT,
            expected_identity=REAL_IDENTITY,
            name="provenance",
            home=tmp_path,
        )
    assert time.monotonic() - started < 3.0


def test_a_zero_exit_without_the_success_line_is_not_trusted(
    tmp_path: Path, real_tools: Tools
) -> None:
    script = tmp_path / "cosign"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    with pytest.raises(Rejected, match="not signed"):
        check_signature(
            dataclasses.replace(real_tools, cosign=script),
            blob=PROVENANCE,
            bundle=PROVENANCE_BUNDLE,
            trusted_root=TRUSTED_ROOT,
            expected_identity=REAL_IDENTITY,
            name="provenance",
            home=tmp_path,
        )


def test_a_failing_exit_with_the_success_line_is_not_trusted(
    tmp_path: Path, real_tools: Tools
) -> None:
    script = tmp_path / "cosign"
    script.write_text('#!/bin/sh\necho "Verified OK" >&2\nexit 1\n', encoding="utf-8")
    script.chmod(0o755)
    with pytest.raises(Rejected, match="not signed"):
        check_signature(
            dataclasses.replace(real_tools, cosign=script),
            blob=PROVENANCE,
            bundle=PROVENANCE_BUNDLE,
            trusted_root=TRUSTED_ROOT,
            expected_identity=REAL_IDENTITY,
            name="provenance",
            home=tmp_path,
        )


# ---- whole releases ------------------------------------------------------------------------


def test_a_complete_release_is_admitted(run: Run) -> None:
    verified = run.verify()
    assert verified.tag == TAG
    assert {item.package.name for item in verified.packages} == {DEB, BASE_RPM, VERSIONED_RPM}
    for item in verified.packages:
        assert item.path.read_bytes() == run.files[item.package.name]


def test_cosign_is_called_with_the_pinned_identity_issuer_and_trust_root(run: Run) -> None:
    run.verify()
    calls = run.log.read_text(encoding="utf-8").split("verify-blob\n")[1:]
    assert len(calls) == 3
    for call in calls:
        arguments = call.split("\n")
        assert arguments[arguments.index("--certificate-identity") + 1] == identity("p-php", TAG)
        assert arguments[arguments.index("--certificate-oidc-issuer") + 1] == (
            "https://token.actions.githubusercontent.com"
        )
        assert arguments[arguments.index("--trusted-root") + 1] == str(TRUSTED_ROOT)
        assert not any("insecure" in argument or "regexp" in argument for argument in arguments)


def test_cosign_runs_without_inherited_settings(run: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COSIGN_EXPERIMENTAL", "1")
    monkeypatch.setenv("SIGSTORE_REKOR_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("TUF_ROOT", "/nonexistent")
    run.verify()
    environment = Path(str(run.log) + ".env").read_text(encoding="utf-8")
    assert "COSIGN" not in environment
    assert "SIGSTORE" not in environment
    assert "TUF" not in environment


@pytest.mark.parametrize(
    "missing", [DEB, DEB + ".bundle", BASE_RPM, VERSIONED_RPM + ".bundle", "SHA256SUMS"]
)
def test_a_missing_file_rejects_the_release_before_any_download(run: Run, missing: str) -> None:
    del run.files[missing]
    with pytest.raises(Rejected, match="release lacks"):
        run.verify()
    assert run.served.urls == []


def test_a_release_for_another_version_is_rejected(run: Run) -> None:
    with pytest.raises(Rejected, match="release lacks"):
        run.verify("v1.0.1")


def test_zts_products_are_refused_before_any_download(run: Run) -> None:
    run.product = dataclasses.replace(PRODUCT, ts=("zts",))
    with pytest.raises(Unsupported):
        run.verify()
    assert run.served.urls == []


@pytest.mark.parametrize("name", [DEB + ".bundle", "SHA256SUMS"])
def test_an_oversized_bundle_or_sums_file_is_rejected(run: Run, name: str) -> None:
    run.files[name] = run.files[name] + b"x" * (1024 * 1024)
    with pytest.raises(Rejected, match="larger than allowed"):
        run.verify()
    assert run.served.urls == []


def test_a_bad_bundle_stops_the_release_before_any_package_is_parsed(run: Run) -> None:
    run.files[DEB] = b"this is not a deb at all"
    run.files[DEB + ".bundle"] = b"bad"
    with pytest.raises(Rejected, match="not signed by the release workflow"):
        run.verify()


def test_one_bad_bundle_rejects_the_whole_release(run: Run) -> None:
    run.files[VERSIONED_RPM + ".bundle"] = b"bad"
    with pytest.raises(Rejected, match=VERSIONED_RPM):
        run.verify()


def test_bytes_that_differ_from_the_listed_digest_are_a_download_error_not_a_rejection(
    run: Run,
) -> None:
    run.served.override[DEB] = b"y" * len(run.files[DEB])
    with pytest.raises(DownloadError, match="does not match its digest"):
        run.verify()


@pytest.mark.parametrize(
    "edit",
    [
        lambda sums: sums.replace(BASE_RPM, "other-" + BASE_RPM),
        lambda sums: sums + sums.splitlines(keepends=True)[0],
        lambda sums: "".join(
            line for line in sums.splitlines(keepends=True) if BASE_RPM not in line
        ),
        lambda sums: "0" * 64 + sums[64:],
    ],
    ids=["unknown-name", "duplicate", "package-unlisted", "wrong-digest"],
)
def test_a_bad_sums_file_rejects_the_release(run: Run, edit: Callable[[str], str]) -> None:
    run.files["SHA256SUMS"] = edit(run.files["SHA256SUMS"].decode()).encode()
    with pytest.raises(Rejected):
        run.verify()


def test_a_deb_with_other_metadata_is_rejected(run: Run, real_tools: Tools, tmp_path: Path) -> None:
    run.files[DEB] = build_deb(
        real_tools, tmp_path, package="php8.3-p", version="9.9.9-1", architecture="amd64"
    )
    run.files["SHA256SUMS"] = _sums(run.files)
    with pytest.raises(Rejected, match="expected package metadata"):
        run.verify()


@pytest.mark.parametrize(
    ("package", "architecture"), [("php8.4-p", "amd64"), ("php8.3-p", "arm64")]
)
def test_a_deb_for_another_cell_is_rejected(
    run: Run, real_tools: Tools, tmp_path: Path, package: str, architecture: str
) -> None:
    run.files[DEB] = build_deb(
        real_tools, tmp_path, package=package, version="1.0.0-1", architecture=architecture
    )
    run.files["SHA256SUMS"] = _sums(run.files)
    with pytest.raises(Rejected, match="expected package metadata"):
        run.verify()


@pytest.mark.parametrize(
    ("name", "version", "release", "arch"),
    [
        ("php-q", "1.0.0", "1.php83", "x86_64"),
        ("php-p", "2.0.0", "1.php83", "x86_64"),
        ("php-p", "1.0.0", "2.php83", "x86_64"),
        ("php-p", "1.0.0", "1.php84", "x86_64"),
        ("php-p", "1.0.0", "1.php83", "aarch64"),
    ],
)
def test_an_rpm_with_other_metadata_is_rejected(
    run: Run, tmp_path: Path, keys: dict[str, Key], name: str, version: str, release: str, arch: str
) -> None:
    run.files[BASE_RPM] = build_rpm(
        tmp_path, name=name, version=version, release=release, arch=arch, key=keys["good"]
    )
    run.files["SHA256SUMS"] = _sums(run.files)
    with pytest.raises(Rejected, match="expected package metadata"):
        run.verify()


def test_an_unsigned_rpm_is_rejected(run: Run, tmp_path: Path) -> None:
    run.files[BASE_RPM] = build_rpm(
        tmp_path, name="php-p", version="1.0.0", release="1.php83", arch="x86_64"
    )
    run.files["SHA256SUMS"] = _sums(run.files)
    with pytest.raises(Rejected, match="not signed by the pinned rpm key"):
        run.verify()


def test_an_rpm_signed_by_another_key_is_rejected(
    run: Run, tmp_path: Path, keys: dict[str, Key]
) -> None:
    run.files[BASE_RPM] = build_rpm(
        tmp_path, name="php-p", version="1.0.0", release="1.php83", arch="x86_64", key=keys["other"]
    )
    run.files["SHA256SUMS"] = _sums(run.files)
    with pytest.raises(Rejected, match="not signed by the pinned rpm key"):
        run.verify()


def test_a_changed_rpm_fails_its_signature(run: Run) -> None:
    data = bytearray(run.files[BASE_RPM])
    data[-1] ^= 0xFF
    run.files[BASE_RPM] = bytes(data)
    run.files["SHA256SUMS"] = _sums(run.files)
    with pytest.raises(Rejected, match="fails the rpm signature check"):
        run.verify()


def test_an_rpm_with_an_epoch_is_rejected(run: Run, tmp_path: Path, keys: dict[str, Key]) -> None:
    run.files[BASE_RPM] = build_rpm(
        tmp_path,
        name="php-p",
        version="1.0.0",
        release="1.php83",
        arch="x86_64",
        key=keys["good"],
        epoch=7,
    )
    run.files["SHA256SUMS"] = _sums(run.files)
    with pytest.raises(Rejected, match="expected package metadata"):
        run.verify()


def _rpmkeys_stand_in(tmp_path: Path, real_tools: Tools, tail: str) -> Path:
    """An rpmkeys that imports for real but answers every other call with `tail`."""
    script = tmp_path / "rpmkeys"
    real = real_tools.rpmkeys
    script.write_text(
        "#!/bin/sh\n"
        f'for argument in "$@"; do [ "$argument" = --import ] && exec {real} "$@"; done\n'
        'for argument in "$@"; do last="$argument"; done\n' + tail,
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


@pytest.mark.parametrize(
    "tail",
    [
        "exit 0\n",
        'echo "$last: digests OK"\nexit 0\n',
        'echo "$last: digests SIGNATURES NOT OK"\nexit 0\n',
        'echo "$last: digests signatures OK extra"\nexit 0\n',
        'echo "$last: digests signatures OK"\nexit 1\n',
    ],
    ids=["silent", "digests-only", "signatures-not-ok", "extra-text", "failing-exit"],
)
def test_only_the_exact_rpmkeys_success_line_with_exit_zero_is_trusted(
    run: Run, real_tools: Tools, tmp_path: Path, tail: str
) -> None:
    stand_in = _rpmkeys_stand_in(tmp_path, real_tools, tail)
    run.tools = dataclasses.replace(run.tools, rpmkeys=stand_in)
    with pytest.raises(Rejected, match="fails the rpm signature check"):
        run.verify()


@pytest.mark.parametrize("program", ["dpkg_deb", "rpm"])
def test_a_package_tool_that_hangs_rejects_the_release_not_the_run(
    run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, program: str
) -> None:
    script = tmp_path / program
    script.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    script.chmod(0o755)
    run.tools = dataclasses.replace(run.tools, **{program: script})
    monkeypatch.setattr(verify, "PACKAGE_TOOL_TIMEOUT_SECONDS", 0.3)
    with pytest.raises(Rejected, match="took longer than"):
        run.verify()


@pytest.mark.parametrize("program", ["dpkg_deb", "rpm"])
def test_a_package_tool_that_floods_rejects_the_release_not_the_run(
    run: Run, tmp_path: Path, program: str
) -> None:
    script = tmp_path / program
    script.write_text("#!/bin/sh\nhead -c 1000000 /dev/zero\n", encoding="utf-8")
    script.chmod(0o755)
    run.tools = dataclasses.replace(run.tools, **{program: script})
    with pytest.raises(Rejected, match="more output than allowed"):
        run.verify()


def test_a_cosign_that_floods_rejects_the_release_not_the_run(
    tmp_path: Path, real_tools: Tools
) -> None:
    script = tmp_path / "cosign"
    script.write_text("#!/bin/sh\nhead -c 1000000 /dev/zero >&2\n", encoding="utf-8")
    script.chmod(0o755)
    with pytest.raises(Rejected, match="more output than allowed"):
        check_signature(
            dataclasses.replace(real_tools, cosign=script),
            blob=PROVENANCE,
            bundle=PROVENANCE_BUNDLE,
            trusted_root=TRUSTED_ROOT,
            expected_identity=REAL_IDENTITY,
            name="provenance",
            home=tmp_path,
        )


def test_rpmkeys_alone_accepts_an_unsigned_rpm_which_is_why_the_key_id_is_also_checked(
    real_tools: Tools, tmp_path: Path
) -> None:
    unsigned = tmp_path / "unsigned.rpm"
    unsigned.write_bytes(
        build_rpm(tmp_path, name="php-p", version="1.0.0", release="1", arch="x86_64")
    )
    database = tmp_path / "db"
    database.mkdir()
    result = tools.run(
        [real_tools.rpmkeys, "--dbpath", database, "--checksig", unsigned], home=tmp_path
    )
    assert result.code == 0
    assert "signatures OK" not in result.stdout


# ---- verifier setup ------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_an_expired_or_revoked_rpm_key_stops_the_run(
    run: Run, keys: dict[str, Key], state: str
) -> None:
    run.key = keys[state]
    with pytest.raises(ToolError, match="no valid signing key"):
        run.verifier()


def test_an_expired_master_key_stops_the_run_with_its_own_message(
    run: Run, keys: dict[str, Key]
) -> None:
    run.key = keys["primary-expired"]
    with pytest.raises(ToolError, match="primary rpm key is expired or revoked"):
        run.verifier()


def test_the_pinned_key_ids_are_the_signing_subkey(run: Run) -> None:
    with run.verifier() as verifier:
        assert verifier.key_ids == {run.key.subkey_id}


def test_a_garbage_key_file_stops_the_run(run: Run, tmp_path: Path) -> None:
    garbage = tmp_path / "garbage.asc"
    garbage.write_text("not a key", encoding="utf-8")
    run.key = dataclasses.replace(run.key, public=garbage)
    with pytest.raises(ToolError):
        run.verifier()


def test_a_missing_or_oversized_key_file_stops_the_run(run: Run, tmp_path: Path) -> None:
    run.key = dataclasses.replace(run.key, public=tmp_path / "missing.asc")
    with pytest.raises(ToolError, match="cannot be read"):
        run.verifier()
    big = tmp_path / "big.asc"
    big.write_bytes(b"x" * (64 * 1024 + 1))
    run.key = dataclasses.replace(run.key, public=big)
    with pytest.raises(ToolError, match="too large"):
        run.verifier()


@pytest.mark.parametrize(
    "content",
    [b"", b"not json", b"[]", b'{"mediaType": "text/plain"}', b'{"mediaType": 1}', b"{}"],
)
def test_a_bad_trusted_root_stops_the_run(run: Run, tmp_path: Path, content: bytes) -> None:
    root = tmp_path / "root.json"
    root.write_bytes(content)
    with pytest.raises(ToolError):
        Verifier(run.tools, rpm_key=run.key.public, trusted_root=root, work=run.work)


def test_a_missing_trusted_root_stops_the_run(run: Run, tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="cannot be read"):
        Verifier(run.tools, rpm_key=run.key.public, trusted_root=tmp_path / "x", work=run.work)


def test_the_work_directory_must_exist_and_be_absolute(run: Run, tmp_path: Path) -> None:
    for work in (tmp_path / "missing", Path("relative")):
        with pytest.raises(ToolError, match="work directory"):
            Verifier(run.tools, rpm_key=run.key.public, trusted_root=TRUSTED_ROOT, work=work)


def test_the_private_working_area_is_removed(run: Run) -> None:
    with run.verifier():
        assert len(list(run.work.iterdir())) == 1
    assert list(run.work.iterdir()) == []


def test_a_failed_setup_leaves_no_working_area(run: Run, tmp_path: Path) -> None:
    run.key = dataclasses.replace(run.key, public=tmp_path / "missing.asc")
    with pytest.raises(ToolError):
        run.verifier()
    assert list(run.work.iterdir()) == []
