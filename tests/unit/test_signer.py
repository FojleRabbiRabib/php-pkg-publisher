# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
from __future__ import annotations

import dataclasses
import os
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from pkgkit import Key, add_signing_subkey, make_key, stop_agent, subkeys_only

from publisher import metadata, signer
from publisher.cache import Cache, Chunks
from publisher.metadata import Built
from publisher.signer import Signed, SigningError, SigningKey, sign
from publisher.tools import Tools, run

PHP_TREES = [f"rpm/{php}/{arch}" for php in ("8.3", "8.4", "8.5") for arch in ("x86_64", "aarch64")]


@pytest.fixture(scope="module")
def tools() -> Tools:
    return Tools.locate(os.environ["PATH"])


def _no_fetch(url: str, size: int) -> Chunks:
    raise AssertionError("an empty repository fetches nothing")
    yield b""


@dataclass(frozen=True)
class Source:
    tree: Path
    built: Built


@pytest.fixture(scope="module")
def source(tools: Tools, tmp_path_factory: pytest.TempPathFactory) -> Source:
    """An unsigned metadata tree of an empty repository: all six rpm trees and both apt indexes."""
    base = tmp_path_factory.mktemp("unsigned")
    for name, mode in (("cache", 0o700), ("tree", 0o755), ("work", 0o700)):
        (base / name).mkdir(mode=mode)
    built = metadata.build(
        [],
        cache=Cache(base / "cache", _no_fetch),
        tools=tools,
        target=base / "tree",
        work=base / "work",
    )
    return Source(tree=base / "tree", built=built)


@dataclass(frozen=True)
class Keys:
    master: Key
    vps: SigningKey


def _signing_key(key: Key) -> SigningKey:
    return SigningKey(
        home=key.home,
        fingerprint=key.subkey_fingerprint,
        certificate=key.public,
        primary=key.primary_fingerprint,
    )


@pytest.fixture(scope="module")
def keys(tools: Tools, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Keys]:
    root = tmp_path_factory.mktemp("keys")
    master = make_key(tools, root, "repo")
    vps = subkeys_only(tools, master, root, "vps")
    yield Keys(master=master, vps=_signing_key(vps))
    stop_agent(master)
    stop_agent(vps)


@dataclass
class Site:
    tree: Path
    work: Path


@pytest.fixture
def site(source: Source, tmp_path: Path) -> Site:
    tree = tmp_path / "tree"
    shutil.copytree(source.tree, tree, symlinks=True)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    return Site(tree=tree, work=work)


def _sign(site: Site, source: Source, key: SigningKey, tools: Tools) -> Signed:
    return sign(site.tree, source.built, key, tools=tools, work=site.work)


def _outputs(tree: Path) -> list[Path]:
    paths = [tree / "dists/stable/InRelease", tree / "dists/stable/Release.gpg"]
    paths += [tree / name / "repodata/repomd.xml.asc" for name in PHP_TREES]
    return paths


def _signature_packets(tools: Tools, scratch: Path, path: Path) -> int:
    result = run([tools.gpg, "--list-packets", path], home=scratch)
    return result.stdout.count(":signature packet:")


def _gpgv(tools: Tools, scratch: Path, certificate: Path, *args: Path) -> tuple[int, str]:
    """Verify with gpgv, which apt itself uses, against a keyring made from the certificate."""
    gpgv = shutil.which("gpgv")
    assert gpgv is not None
    home = scratch / "oracle"
    home.mkdir(mode=0o700, exist_ok=True)
    env = {"GNUPGHOME": str(home)}
    ring = scratch / "ring.gpg"
    if not ring.exists():
        run([tools.gpg, "--batch", "--import", certificate], home=scratch, env=env)
        run([tools.gpg, "--batch", "--export", "--output", ring], home=scratch, env=env)
        run([tools.gpgconf, "--kill", "gpg-agent"], home=scratch, env=env)
    result = run([gpgv, "--keyring", ring, "--status-fd", "1", *args], home=scratch)
    return result.code, result.stdout


# --- signing -------------------------------------------------------------------------------


def test_every_file_is_signed_once(tools: Tools, keys: Keys, source: Source, site: Site) -> None:
    result = _sign(site, source, keys.vps, tools)
    assert result.signatures == 8
    for path in _outputs(site.tree):
        assert path.is_file()
        if path.name != "InRelease":  # clearsigned: the gpgv tests count its VALIDSIG
            assert _signature_packets(tools, site.work, path) == 1


def test_gpgv_accepts_each_signature_as_apt_would(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    _sign(site, source, keys.vps, tools)
    dists = site.tree / "dists/stable"
    code, status = _gpgv(tools, site.work, keys.vps.certificate, dists / "InRelease")
    assert code == 0
    assert f"VALIDSIG {keys.vps.fingerprint}" in status
    code, _ = _gpgv(
        tools, site.work, keys.vps.certificate, dists / "Release.gpg", dists / "Release"
    )
    assert code == 0
    for name in PHP_TREES:
        repodata = site.tree / name / "repodata"
        pair = (repodata / "repomd.xml.asc", repodata / "repomd.xml")
        assert _gpgv(tools, site.work, keys.vps.certificate, *pair)[0] == 0


def test_a_changed_file_no_longer_verifies(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    _sign(site, source, keys.vps, tools)
    release = site.tree / "dists/stable/Release"
    release.write_bytes(release.read_bytes() + b"Extra: 1\n")
    signature = site.tree / "dists/stable/Release.gpg"
    assert _gpgv(tools, site.work, keys.vps.certificate, signature, release)[0] != 0


def test_inrelease_carries_exactly_the_release_text(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    _sign(site, source, keys.vps, tools)
    text = (site.tree / "dists/stable/InRelease").read_text(encoding="utf-8")
    release = (site.tree / "dists/stable/Release").read_text(encoding="utf-8")
    assert text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n")
    assert release in text


def test_the_result_reports_when_the_subkey_expires(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    result = _sign(site, source, keys.vps, tools)
    assert result.subkey_expires is not None
    assert 300 * 24 * 3600 < result.subkey_expires - time.time() < 400 * 24 * 3600


def test_no_agent_is_left_running_for_the_signing_home(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    _sign(site, source, keys.vps, tools)
    env = {"GNUPGHOME": str(keys.vps.home)}
    from pkgkit import _find

    listed = run([_find("gpgconf"), "--list-dirs", "agent-socket"], home=site.work, env=env)
    assert not Path(listed.stdout.strip()).exists()


def test_staging_is_removed(tools: Tools, keys: Keys, source: Source, site: Site) -> None:
    _sign(site, source, keys.vps, tools)
    assert list(site.work.iterdir()) == []


# --- one subkey per phase ------------------------------------------------------------------


def test_a_rotation_signs_with_the_configured_subkey_only(
    tools: Tools, tmp_path_factory: pytest.TempPathFactory, source: Source, site: Site
) -> None:
    root = tmp_path_factory.mktemp("rotation")
    first = make_key(tools, root, "rot")
    both = add_signing_subkey(tools, first, root, "rot-both")
    home = subkeys_only(tools, both, root, "rot-vps")
    try:
        for subkey in (first.subkey_fingerprint, both.subkey_fingerprint):
            key = SigningKey(
                home=home.home,
                fingerprint=subkey,
                certificate=both.public,
                primary=both.primary_fingerprint,
            )
            tree = site.tree.parent / f"tree-{subkey[:8]}"
            shutil.copytree(site.tree, tree, symlinks=True)
            sign(tree, source.built, key, tools=tools, work=site.work)
            code, status = _gpgv(tools, site.work, both.public, tree / "dists/stable/InRelease")
            assert code == 0
            assert status.count("VALIDSIG") == 1
            assert f"VALIDSIG {subkey}" in status
            for path in _outputs(tree)[1:]:
                assert _signature_packets(tools, site.work, path) == 1
    finally:
        stop_agent(first)
        stop_agent(home)


# --- the key must be the one clients trust --------------------------------------------------


def test_a_home_holding_the_primary_secret_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    full = _signing_key(keys.master)
    with pytest.raises(SigningError, match="must stay offline"):
        _sign(site, source, full, tools)


def test_a_subkey_missing_from_the_pinned_certificate_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path_factory: pytest.TempPathFactory
) -> None:
    other = make_key(tools, tmp_path_factory.mktemp("other"), "other")
    try:
        key = dataclasses.replace(keys.vps, certificate=other.public)
        with pytest.raises(SigningError, match="not the one primary key"):
            _sign(site, source, key, tools)
    finally:
        stop_agent(other)


def test_a_wrong_primary_pin_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    key = dataclasses.replace(keys.vps, primary="A" * 40)
    with pytest.raises(SigningError, match="not the one primary key"):
        _sign(site, source, key, tools)


def test_a_subkey_the_certificate_lacks_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    key = dataclasses.replace(keys.vps, fingerprint="B" * 40)
    with pytest.raises(SigningError, match="not in the pinned certificate"):
        _sign(site, source, key, tools)


@pytest.mark.parametrize("state", ["expired", "revoked", "primary-expired"])
def test_an_unusable_key_is_refused(
    tools: Tools,
    source: Source,
    site: Site,
    tmp_path_factory: pytest.TempPathFactory,
    state: str,
) -> None:
    root = tmp_path_factory.mktemp(state)
    bad = make_key(tools, root, state, state)  # type: ignore[arg-type]
    try:
        home = subkeys_only(tools, bad, root, f"{state}-vps")
        key = _signing_key(home)
        with pytest.raises(SigningError, match=r"expired|revoked"):
            _sign(site, source, key, tools)
        stop_agent(home)
    finally:
        stop_agent(bad)


def test_a_subkey_that_expires_before_the_release_does_is_refused(
    tools: Tools, source: Source, site: Site, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root = tmp_path_factory.mktemp("short")
    short = make_key(tools, root, "short", lifetime="10d")
    home = subkeys_only(tools, short, root, "short-vps")
    try:
        with pytest.raises(SigningError, match="expires before the Release"):
            _sign(site, source, _signing_key(home), tools)
        assert not (site.tree / "dists/stable/InRelease").exists()
    finally:
        stop_agent(short)
        stop_agent(home)


def test_a_subkey_that_outlives_the_release_is_accepted(
    tools: Tools, source: Source, site: Site, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root = tmp_path_factory.mktemp("long")
    longer = make_key(tools, root, "long", lifetime="20d")
    home = subkeys_only(tools, longer, root, "long-vps")
    try:
        assert _sign(site, source, _signing_key(home), tools).signatures == 8
    finally:
        stop_agent(longer)
        stop_agent(home)


def test_a_passphrase_protected_subkey_fails_closed(
    tools: Tools, source: Source, site: Site, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root = tmp_path_factory.mktemp("protected")
    home = root / "home"
    home.mkdir(mode=0o700)
    env = {"GNUPGHOME": str(home)}
    gpg: list[str | Path] = [tools.gpg, "--batch", "--no-tty", "--pinentry-mode", "loopback"]
    gpg += ["--passphrase", "pw"]
    run(
        [*gpg, "--quick-gen-key", "p <p@example.invalid>", "rsa3072", "cert", "0"],
        home=root,
        env=env,
    )
    listing = run([*gpg, "--with-colons", "--list-keys"], home=root, env=env).stdout
    primary = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr"))
    run([*gpg, "--quick-add-key", primary, "rsa3072", "sign", "1y"], home=root, env=env)
    listing = run(
        [*gpg, "--with-colons", "--fixed-list-mode", "--list-keys"], home=root, env=env
    ).stdout
    lines = listing.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith("sub"))
    subkey = lines[index + 1].split(":")[9]
    certificate = root / "p.asc"
    certificate.write_text(
        run([*gpg, "--armor", "--export", primary], home=root, env=env).stdout, "utf-8"
    )
    exported = root / "subkeys.gpg"
    run([*gpg, "--export-secret-subkeys", "--output", exported], home=root, env=env)
    vps = root / "vps"
    vps.mkdir(mode=0o700)
    run([*gpg, "--import", exported], home=root, env={"GNUPGHOME": str(vps)})
    key = SigningKey(home=vps, fingerprint=subkey, certificate=certificate, primary=primary)
    try:
        with pytest.raises(SigningError, match="signing InRelease failed"):
            _sign(site, source, key, tools)
        assert not (site.tree / "dists/stable/InRelease").exists()
    finally:
        for path in (home, vps):
            run(
                [shutil.which("gpgconf") or "gpgconf", "--kill", "gpg-agent"],
                home=root,
                env={"GNUPGHOME": str(path)},
            )


# --- configuration and tree checks ----------------------------------------------------------


@pytest.mark.parametrize(
    ("fingerprint", "primary"),
    [("ab" * 20, None), (None, "abc"), ("A" * 39, None)],
)
def test_malformed_fingerprints_are_refused(
    tools: Tools,
    keys: Keys,
    source: Source,
    site: Site,
    fingerprint: str | None,
    primary: str | None,
) -> None:
    key = dataclasses.replace(
        keys.vps,
        fingerprint=fingerprint or keys.vps.fingerprint,
        primary=primary or keys.vps.primary,
    )
    with pytest.raises(SigningError, match="40 upper-case hex"):
        _sign(site, source, key, tools)


def test_the_signing_key_cannot_be_the_primary_key(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    key = dataclasses.replace(keys.vps, fingerprint=keys.vps.primary)
    with pytest.raises(SigningError, match="must be a subkey"):
        _sign(site, source, key, tools)


def test_a_signing_home_open_to_others_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    home = tmp_path / "open"
    shutil.copytree(keys.vps.home, home, ignore=shutil.ignore_patterns("S.*", "*.lock"))
    home.chmod(0o755)
    with pytest.raises(SigningError, match="group or others"):
        _sign(site, source, dataclasses.replace(keys.vps, home=home), tools)


def test_a_key_home_too_long_for_the_agent_socket_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    home = tmp_path / ("long" * 25)
    home.mkdir(mode=0o700)
    with pytest.raises(SigningError, match="too long"):
        _sign(site, source, dataclasses.replace(keys.vps, home=home), tools)


def test_a_temporary_directory_too_long_for_the_agent_socket_is_refused(
    tools: Tools,
    keys: Keys,
    source: Source,
    site: Site,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    long_temp = tmp_path / ("t" * 90)
    long_temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(long_temp))
    with pytest.raises(SigningError, match="set TMPDIR"):
        _sign(site, source, keys.vps, tools)
    assert list(long_temp.iterdir()) == []
    assert list(site.work.iterdir()) == []


def test_a_missing_certificate_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    key = dataclasses.replace(keys.vps, certificate=tmp_path / "none.asc")
    with pytest.raises(SigningError, match="regular file"):
        _sign(site, source, key, tools)


def test_an_existing_signature_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    (site.tree / "dists/stable/InRelease").write_text("old", encoding="utf-8")
    with pytest.raises(SigningError, match="already exists"):
        _sign(site, source, keys.vps, tools)


def test_signing_twice_is_refused(tools: Tools, keys: Keys, source: Source, site: Site) -> None:
    _sign(site, source, keys.vps, tools)
    with pytest.raises(SigningError, match="already exists"):
        _sign(site, source, keys.vps, tools)


def test_a_missing_release_is_refused(tools: Tools, keys: Keys, source: Source, site: Site) -> None:
    (site.tree / "dists/stable/Release").unlink()
    with pytest.raises(SigningError, match="nothing to sign"):
        _sign(site, source, keys.vps, tools)


def test_a_missing_repomd_is_refused(tools: Tools, keys: Keys, source: Source, site: Site) -> None:
    (site.tree / "rpm/8.5/aarch64/repodata/repomd.xml").unlink()
    with pytest.raises(SigningError, match="nothing to sign"):
        _sign(site, source, keys.vps, tools)
    assert not (site.tree / "dists/stable/InRelease").exists()


def test_a_release_without_valid_until_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    release = site.tree / "dists/stable/Release"
    release.write_text("Origin: x\n", encoding="utf-8")
    with pytest.raises(SigningError, match="cannot be read for signing"):
        _sign(site, source, keys.vps, tools)


def test_the_work_directory_must_be_private(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    site.work.chmod(0o755)
    with pytest.raises(SigningError, match="group or others"):
        _sign(site, source, keys.vps, tools)


# --- a gpg that misbehaves fails closed -----------------------------------------------------


def _gpg_wrapper(directory: Path, real: Path, edit: str) -> Path:
    """A `gpg` that rewrites its arguments (`args`) with a few lines of Python, then runs gpg."""
    path = directory / "gpg"
    path.write_text(
        f"#!{sys.executable}\nimport os, sys\nargs = sys.argv[1:]\n{edit}\n"
        f"os.execv({str(real)!r}, [{str(real)!r}, *args])\n",
        encoding="utf-8",
    )
    path.chmod(stat.S_IRWXU)
    return path


def _other_subkey(tools: Tools, root: Path) -> tuple[Key, Key]:
    first = make_key(tools, root, "wrap")
    both = add_signing_subkey(tools, first, root, "wrap-both")
    return first, both


@pytest.fixture
def two_subkeys(
    tools: Tools, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[SigningKey, str]]:
    root = tmp_path_factory.mktemp("two")
    first, both = _other_subkey(tools, root)
    home = subkeys_only(tools, both, root, "two-vps")
    key = SigningKey(
        home=home.home,
        fingerprint=first.subkey_fingerprint,
        certificate=both.public,
        primary=both.primary_fingerprint,
    )
    yield key, both.subkey_fingerprint
    stop_agent(first)
    stop_agent(home)


def test_a_signature_by_another_subkey_is_refused(
    tools: Tools,
    source: Source,
    site: Site,
    tmp_path: Path,
    two_subkeys: tuple[SigningKey, str],
) -> None:
    key, other = two_subkeys
    edit = f"args = [a.replace({key.fingerprint + '!'!r}, {other + '!'!r}) for a in args]"
    fake = dataclasses.replace(tools, gpg=_gpg_wrapper(tmp_path, tools.gpg, edit))
    with pytest.raises(SigningError, match="not made by the configured subkey"):
        sign(site.tree, source.built, key, tools=fake, work=site.work)
    assert not (site.tree / "dists/stable/InRelease").exists()


def test_a_dual_signature_is_refused(
    tools: Tools,
    source: Source,
    site: Site,
    tmp_path: Path,
    two_subkeys: tuple[SigningKey, str],
) -> None:
    key, other = two_subkeys
    edit = (
        "if '--local-user' in args:\n"
        "    i = args.index('--local-user')\n"
        f"    args[i:i] = ['--local-user', {other + '!'!r}]\n"
    )
    fake = dataclasses.replace(tools, gpg=_gpg_wrapper(tmp_path, tools.gpg, edit))
    with pytest.raises(SigningError, match="exactly one good signature"):
        sign(site.tree, source.built, key, tools=fake, work=site.work)


def test_a_different_digest_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    edit = "args = ['SHA512' if a == 'SHA256' else a for a in args]"
    fake = dataclasses.replace(tools, gpg=_gpg_wrapper(tmp_path, tools.gpg, edit))
    with pytest.raises(SigningError, match="was not signed with SHA256"):
        sign(site.tree, source.built, keys.vps, tools=fake, work=site.work)


def test_a_clearsigned_text_that_differs_from_release_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    changed = tmp_path / "changed"
    changed.write_text("Origin: other\n", encoding="utf-8")
    edit = (
        f"args = [{str(changed)!r} if '--clearsign' in args and a == args[-1] else a for a in args]"
    )
    fake = dataclasses.replace(tools, gpg=_gpg_wrapper(tmp_path, tools.gpg, edit))
    with pytest.raises(SigningError, match="exactly the text of Release"):
        sign(site.tree, source.built, keys.vps, tools=fake, work=site.work)


def test_a_gpg_that_writes_nothing_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    quiet = tmp_path / "gpg"
    quiet.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    quiet.chmod(stat.S_IRWXU)
    fake = dataclasses.replace(tools, gpg=quiet)
    with pytest.raises(SigningError):
        sign(site.tree, source.built, keys.vps, tools=fake, work=site.work)


def _status(*lines: str) -> list[list[str]]:
    return [line.split() for line in lines]


def _good(key: SigningKey, *, made: float | None = None, digest: str = "8") -> list[list[str]]:
    stamp = int(time.time() if made is None else made)
    return _status(
        "NEWSIG",
        "GOODSIG 0123456789ABCDEF name",
        f"VALIDSIG {key.fingerprint} 2026-11-05 {stamp} 0 4 0 1 {digest} 00 {key.primary}",
    )


def test_a_good_status_passes(keys: Keys) -> None:
    signer._check_status(keys.vps, _good(keys.vps), "x")


def test_a_signature_time_off_the_clock_is_refused(keys: Keys) -> None:
    with pytest.raises(SigningError, match="not near the clock"):
        signer._check_status(keys.vps, _good(keys.vps, made=time.time() - 7200), "x")


def test_a_status_for_the_wrong_primary_is_refused(keys: Keys) -> None:
    other = dataclasses.replace(keys.vps, primary="C" * 40)
    with pytest.raises(SigningError, match="not made by the configured subkey"):
        signer._check_status(other, _good(keys.vps), "x")


@pytest.mark.parametrize("tag", ["BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"])
def test_a_bad_status_tag_is_refused(keys: Keys, tag: str) -> None:
    status = [*_good(keys.vps), [tag, "0123456789ABCDEF"]]
    with pytest.raises(SigningError, match="exactly one good signature"):
        signer._check_status(keys.vps, status, "x")


def test_no_signature_status_is_refused(keys: Keys) -> None:
    with pytest.raises(SigningError, match="exactly one good signature"):
        signer._check_status(keys.vps, [], "x")


# --- findings of the blind review -----------------------------------------------------------


def test_the_written_files_are_readable_by_the_web_server(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    _sign(site, source, keys.vps, tools)
    for path in _outputs(site.tree):
        assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_a_primary_key_that_expires_before_the_release_does_is_refused(
    tools: Tools, source: Source, site: Site, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root = tmp_path_factory.mktemp("primary-short")
    short = make_key(tools, root, "pshort", primary_lifetime="5d")
    home = subkeys_only(tools, short, root, "pshort-vps")
    try:
        with pytest.raises(SigningError, match="expires before the Release"):
            _sign(site, source, _signing_key(home), tools)
    finally:
        stop_agent(short)
        stop_agent(home)


def test_a_relative_tree_path_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    with pytest.raises(SigningError, match="absolute"):
        sign(Path("tree"), source.built, keys.vps, tools=tools, work=site.work)


def test_an_agent_that_cannot_be_stopped_fails_the_run(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    stuck = tmp_path / "gpgconf"
    stuck.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    stuck.chmod(stat.S_IRWXU)
    fake = dataclasses.replace(tools, gpgconf=stuck)
    with pytest.raises(SigningError, match="cannot stop gpg-agent"):
        sign(site.tree, source.built, keys.vps, tools=fake, work=site.work)
    assert not (site.tree / "dists/stable/InRelease").exists()


def test_a_large_release_can_be_signed(
    tools: Tools, keys: Keys, source: Source, site: Site
) -> None:
    release = site.tree / "dists/stable/Release"
    filler = b"".join(b" " + b"%064x" % n + b" 1 main/x\n" for n in range(2500))
    release.write_bytes(release.read_bytes() + b"X-Filler:\n" + filler)
    assert release.stat().st_size > 64 * 1024
    _sign(site, source, keys.vps, tools)
    assert release.read_bytes() in (site.tree / "dists/stable/InRelease").read_bytes()


def test_a_release_that_changes_while_signing_is_refused(
    tools: Tools, keys: Keys, source: Source, site: Site, tmp_path: Path
) -> None:
    release = site.tree / "dists/stable/Release"
    edit = (
        f"if '--detach-sign' in args:\n    open({str(release)!r}, 'a').write('Changed: yes\\n')\n"
    )
    fake = dataclasses.replace(tools, gpg=_gpg_wrapper(tmp_path, tools.gpg, edit))
    with pytest.raises(SigningError, match="changed while it was signed"):
        sign(site.tree, source.built, keys.vps, tools=fake, work=site.work)
    assert not (site.tree / "dists/stable/InRelease").exists()


def test_a_gpg_that_hangs_is_stopped(
    tools: Tools,
    keys: Keys,
    source: Source,
    site: Site,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from publisher.tools import ToolTimeout

    slow = tmp_path / "gpg"
    slow.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    slow.chmod(stat.S_IRWXU)
    monkeypatch.setattr(signer, "GPG_TIMEOUT_SECONDS", 0.3)
    with pytest.raises(ToolTimeout):
        sign(
            site.tree,
            source.built,
            keys.vps,
            tools=dataclasses.replace(tools, gpg=slow),
            work=site.work,
        )


def test_a_failure_while_writing_is_reported(
    tools: Tools,
    keys: Keys,
    source: Source,
    site: Site,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from publisher import files

    def failing(path: Path, data: bytes, **_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(files, "write_atomic", failing)
    with pytest.raises(SigningError, match="cannot write the signatures"):
        _sign(site, source, keys.vps, tools)


def test_a_detached_dual_signature_is_refused(
    tools: Tools,
    source: Source,
    site: Site,
    tmp_path: Path,
    two_subkeys: tuple[SigningKey, str],
) -> None:
    """Only the detached signatures get a second signature; InRelease stays correct."""
    key, other = two_subkeys
    edit = (
        "if '--local-user' in args and '--clearsign' not in args:\n"
        "    i = args.index('--local-user')\n"
        f"    args[i:i] = ['--local-user', {other + '!'!r}]\n"
    )
    fake = dataclasses.replace(tools, gpg=_gpg_wrapper(tmp_path, tools.gpg, edit))
    with pytest.raises(SigningError, match=r"Release\.gpg: does not carry exactly one good"):
        sign(site.tree, source.built, key, tools=fake, work=site.work)


def test_a_detached_signature_by_another_subkey_is_refused(
    tools: Tools,
    source: Source,
    site: Site,
    tmp_path: Path,
    two_subkeys: tuple[SigningKey, str],
) -> None:
    key, other = two_subkeys
    edit = (
        "if '--clearsign' not in args:\n"
        f"    args = [a.replace({key.fingerprint + '!'!r}, {other + '!'!r}) for a in args]\n"
    )
    fake = dataclasses.replace(tools, gpg=_gpg_wrapper(tmp_path, tools.gpg, edit))
    with pytest.raises(SigningError, match=r"Release\.gpg: was not made by the configured"):
        sign(site.tree, source.built, key, tools=fake, work=site.work)
