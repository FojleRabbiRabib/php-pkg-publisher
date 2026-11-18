# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""The keyring packages: built from a throwaway certificate, read back with independent tools.

The certificate has the design's shape: one master with two signing subkeys, one for the repo and
one for the RPM job. Every expectation comes from `dpkg-deb`, `rpm`, `gpg` and `gpgv`, not from the
builder.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import build_keyring
import pytest
from pkgkit import Key, add_encryption_subkey, add_signing_subkey, make_key, stop_agent

from publisher.tools import Tools

MAINTAINER = "Test Maintainer <maintainer@example.invalid>"
EPOCH = 1780000000
APT_PATH = "./usr/share/keyrings/rabib-archive-keyring.gpg"
RPM_PATH = "./etc/pki/rpm-gpg/RPM-GPG-KEY-rabib"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


@dataclass(frozen=True)
class Certificate:
    key: Key
    primary: str
    repo: str
    rpm: str

    @property
    def public(self) -> Path:
        return self.key.public


def _two_subkeys(tools: Tools, root: Path, name: str, state: str = "valid") -> Certificate:
    first = make_key(tools, root, name, state)  # type: ignore[arg-type]
    second = add_signing_subkey(tools, first, root, f"{name}-two")
    return Certificate(
        key=second,
        primary=first.primary_fingerprint.upper(),
        repo=first.subkey_fingerprint.upper(),
        rpm=second.subkey_fingerprint.upper(),
    )


@dataclass(frozen=True)
class Kit:
    good: Certificate
    expired: Certificate
    revoked: Certificate
    primary_expired: Certificate
    root: Path


@pytest.fixture(scope="module")
def kit(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Kit]:
    tools = Tools.locate(os.environ["PATH"])
    root = tmp_path_factory.mktemp("kr")
    made = Kit(
        good=_two_subkeys(tools, root, "good"),
        expired=_two_subkeys(tools, root, "expired", "expired"),
        revoked=_two_subkeys(tools, root, "revoked", "revoked"),
        primary_expired=_two_subkeys(tools, root, "pexpired", "primary-expired"),
        root=root,
    )
    yield made
    for item in (made.good, made.expired, made.revoked, made.primary_expired):
        stop_agent(item.key)


def _command(
    cert: Certificate, output: Path, *, replace: dict[str, list[str]] | None = None
) -> list[str]:
    """The builder's arguments; `replace` swaps the values of a flag (an empty list drops it)."""
    flags: dict[str, list[str]] = {
        "--key": [str(cert.public)],
        "--fingerprint": [cert.primary],
        "--repo-subkey": [cert.repo],
        "--rpm-subkey": [cert.rpm],
        "--version": ["2026.1"],
        "--maintainer": [MAINTAINER],
        "--source-date-epoch": [str(EPOCH)],
        "--output": [str(output)],
        "--unsigned": [],
    }
    flags.update(replace or {})
    arguments: list[str] = []
    for flag, values in flags.items():
        if flag == "--unsigned":
            if replace is not None and flag in replace and replace[flag] == ["drop"]:
                continue
            arguments.append(flag)
        elif flag in (replace or {}) or values:
            for value in values:
                arguments += [flag, value]
    return arguments


def _build(
    cert: Certificate, output: Path, replace: dict[str, list[str]] | None = None
) -> tuple[int, str]:
    code = build_keyring.main(_command(cert, output, replace=replace))
    return code, ""


@pytest.fixture(scope="module")
def built(kit: Kit, tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("built") / "out"
    code, _ = _build(kit.good, output)
    assert code == 0
    return output


def _run(*command: str | Path, stdin: bytes | None = None) -> bytes:
    done = subprocess.run(  # noqa: S603
        [str(part) for part in command],
        input=stdin,
        capture_output=True,
        check=True,
        env=ENV,
    )
    return done.stdout


def _fingerprints(data: bytes) -> tuple[set[str], set[str]]:
    """(primary and subkey fingerprints, secret key records) in a key file, read by gpg."""
    listing = _run(
        "gpg",
        "--batch",
        "--no-tty",
        "--with-colons",
        "--fixed-list-mode",
        "--show-keys",
        stdin=data,
    ).decode()
    records = [line.split(":") for line in listing.splitlines()]
    found = {record[9].upper() for record in records if record[0] == "fpr"}
    secret = {record[0] for record in records if record[0] in ("sec", "ssb")}
    return found, secret


def _tar_files(archive: bytes) -> dict[str, bytes]:
    """The regular files of a tar stream, by path without the leading `./`."""
    with tarfile.open(fileobj=io.BytesIO(archive)) as handle:
        files: dict[str, bytes] = {}
        for member in handle.getmembers():
            data = handle.extractfile(member) if member.isfile() else None
            if data is not None:
                files[member.name.removeprefix("./")] = data.read()
        return files


def _deb_file(deb: Path, path: str) -> bytes:
    archive = _run("dpkg-deb", "--fsys-tarfile", deb)
    with tarfile.open(fileobj=io.BytesIO(archive)) as handle:
        member = handle.extractfile(path)
        assert member is not None
        return member.read()


def _rpm_file(package: Path, path: str) -> bytes:
    archive = _run("rpm2archive", "-", stdin=package.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as handle:
        member = handle.extractfile(path)
        assert member is not None
        return member.read()


# ---- what is built ------------------------------------------------------------------------------


def test_a_build_writes_both_versions_and_fixed_names_with_the_same_bytes(built: Path) -> None:
    names = sorted(path.name for path in built.iterdir())
    assert names == [
        "rabib-archive-keyring.deb",
        "rabib-archive-keyring_2026.1_all.deb",
        "rabib-release-2026.1-1.noarch.rpm",
        "rabib-release.rpm",
    ]
    assert (built / names[0]).read_bytes() == (built / names[1]).read_bytes()
    assert (built / names[2]).read_bytes() == (built / names[3]).read_bytes()
    assert all(path.stat().st_mode & 0o777 == 0o644 for path in built.iterdir())


def test_the_deb_declares_its_package_and_holds_only_the_keyring_and_its_documents(
    built: Path,
) -> None:
    deb = built / "rabib-archive-keyring_2026.1_all.deb"
    fields = _run(
        "dpkg-deb", "-f", deb, "Package", "Version", "Architecture", "Maintainer"
    ).decode()
    assert fields.splitlines() == [
        "Package: rabib-archive-keyring",
        "Version: 2026.1",
        "Architecture: all",
        f"Maintainer: {MAINTAINER}",
    ]
    listing = _run("dpkg-deb", "--contents", deb).decode().splitlines()
    files = sorted(line.split()[-1] for line in listing if line.startswith("-"))
    assert files == [
        "./usr/share/doc/rabib-archive-keyring/LICENSE",
        "./usr/share/doc/rabib-archive-keyring/NOTICE",
        "./usr/share/doc/rabib-archive-keyring/changelog.gz",
        "./usr/share/doc/rabib-archive-keyring/copyright",
        "./usr/share/keyrings/rabib-archive-keyring.gpg",
    ]
    assert sorted(_tar_files(_run("dpkg-deb", "--ctrl-tarfile", deb))) == ["control", "md5sums"]


def test_the_deb_md5sums_list_every_file_with_its_real_digest(built: Path) -> None:
    deb = built / "rabib-archive-keyring_2026.1_all.deb"
    control = _tar_files(_run("dpkg-deb", "--ctrl-tarfile", deb))
    listed = dict(line.split("  ", 1)[::-1] for line in control["md5sums"].decode().splitlines())
    payload = _tar_files(_run("dpkg-deb", "--fsys-tarfile", deb))
    held = {
        name: hashlib.md5(data, usedforsecurity=False).hexdigest() for name, data in payload.items()
    }
    assert listed == held


def test_the_apt_keyring_holds_the_primary_and_the_repo_subkey_and_no_secret(
    built: Path, kit: Kit
) -> None:
    data = _deb_file(built / "rabib-archive-keyring.deb", APT_PATH)
    fingerprints, secret = _fingerprints(data)
    assert fingerprints == {kit.good.primary, kit.good.repo}
    assert secret == set()


def test_the_rpm_key_holds_the_primary_and_both_subkeys_and_no_secret(
    built: Path, kit: Kit
) -> None:
    data = _rpm_file(built / "rabib-release.rpm", RPM_PATH)
    assert data.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    fingerprints, secret = _fingerprints(data)
    assert fingerprints == {kit.good.primary, kit.good.repo, kit.good.rpm}
    assert secret == set()


def test_the_rpm_declares_its_package_and_runs_the_cache_cleanup_and_no_import(
    built: Path,
) -> None:
    package = built / "rabib-release.rpm"
    fields = _run(
        "rpm", "-qp", "--qf", "%{NAME} %{VERSION} %{RELEASE} %{ARCH} %{LICENSE}", package
    ).decode()
    assert fields == "rabib-release 2026.1 1 noarch Apache-2.0"
    # rpm 6 cannot import a key inside a transaction: no scriptlet but %posttrans may exist
    for scriptlet in ("PREIN", "POSTIN", "PREUN", "POSTUN", "PRETRANS"):
        shown = _run("rpm", "-qp", "--qf", f"%{{{scriptlet}}}", package).decode().strip()
        assert shown == "(none)", scriptlet
    trans = _run("rpm", "-qp", "--qf", "%{POSTTRANS}", package).decode()
    assert "rm -rf -- /var/cache/dnf/rabib-*/pubring /var/cache/libdnf5/rabib-*/pubring" in trans
    files = _run("rpm", "-qpl", package).decode().splitlines()
    assert "/etc/pki/rpm-gpg/RPM-GPG-KEY-rabib" in files
    assert all("pubring" not in line for line in files)


def test_apt_accepts_the_repo_subkey_and_refuses_the_rpm_subkey(
    built: Path, kit: Kit, tmp_path: Path
) -> None:
    keyring = tmp_path / "apt.gpg"
    keyring.write_bytes(_deb_file(built / "rabib-archive-keyring.deb", APT_PATH))
    outcomes = {}
    for name, fingerprint in (("repo", kit.good.repo), ("rpm", kit.good.rpm)):
        message = tmp_path / f"{name}.txt"
        message.write_text("Release\n", encoding="utf-8")
        signed = tmp_path / f"{name}.asc"
        _run(
            "gpg", "--homedir", kit.good.key.home, "--batch", "--no-tty", "--pinentry-mode",
            "loopback", "--passphrase", "", "--local-user", f"{fingerprint}!",
            "--output", signed, "--clearsign", message,
        )  # fmt: skip
        done = subprocess.run(  # noqa: S603
            [
                shutil.which("gpgv", path=ENV["PATH"]) or "gpgv",
                "--keyring",
                str(keyring),
                str(signed),
            ],
            capture_output=True,
            check=False,
            env=ENV,
        )
        outcomes[name] = done.returncode
    assert outcomes["repo"] == 0
    assert outcomes["rpm"] != 0


def test_the_subkey_filter_compares_fingerprints_as_strings() -> None:
    """gpg's `!=` is numeric, so fingerprints that start with a letter would all compare equal."""
    expression = build_keyring.drop_filter(["AB12", "CD34"])
    assert expression == "drop-subkey=fpr <> AB12 && fpr <> CD34"
    assert "!=" not in expression


# ---- reproducible and signed --------------------------------------------------------------------


def _digests(output: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(output.iterdir())
    }


def test_two_builds_of_the_same_inputs_are_byte_identical(
    kit: Kit, built: Path, tmp_path: Path
) -> None:
    again = tmp_path / "again"
    assert _build(kit.good, again)[0] == 0
    assert _digests(again) == _digests(built)


def test_a_different_source_date_changes_the_bytes(kit: Kit, built: Path, tmp_path: Path) -> None:
    other = tmp_path / "other"
    assert _build(kit.good, other, {"--source-date-epoch": [str(EPOCH + 86400)]})[0] == 0
    assert _digests(other) != _digests(built)


def test_a_signed_rpm_carries_the_rpm_subkey_signature_and_verifies(
    kit: Kit, tmp_path: Path
) -> None:
    output = tmp_path / "signed"
    replace = {
        "--unsigned": ["drop"],
        "--sign-home": [str(kit.good.key.home)],
        "--sign-key": [kit.good.rpm],
    }
    assert _build(kit.good, output, replace)[0] == 0
    package = output / "rabib-release.rpm"
    signature = _run("rpm", "-qp", "--qf", "%{RSAHEADER:pgpsig}", "--nosignature", package).decode()
    assert signature.endswith(f"Key ID {kit.good.rpm[-16:].lower()}")
    database = tmp_path / "db"
    database.mkdir()
    _run("rpmkeys", "--dbpath", database, "--import", kit.good.public)
    checked = _run("rpmkeys", "--dbpath", database, "--checksig", package).decode()
    assert checked.strip() == f"{package}: digests signatures OK"
    # the builder leaves no gpg-agent running in the signing home
    socket = _run("gpgconf", "--homedir", kit.good.key.home, "--list-dirs", "agent-socket").decode()
    assert not Path(socket.strip()).exists()


# ---- fail closed --------------------------------------------------------------------------------

OTHER = "0123456789ABCDEF0123456789ABCDEF01234567"


def _secret_file(kit: Kit, tmp_path: Path) -> Path:
    path = tmp_path / "secret.asc"
    secret = _run(
        "gpg", "--homedir", kit.good.key.home, "--batch", "--no-tty", "--pinentry-mode", "loopback",
        "--passphrase", "", "--armor", "--export-secret-keys", kit.good.primary,
    )  # fmt: skip
    path.write_bytes(secret)
    return path


@pytest.mark.parametrize(
    ("replace", "message"),
    [
        ({"--fingerprint": [OTHER]}, "not the one named"),
        ({"--repo-subkey": [OTHER]}, "missing, expired or revoked"),
        ({"--rpm-subkey": [OTHER]}, "missing, expired or revoked"),
        ({"--repo-subkey": []}, "at least one --repo-subkey"),
        ({"--rpm-subkey": []}, "at least one --rpm-subkey"),
        ({"--version": ["2026"]}, "version must look like"),
        ({"--version": ["2026.0"]}, "version must look like"),
        ({"--version": ["26.1"]}, "version must look like"),
        ({"--maintainer": ["nobody"]}, "maintainer must look like"),
        ({"--maintainer": ["A <b@c>\nInjected: yes"]}, "maintainer must look like"),
        ({"--maintainer": ["A %(id) <a@b.c>"]}, "maintainer must look like"),
        ({"--maintainer": ["A <%{_topdir}@b.c>"]}, "maintainer must look like"),
        ({"--unsigned": ["drop"], "--sign-key": [OTHER]}, "--sign-home and --sign-key go together"),
        ({"--fingerprint": ["abc"]}, "40 hexadecimal digits"),
        ({"--unsigned": ["drop"]}, "either --sign-home with --sign-key, or --unsigned"),
        ({"--sign-home": ["/nonexistent"]}, "either --sign-home with --sign-key, or --unsigned"),
        ({"--source-date-epoch": ["-1"]}, "must not be negative"),
    ],
    ids=lambda value: value if isinstance(value, str) else ",".join(value),
)
def test_a_bad_argument_builds_nothing(
    kit: Kit,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    replace: dict[str, list[str]],
    message: str,
) -> None:
    output = tmp_path / "out"
    code, _ = _build(kit.good, output, replace)
    assert code == 1
    assert message in capsys.readouterr().err
    assert not output.exists()


def test_a_repo_subkey_cannot_also_be_the_rpm_subkey(
    kit: Kit, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "out"
    code, _ = _build(kit.good, output, {"--rpm-subkey": [kit.good.repo]})
    assert code == 1
    assert "both a repo subkey and an RPM subkey" in capsys.readouterr().err
    assert not output.exists()


def test_the_signing_key_must_be_an_rpm_subkey(
    kit: Kit, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "out"
    replace = {
        "--unsigned": ["drop"],
        "--sign-home": [str(kit.good.key.home)],
        "--sign-key": [kit.good.repo],
    }
    assert _build(kit.good, output, replace)[0] == 1
    assert "one of the --rpm-subkey fingerprints" in capsys.readouterr().err
    assert not output.exists()


def test_a_file_with_secret_keys_is_refused(
    kit: Kit, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "out"
    code, _ = _build(kit.good, output, {"--key": [str(_secret_file(kit, tmp_path))]})
    assert code == 1
    assert "secret key material" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.parametrize(
    ("which", "message"),
    [
        ("expired", "expired or revoked"),
        ("revoked", "expired or revoked"),
        ("primary_expired", "primary key is expired or revoked"),
    ],
)
def test_an_expired_or_revoked_key_is_refused(
    kit: Kit, tmp_path: Path, capsys: pytest.CaptureFixture[str], which: str, message: str
) -> None:
    cert: Certificate = getattr(kit, which)
    output = tmp_path / "out"
    code, _ = _build(cert, output)
    assert code == 1
    assert message in capsys.readouterr().err
    assert not output.exists()


def test_a_valid_subkey_that_cannot_sign_is_refused(
    kit: Kit, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tools = Tools.locate(os.environ["PATH"])
    base = make_key(tools, kit.root, "encrbase")
    both = add_encryption_subkey(tools, base, kit.root, "encrcert")
    try:
        cert = Certificate(
            key=both,
            primary=base.primary_fingerprint.upper(),
            repo=base.subkey_fingerprint.upper(),
            rpm=both.subkey_fingerprint.upper(),
        )
        output = tmp_path / "out"
        assert _build(cert, output)[0] == 1
        assert "cannot sign" in capsys.readouterr().err
        assert not output.exists()
    finally:
        stop_agent(base)


def test_a_signing_home_without_the_key_builds_nothing(
    kit: Kit, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "empty-home"
    empty.mkdir(mode=0o700)
    output = tmp_path / "out"
    replace = {
        "--unsigned": ["drop"],
        "--sign-home": [str(empty)],
        "--sign-key": [kit.good.rpm],
    }
    assert _build(kit.good, output, replace)[0] == 1
    assert "rpmsign failed" in capsys.readouterr().err
    assert not output.exists()


def test_a_signature_by_another_key_is_refused(
    kit: Kit,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`rpmkeys` accepts any key of the certificate, so the builder reads the key id itself."""
    real = build_keyring._run

    def other_key(command: Sequence[str | Path], **kwargs: Any) -> str:
        done = real(command, **kwargs)
        if "%{RSAHEADER:pgpsig}" in [str(part) for part in command]:
            return "RSA/SHA256, Mon 01 Jan 2026 00:00:00, Key ID 0000000000000000"
        return done

    monkeypatch.setattr(build_keyring, "_run", other_key)
    output = tmp_path / "out"
    replace = {
        "--unsigned": ["drop"],
        "--sign-home": [str(kit.good.key.home)],
        "--sign-key": [kit.good.rpm],
    }
    assert _build(kit.good, output, replace)[0] == 1
    assert "signature by another key" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.parametrize("existing", [False, True], ids=["new-output", "existing-output"])
def test_a_failed_copy_into_the_output_leaves_no_partial_output(
    kit: Kit,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
) -> None:
    output = tmp_path / "out"
    if existing:
        output.mkdir()
        (output / "keep.txt").write_text("kept", encoding="utf-8")
    real = shutil.copyfile
    staged: list[str] = []

    def full_disk(source: str | Path, target: str | Path, **kwargs: Any) -> Any:
        if Path(target).parent == output:
            staged.append(str(target))
            if len(staged) == 3:
                raise OSError(28, "No space left on device")
        return real(source, target, **kwargs)

    monkeypatch.setattr(shutil, "copyfile", full_disk)
    assert _build(kit.good, output)[0] == 1
    assert "cannot write the output: No space left on device" in capsys.readouterr().err
    assert len(staged) == 3
    if existing:
        assert [path.name for path in output.iterdir()] == ["keep.txt"]
    else:
        assert not output.exists()


def test_template_values_are_never_read_as_macros() -> None:
    values = {"VERSION": "2026.1", "MAINTAINER": "A %(id) <a@b.c>"}
    text = build_keyring._substitute("@VERSION@ @MAINTAINER@", values)
    assert text == "2026.1 A %%(id) <a@b.c>"
