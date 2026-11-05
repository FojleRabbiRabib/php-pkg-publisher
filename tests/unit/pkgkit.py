# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Build throwaway signing keys, debs and rpms with the real system tools, for the tests."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from publisher.tools import SEARCH_PATH, Tools, run

KeyState = Literal["valid", "expired", "primary-expired", "revoked"]
LONG_AGO = "20240101T000000"


@dataclass(frozen=True, slots=True, kw_only=True)
class Key:
    """A master key with one signing subkey; `public` holds only the public certificate."""

    home: Path
    public: Path
    subkey_id: str
    subkey_fingerprint: str


def _find(program: str) -> Path:
    path = shutil.which(program, path=SEARCH_PATH)
    assert path is not None, f"{program} must be installed to run these tests"
    return Path(path)


def make_key(tools: Tools, root: Path, name: str, state: KeyState = "valid") -> Key:
    """Create a key whose signing subkey is valid, expired or revoked, or whose master expired."""
    home = root / name
    home.mkdir(mode=0o700)
    env = {"GNUPGHOME": str(home)}
    gpg: list[str | Path] = [tools.gpg, "--batch", "--no-tty", "--pinentry-mode", "loopback"]
    gpg += ["--passphrase", ""]
    past = state in ("expired", "primary-expired")
    faked: list[str | Path] = ["--faked-system-time", LONG_AGO] if past else []
    uid = f"{name} <{name}@example.invalid>"
    lifetime = "1d" if state == "primary-expired" else "0"
    created = run(
        [*gpg, *faked, "--quick-gen-key", uid, "rsa3072", "cert", lifetime], home=home, env=env
    )
    assert created.code == 0
    listing = run([*gpg, "--with-colons", "--list-keys"], home=home, env=env)
    master = next(
        line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr")
    )
    added = run(
        [*gpg, *faked, "--quick-add-key", master, "rsa3072", "sign", "1d" if faked else "1y"],
        home=home,
        env=env,
    )
    assert added.code == 0
    if state == "revoked":
        script = "key 1\nrevkey\ny\n0\n\ny\nsave\n"
        revoked = subprocess.run(  # noqa: S603
            [*map(str, [*gpg, "--command-fd", "0", "--edit-key", master])],
            input=script.encode(),
            capture_output=True,
            env={"GNUPGHOME": str(home), "PATH": "/usr/bin:/bin"},
            check=False,
        )
        assert revoked.returncode == 0
    listing = run([*gpg, "--with-colons", "--fixed-list-mode", "--list-keys"], home=home, env=env)
    lines = listing.stdout.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith("sub"))
    subkey_id = lines[index].split(":")[4].lower()
    subkey_fingerprint = lines[index + 1].split(":")[9]
    exported = run([*gpg, "--armor", "--export", master], home=home, env=env)
    public = root / f"{name}.asc"
    public.write_text(exported.stdout, encoding="utf-8")
    return Key(home=home, public=public, subkey_id=subkey_id, subkey_fingerprint=subkey_fingerprint)


def stop_agent(key: Key) -> None:
    """Stop the gpg-agent that gpg started for this key's home."""
    run(
        [_find("gpgconf"), "--kill", "gpg-agent"],
        home=key.home,
        env={"GNUPGHOME": str(key.home)},
    )


def build_deb(tools: Tools, root: Path, *, package: str, version: str, architecture: str) -> bytes:
    tree = root / f"deb-{package}-{architecture}"
    (tree / "DEBIAN").mkdir(parents=True)
    (tree / "DEBIAN" / "control").write_text(
        f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
        "Maintainer: Test <test@example.invalid>\nDescription: test package\n",
        encoding="utf-8",
    )
    out = root / f"{package}-{architecture}.deb"
    built = run([tools.dpkg_deb, "--build", "--root-owner-group", tree, out], home=root)
    assert built.code == 0, built.stderr
    return out.read_bytes()


def build_rpm(
    root: Path,
    *,
    name: str,
    version: str,
    release: str,
    arch: str,
    key: Key | None = None,
    epoch: int | None = None,
) -> bytes:
    """Build an empty rpm; sign it with `key`'s subkey when a key is given."""
    top = root / f"rpm-{name}-{arch}"
    for part in ("SPECS", "BUILD", "RPMS", "SOURCES", "SRPMS"):
        (top / part).mkdir(parents=True)
    spec = top / "SPECS" / "t.spec"
    epoch_line = "" if epoch is None else f"Epoch: {epoch}\n"
    spec.write_text(
        f"Name: {name}\n{epoch_line}Version: {version}\nRelease: {release}\nSummary: test\n"
        "License: Apache-2.0\n%description\ntest\n%files\n",
        encoding="utf-8",
    )
    rpmbuild = _find("rpmbuild")
    built = run(
        [rpmbuild, "--define", f"_topdir {top}", "--target", f"{arch}-linux", "-bb", spec],
        home=root,
    )
    assert built.code == 0, built.stderr
    (path,) = (top / "RPMS").rglob("*.rpm")
    if key is not None:
        sign: list[str | Path] = [_find("rpmsign")]
        # rpm 4.18 on Ubuntu 24.04 still defaults to /usr/bin/gpg2, which that system lacks.
        sign += ["--define", f"__gpg {_find('gpg')}"]
        sign += ["--define", f"_gpg_name {key.subkey_fingerprint}!"]
        sign += ["--define", f"_gpg_path {key.home}", "--addsign", path]
        signed = run(sign, home=root)
        assert signed.code == 0, signed.stderr
    return path.read_bytes()
